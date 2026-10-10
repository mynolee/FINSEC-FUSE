package com.finsec.fuse.integration;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.AdmissionLimiter;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.config.SecurityPolicy;
import com.finsec.fuse.payment.PaymentFixture;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Synthetic SC-T17-B02/B06/B07/B09/B10 acceptance evidence: real HTTP filters/MVC and
 * committed PostgreSQL rows. This proves one instance's actor write quota, not multi-node
 * coordination, anonymous/read limits, or wall-clock window rollover. No live model/payment.
 */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(PublicRateLimitStateIT.FixedAdmissionWindow.class)
class PublicRateLimitStateIT extends PaymentFixture {
    @TestConfiguration(proxyBeanMethods=false)
    static class FixedAdmissionWindow {
        // Existing public constructor seam; the real limiter/filter stay in the HTTP chain.
        // Freeze only admission time so slower HTTP/database checks cannot reset the quota.
        @Bean @Primary AdmissionLimiter fixedAdmissionLimiter(SecurityPolicy policy) {
            return new AdmissionLimiter(policy,Clock.fixed(Instant.parse("2026-10-09T04:00:00Z"),ZoneOffset.UTC));
        }
    }

    @Value("${local.server.port}") int port;
    @Autowired DevActorRegistry registry;
    @Autowired SecurityPolicy securityPolicy;
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    private String token(Set<String> customers) {
        String token=DevActorRegistry.generateToken();
        issueToken(token,new Actor("rate-state-"+UUID.randomUUID(),"LOAN_REVIEWER",customers));
        return token;
    }
    private String startBody(int customer) {
        return json.write(Map.of("businessReference","APP-DEMO-"+customer+"-001",
            "customerId","customer-"+customer,"amountKrw",1000000L,
            "payoutAccountId","00000000-0000-4000-8000-000000000"+customer));
    }
    private HttpResponse<String> post(String token,String path,UUID action,String body) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path))
            .timeout(Duration.ofSeconds(10)).header("Authorization","Bearer "+token)
            .header("Idempotency-Key",action.toString()).header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
    }
    private Map<String,Object> acceptedStart(String token,UUID action,int customer) throws Exception {
        var response=post(token,"/api/v1/workflows",action,startBody(customer));
        assertEquals(202,response.statusCode(),response.body());
        var result=json.map(response.body());
        assertEquals(action.toString(),result.get("requestId"));
        assertNotNull(result.get("workflowId"));assertEquals("ALLOW",result.get("decision"));
        assertEquals("KYC_PENDING",result.get("state"));assertEquals(false,result.get("replayed"));
        assertEquals(1,((Number)result.get("generation")).intValue());
        assertEquals(List.of(),result.get("reasonCodes"));
        return result;
    }
    private Map<String,List<String>> snapshot() {
        var read=new TransactionTemplate(Objects.requireNonNull(tx.getTransactionManager()));
        read.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        read.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        read.setReadOnly(true);
        return read.execute(status->{
            var result=new LinkedHashMap<String,List<String>>();
            var tables=db.jdbc().queryForList("SELECT table_name FROM information_schema.tables "
                +"WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name",String.class);
            assertTrue(tables.containsAll(List.of("demo_auth_registry","demo_token","workflow","workflow_job","action_request",
                "delegation_grant","trusted_evidence","risk_ledger","approval","mock_payment")));
            for(String table:tables) {
                String quoted="\""+table.replace("\"","\"\"")+"\"";
                result.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM public."+quoted
                    +" t ORDER BY to_jsonb(t)::text",String.class));
            }
            return result;
        });
    }
    private void limited(HttpResponse<String> response) {
        assertEquals(429,response.statusCode(),response.body());
        assertEquals("60",response.headers().firstValue("Retry-After").orElseThrow());
        assertEquals("no-store",response.headers().firstValue("Cache-Control").orElseThrow());
        var result=json.map(response.body());
        assertEquals(List.of("RATE_LIMITED"),result.get("reasonCodes"));
        assertEquals("DENY",result.get("decision"));assertEquals(false,result.get("replayed"));
        // Admission rejects before the controller resolves/correlates an action receipt.
        assertNull(result.get("requestId"));assertNull(result.get("workflowId"));
        assertNull(result.get("generation"));assertNull(result.get("state"));
    }
    private void drainMockJobs() {
        for(int step=0;step<12;step++) {
            var next=jobs.claim();if(next.isEmpty())return;
            var lease=next.orElseThrow();
            switch(lease.phase()) {
                case "KYC" -> {
                    var prepared=kyc.prepare(lease.jobId(),lease.token()).orElseThrow();
                    kyc.apply(prepared,verified(prepared));
                }
                case "LOAN" -> loans.execute(lease.jobId(),lease.token());
                case "PAY" -> paymentAgent.execute(lease.jobId(),lease.token());
                default -> fail("Unexpected phase "+lease.phase());
            }
        }
        fail("Mock jobs did not drain within bounded deterministic steps");
    }

    @Test void exhaustedActorCannotCreateOrReplayDurableStateWhileIndependentActorCanApproveAndPay() throws Exception {
        assertEquals(20,securityPolicy.authenticatedChangesPerMinute());
        // Populate real grants, risk, jobs and expiry-bearing evidence before taking the baseline.
        String independent=token(Set.of("customer-102"));
        var normal=acceptedStart(independent,UUID.randomUUID(),102);
        UUID normalId=UUID.fromString((String)normal.get("workflowId"));
        drainMockJobs();assertEquals("WAIT_APPROVAL",workflow(normalId).get("state"));
        assertEquals(0,count("mock_payment"));

        String saturated=token(Set.of("customer-101","customer-103"));
        UUID originalAction=UUID.randomUUID();
        var original=acceptedStart(saturated,originalAction,103); // Write request 1.
        var baseline=snapshot();
        for(String table:List.of("workflow_job","action_request","delegation_grant","trusted_evidence","risk_ledger"))
            assertFalse(baseline.get(table).isEmpty(),table+" must be populated, not a vacuous comparison");
        assertEquals(2,baseline.get("workflow").size());
        var replay=new LinkedHashMap<>(original);replay.put("replayed",true);
        for(int request=2;request<=20;request++) {
            var response=post(saturated,"/api/v1/workflows",originalAction,startBody(103));
            assertEquals(202,response.statusCode(),"Request "+request+": "+response.body());
            assertEquals(replay,json.map(response.body()));
            assertEquals(baseline,snapshot(),"Replay "+request+" must preserve every committed row, including expiries");
        }

        // Request 21 is a fresh action with valid independently registered terms and authorized scope.
        // It would create a different workflow without the limiter, rather than merely conflict.
        assertEquals(1,db.number(db.required("SELECT count(*) n FROM application_registry WHERE "
            +"business_reference='APP-DEMO-101-001' AND customer_id='customer-101' "
            +"AND amount_krw=1000000 AND payout_account_id='00000000-0000-4000-8000-000000000101'"),"n"));
        UUID freshAction=UUID.randomUUID();
        limited(post(saturated,"/api/v1/workflows",freshAction,startBody(101)));
        assertEquals(baseline,snapshot(),"Fresh-action 429 must not append a receipt, job, audit or risk entry");
        limited(post(saturated,"/api/v1/workflows",originalAction,startBody(103)));
        assertEquals(baseline,snapshot(),"Old-action 429 must not replay, overwrite or refresh any durable state");

        var previewResponse=client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port
            +"/api/v1/workflows/"+normalId+"/approval-preview")).timeout(Duration.ofSeconds(10))
            .header("Authorization","Bearer "+independent).GET().build(),HttpResponse.BodyHandlers.ofString());
        assertEquals(200,previewResponse.statusCode(),previewResponse.body());
        String approvalBody=json.write(Map.of("decision","APPROVE","reviewSnapshotHash",
            json.map(previewResponse.body()).get("reviewSnapshotHash"),"comment","Synthetic mock review"));
        UUID approvalAction=UUID.randomUUID();
        var approval=post(independent,"/api/v1/workflows/"+normalId+"/approvals",approvalAction,approvalBody);
        assertEquals(201,approval.statusCode(),approval.body());
        assertEquals("ALLOW",json.map(approval.body()).get("decision"));
        drainMockJobs();
        assertEquals("PAID",workflow(normalId).get("state"));
        assertEquals(85,((Number)workflow(normalId).get("used_risk")).intValue());
        assertEquals(0,((Number)workflow(normalId).get("reserved_risk")).intValue());
        assertEquals(1,count("mock_payment"));assertEquals(1,count("approval"));
        assertEquals(normalId,db.required("SELECT workflow_id FROM mock_payment").get("workflow_id"));
        assertEquals(1,db.number(db.required("SELECT count(*) n FROM audit_event WHERE event_type='PAYMENT_COMMITTED'"),"n"));
        var paid=snapshot();
        var approvalReplay=post(independent,"/api/v1/workflows/"+normalId+"/approvals",approvalAction,approvalBody);
        assertEquals(201,approvalReplay.statusCode(),approvalReplay.body());
        var expectedApproval=new LinkedHashMap<>(json.map(approval.body()));expectedApproval.put("replayed",true);
        assertEquals(expectedApproval,json.map(approvalReplay.body()));
        assertEquals(paid,snapshot(),"Independent approval replay must not duplicate the mock payment");
    }
}
