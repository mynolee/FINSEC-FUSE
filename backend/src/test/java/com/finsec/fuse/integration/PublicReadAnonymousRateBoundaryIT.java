package com.finsec.fuse.integration;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.AdmissionLimiter;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.config.SecurityPolicy;
import com.finsec.fuse.experiments.ExperimentCaptureGateway;
import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.workflow.KycGateway;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Synthetic SC-T17-B01/B03: actual loopback HTTP, real filters/MVC and committed
 * PostgreSQL rows. Only admission time is frozen. A fresh context isolates each
 * anonymous bucket. No rollover, proxy/multi-node, active scheduler or LIVE claim.
 */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties="server.address=127.0.0.1")
@Import(PublicReadAnonymousRateBoundaryIT.FixedRateContext.class)
@DirtiesContext(classMode=DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class PublicReadAnonymousRateBoundaryIT extends PaymentFixture {
    private static final Instant ADMISSION_TIME=Instant.parse("2026-10-09T04:00:00Z");
    private static final String LIST_PATH="/api/v1/workflows?page=0&size=20";
    private static final Set<String> ERROR_KEYS=Set.of("requestId","workflowId","generation","state",
        "decision","reasonCodes","message","replayed");

    static class GatewayCalls {
        final AtomicInteger kyc=new AtomicInteger();
        final AtomicInteger experiment=new AtomicInteger();
    }
    @TestConfiguration(proxyBeanMethods=false)
    static class FixedRateContext {
        @Bean @Primary AdmissionLimiter fixedReadAnonymousLimiter(SecurityPolicy policy) {
            return new AdmissionLimiter(policy,Clock.fixed(ADMISSION_TIME,ZoneOffset.UTC));
        }
        @Bean GatewayCalls rateGatewayCalls() {return new GatewayCalls();}
        @Bean @Primary KycGateway noRateKycModel(GatewayCalls calls) {
            return input->{calls.kyc.incrementAndGet();throw new AssertionError("Unexpected KYC gateway invocation");};
        }
        @Bean @Primary ExperimentCaptureGateway noRateExperimentModel(GatewayCalls calls) {
            return input->{calls.experiment.incrementAndGet();throw new AssertionError("Unexpected experiment gateway invocation");};
        }
    }
    private record CaseState(UUID primaryWorkflow,UUID independentWorkflow,String primaryToken,
            String independentToken,Instant businessTime,Map<String,List<String>> before) {}

    @Value("${local.server.port}") int port;
    @Value("${fuse.worker-enabled:true}") boolean scheduledWorkerEnabled;
    @Autowired SecurityPolicy securityPolicy;
    @Autowired GatewayCalls gatewayCalls;
    @Autowired ApplicationContext context;
    private HttpClient client;
    @AfterEach void closeHttpClient() {if(client!=null)client.close();}

    private CaseState prepareState() {
        assertEquals(120,securityPolicy.authenticatedReadsPerMinute());
        assertEquals(20,securityPolicy.authenticatedChangesPerMinute());
        assertEquals(30,securityPolicy.anonymousAttemptsPerIpPerMinute());
        assertFalse(scheduledWorkerEnabled,"This proof excludes scheduled worker dispatch");
        assertSame(context.getBean("fixedReadAnonymousLimiter"),context.getBean(AdmissionLimiter.class));
        assertSame(context.getBean("noRateKycModel"),context.getBean(KycGateway.class));
        assertSame(context.getBean("noRateExperimentModel"),context.getBean(ExperimentCaptureGateway.class));
        noModelCalls();assertTrue(port>0);
        client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1).build();

        // Existing fixture services populate durable state without HTTP quota use.
        // KYC responses are explicit synthetic inputs, not model gateway calls.
        UUID primary=ready102();approve(primary);
        UUID independent=start("customer-101");
        assertEquals("APPROVED",workflow(primary).get("state"));assertRisk(primary,35,0);
        assertEquals("KYC_PENDING",workflow(independent).get("state"));assertRisk(independent,0,0);
        assertEquals(0,count("mock_payment"));assertEquals(0,count("quarantine"));assertEquals(1,count("approval"));
        assertTrue(db.number(db.required("SELECT count(*) n FROM approval WHERE expires_at IS NOT NULL"),"n")>0);
        assertTrue(db.number(db.required("SELECT count(*) n FROM trusted_evidence WHERE expires_at IS NOT NULL"),"n")>0);

        // The existing owner oracle checks issuance writes; authority time remains DB-owned.
        String primaryToken=DevActorRegistry.generateToken(),independentToken=DevActorRegistry.generateToken();
        issueToken(primaryToken,new Actor("rate-read-primary-"+UUID.randomUUID(),"LOAN_REVIEWER",Set.of("customer-102")));
        issueToken(independentToken,new Actor("rate-read-independent-"+UUID.randomUUID(),"CUSTOMER",Set.of("customer-101")));
        var before=snapshot();
        for(String table:List.of("demo_auth_registry","demo_token","workflow","workflow_job","action_request",
                "delegation_grant","agent_run","agent_result","risk_ledger","approval","trusted_evidence","audit_event"))
            assertFalse(before.get(table).isEmpty(),"Non-vacuous fixture table: "+table);
        assertEquals(2,before.get("workflow").size());noModelCalls();
        return new CaseState(primary,independent,primaryToken,independentToken,clock.now(),before);
    }

    private HttpResponse<String> get(String token) throws Exception {
        var request=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+LIST_PATH))
            .timeout(Duration.ofSeconds(10)).GET();
        if(token!=null)request.header("Authorization","Bearer "+token);
        return client.send(request.build(),HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }
    private void safeHeaders(HttpResponse<String> response) {
        assertEquals("no-store",response.headers().firstValue("Cache-Control").orElseThrow());
        assertEquals("nosniff",response.headers().firstValue("X-Content-Type-Options").orElseThrow());
        var media=MediaType.parseMediaType(response.headers().firstValue("Content-Type").orElseThrow());
        assertEquals("application",media.getType());assertEquals("json",media.getSubtype());
        if(media.getCharset()!=null)assertEquals(StandardCharsets.UTF_8,media.getCharset());
    }
    private void allowedList(HttpResponse<String> response,UUID expectedWorkflow,String expectedCustomer,
            String expectedState,int expectedRisk) {
        assertEquals(200,response.statusCode());safeHeaders(response);
        assertTrue(response.headers().allValues("Retry-After").isEmpty());
        var body=json.map(response.body());assertEquals(Set.of("items","total","page","size"),body.keySet());
        assertEquals(1,assertInstanceOf(Number.class,body.get("total")).intValue());
        assertEquals(0,assertInstanceOf(Number.class,body.get("page")).intValue());
        assertEquals(20,assertInstanceOf(Number.class,body.get("size")).intValue());
        var items=assertInstanceOf(List.class,body.get("items"));assertEquals(1,items.size());
        var item=assertInstanceOf(Map.class,items.getFirst());
        assertEquals(expectedWorkflow.toString(),item.get("workflowId"));assertEquals(expectedCustomer,item.get("customerId"));
        assertEquals(expectedState,item.get("state"));
        assertEquals(expectedRisk,assertInstanceOf(Number.class,item.get("usedRisk")).intValue());
        assertEquals(0,assertInstanceOf(Number.class,item.get("reservedRisk")).intValue());
        assertTrue(assertInstanceOf(List.class,item.get("activeQuarantines")).isEmpty());
    }
    private void admissionDenied(HttpResponse<String> response,boolean limited) {
        assertEquals(limited?429:401,response.statusCode());safeHeaders(response);
        if(limited)assertEquals(List.of("60"),response.headers().allValues("Retry-After"));
        else assertTrue(response.headers().allValues("Retry-After").isEmpty());
        var media=MediaType.parseMediaType(response.headers().firstValue("Content-Type").orElseThrow());
        assertEquals(StandardCharsets.UTF_8,media.getCharset());
        var body=json.map(response.body());assertEquals(ERROR_KEYS,body.keySet());
        for(String field:List.of("requestId","workflowId","generation","state"))assertNull(body.get(field));
        assertEquals("DENY",body.get("decision"));assertEquals(false,body.get("replayed"));
        assertEquals(List.of(limited?"RATE_LIMITED":"UNAUTHENTICATED"),body.get("reasonCodes"));
        assertEquals(limited?"Request rate exceeded; retry after 60 seconds":"A valid bearer token is required",body.get("message"));
    }
    private Map<String,List<String>> snapshot() {
        var read=new TransactionTemplate(Objects.requireNonNull(tx.getTransactionManager()));
        read.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        read.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);read.setReadOnly(true);
        return read.execute(status->{
            var result=new LinkedHashMap<String,List<String>>();
            var tables=db.jdbc().queryForList("SELECT table_name FROM information_schema.tables "
                +"WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name",String.class);
            assertTrue(tables.containsAll(List.of("demo_auth_registry","demo_token","workflow","workflow_job",
                "action_request","delegation_grant","agent_run","agent_result","risk_ledger","approval",
                "trusted_evidence","mock_payment","quarantine","audit_event")));
            for(String table:tables) {
                String quoted="\""+table.replace("\"","\"\"")+"\"";
                result.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM public."+quoted
                    +" t ORDER BY to_jsonb(t)::text",String.class));
            }
            return result;
        });
    }
    private void noModelCalls() {
        assertEquals(0,gatewayCalls.kyc.get(),"No worker KYC gateway invocation");
        assertEquals(0,gatewayCalls.experiment.get(),"No experiment model capture invocation");
    }
    private void unchanged(CaseState state,String boundary) {
        // Boolean comparison keeps full synthetic DB rows out of assertion failure output.
        assertTrue(state.before().equals(snapshot()),"Every committed row must remain unchanged at "+boundary);
        assertEquals(state.businessTime(),clock.now());noModelCalls();
        assertEquals("APPROVED",workflow(state.primaryWorkflow()).get("state"));
        assertEquals("KYC_PENDING",workflow(state.independentWorkflow()).get("state"));
        assertRisk(state.primaryWorkflow(),35,0);assertRisk(state.independentWorkflow(),0,0);
        assertEquals(0,count("mock_payment"));assertEquals(0,count("quarantine"));assertEquals(1,count("approval"));
    }

    @Test @Timeout(180)
    void authenticatedReadsRespectExactQuotaWithoutBusinessOrModelEffects() throws Exception {
        var state=prepareState();
        for(int request=1;request<=120;request++) {
            allowedList(get(state.primaryToken()),state.primaryWorkflow(),"customer-102","APPROVED",35);
            noModelCalls();
            if(request==119 || request==120)unchanged(state,"authenticated read "+request);
        }
        admissionDenied(get(state.primaryToken()),true);unchanged(state,"authenticated read 121");
        admissionDenied(get(state.primaryToken()),true);unchanged(state,"authenticated repeated excess");
        // Same real source IP, different actor/scope: the other quota remains available.
        allowedList(get(state.independentToken()),state.independentWorkflow(),"customer-101","KYC_PENDING",0);
        unchanged(state,"independent authenticated actor");
        admissionDenied(get(state.primaryToken()),true);unchanged(state,"original actor still saturated");
    }
    @Test @Timeout(180)
    void anonymousAttemptsRespectExactQuotaWithoutBusinessOrModelEffects() throws Exception {
        var state=prepareState();
        for(int request=1;request<=30;request++) {
            // No Authorization, cookie, forwarded identity or warm-up API request.
            admissionDenied(get(null),false);noModelCalls();
            if(request==29 || request==30)unchanged(state,"anonymous attempt "+request);
        }
        admissionDenied(get(null),true);unchanged(state,"anonymous attempt 31");
        admissionDenied(get(null),true);unchanged(state,"anonymous repeated excess");
        allowedList(get(state.independentToken()),state.independentWorkflow(),"customer-101","KYC_PENDING",0);
        unchanged(state,"valid actor after anonymous saturation");
        admissionDenied(get(null),true);unchanged(state,"anonymous bucket still saturated");
    }
}
