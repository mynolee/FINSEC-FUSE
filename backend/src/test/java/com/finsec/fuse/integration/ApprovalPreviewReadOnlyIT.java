package com.finsec.fuse.integration;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.payment.ApprovalRequest;
import com.finsec.fuse.payment.PaymentFixture;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import static org.junit.jupiter.api.Assertions.*;

/** N_REVIEW_ONLY_02 / SC-T01-B06: public preview is a review, never a payment authorization. */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApprovalPreviewReadOnlyIT extends PaymentFixture {
    @Value("${local.server.port}") int port;
    @Autowired DevActorRegistry registry;
    @Autowired FusePolicy policy;
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    private String token(String role,Set<String> customers) {
        String token=DevActorRegistry.generateToken();
        registry.register(token,new Actor("preview-only-"+UUID.randomUUID(),role,customers));
        return token;
    }
    private HttpResponse<String> preview(UUID workflow,String token) throws Exception {
        var request=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port
            +"/api/v1/workflows/"+workflow+"/approval-preview")).timeout(Duration.ofSeconds(10));
        if(token!=null)request.header("Authorization","Bearer "+token);
        return client.send(request.GET().build(),HttpResponse.BodyHandlers.ofString());
    }
    private <T> T committed(Supplier<T> observation) {
        var fresh=new TransactionTemplate(Objects.requireNonNull(tx.getTransactionManager()));
        fresh.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        fresh.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        fresh.setReadOnly(true);
        return fresh.execute(status->observation.get());
    }
    private Map<String,List<String>> snapshot() {
        return committed(()->{
            var rows=new LinkedHashMap<String,List<String>>();
            var tables=db.jdbc().queryForList("SELECT table_name FROM information_schema.tables "
                +"WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name",String.class);
            assertTrue(tables.containsAll(List.of("execution_gate","application_registry","loan_application",
                "workflow","workflow_job","agent_run","agent_result","delegation_grant","approval",
                "payment_reservation","mock_payment","risk_ledger","audit_event","action_request")));
            // Discover every public base table, including Flyway history and future tables. Full
            // row JSON preserves timestamps and composite-key rows, rather than only row counts.
            for(String table:tables) {
                String quoted="\""+table.replace("\"","\"\"")+"\"";
                rows.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM public."+quoted
                    +" t ORDER BY to_jsonb(t)::text",String.class));
            }
            return rows;
        });
    }
    private Map<String,Object> expectedPreview(UUID id) {
        return committed(()->{
            var workflow=workflow(id);
            var app=db.required("SELECT * FROM loan_application WHERE id=?",workflow.get("application_id"));
            var kyc=db.required("SELECT * FROM agent_result WHERE id=?",workflow.get("current_kyc_result_id"));
            var loan=db.required("SELECT * FROM agent_result WHERE id=?",workflow.get("current_loan_result_id"));
            assertEquals("VALIDATED",kyc.get("status"));assertEquals("VALIDATED",loan.get("status"));
            assertEquals(id,kyc.get("workflow_id"));assertEquals(id,loan.get("workflow_id"));
            assertEquals(workflow.get("generation"),kyc.get("generation"));
            assertEquals(workflow.get("generation"),loan.get("generation"));
            assertEquals(kyc.get("evidence_bundle_hash"),loan.get("evidence_bundle_hash"));
            // Build the documented ordered review fingerprint from persisted facts, without
            // calling ApprovalService.preview or PaymentSupport.snapshot as an oracle.
            var expected=Json.ordered("workflowId",id,"generation",workflow.get("generation"),
                "customerId",app.get("customer_id"),"amountKrw",app.get("amount_krw"),
                "payoutAccountId",app.get("payout_account_id"),"kycResultId",kyc.get("id"),
                "loanResultId",loan.get("id"),"evidenceBundleHash",kyc.get("evidence_bundle_hash"),
                "loanResultHash",loan.get("result_hash"),"policyVersion",workflow.get("policy_version"),
                "usedRisk",35,"reservedRisk",0,"riskLimitAfterApproval",policy.approvedRiskLimit());
            String hash=json.hash(expected);assertTrue(hash.matches("[0-9a-f]{64}"));
            expected.put("reviewSnapshotHash",hash);expected.put("extraRiskLimit",policy.approvalExtraRisk());
            expected.put("expiresInSeconds",policy.approvalTtlSeconds());expected.put("canApprove",true);
            return json.map(json.write(expected));
        });
    }
    private void noAuthorizationCreated(UUID id) {
        committed(()->{
            assertEquals("WAIT_APPROVAL",workflow(id).get("state"));
            assertEquals("APPROVAL_REQUIRED",workflow(id).get("last_reason_code"));assertRisk(id,35,0);
            assertEquals(0,count("approval"));assertEquals(0,count("payment_reservation"));
            assertEquals(0,count("mock_payment"));assertEquals(0,events("RESERVE"));assertEquals(0,events("CONSUME"));
            assertEquals(0,db.jdbc().queryForObject("SELECT count(*) FROM workflow_job WHERE phase='PAY'",Integer.class));
            return null;
        });
    }
    private void readOnlyPreview(UUID id,String token,int status,Map<String,Object> expected,
                                 Map<String,List<String>> before,String label) throws Exception {
        // Make an accidental updated_at=now() observable, even though the harness clock is fixed.
        clock.set(clock.now().plusSeconds(1));
        var response=preview(id,token);assertEquals(status,response.statusCode(),label+": "+response.body());
        var body=json.map(response.body());
        if(status==200) {
            assertEquals(expected,body,label);
            assertEquals("no-store",response.headers().firstValue("Cache-Control").orElseThrow());
        } else {
            assertEquals("DENY",body.get("decision"),label);
            assertEquals(List.of(status==401?"UNAUTHENTICATED":"FORBIDDEN"),body.get("reasonCodes"),label);
            assertNull(body.get("workflowId"));assertNull(body.get("generation"));assertNull(body.get("state"));
            assertFalse(body.containsKey("reviewSnapshotHash"));assertFalse(body.containsKey("customerId"));
        }
        assertEquals(before,snapshot(),label+" must not change any committed durable row or timestamp");
        noAuthorizationCreated(id);
    }

    @Test void repeatedAuthorizedPreviewsStayReadOnlyAndExplicitApprovalStillPays() throws Exception {
        UUID id=ready102();
        // A second populated workflow proves preview cannot perturb unrelated durable state.
        UUID independent=start("customer-103");var prepared=prepareKyc();kyc.apply(prepared,verified(prepared));
        var loan=jobs.claim().orElseThrow();assertEquals("LOAN",loan.phase());loans.execute(loan.jobId(),loan.token());
        assertEquals("REJECTED",workflow(independent).get("state"));assertTrue(jobs.claim().isEmpty());
        var independentBefore=committed(()->new LinkedHashMap<>(workflow(independent)));
        var expected=expectedPreview(id);noAuthorizationCreated(id);var before=snapshot();
        String reviewer=token("LOAN_REVIEWER",Set.of("customer-102"));
        for(int attempt=0;attempt<5;attempt++)
            readOnlyPreview(id,reviewer,200,expected,before,"authorized preview "+attempt);
        readOnlyPreview(id,token("LOAN_REVIEWER",Set.of("customer-101","customer-102","customer-103")),
            200,expected,before,"reviewer with broader legitimate customer scope");

        UUID action=UUID.randomUUID();
        String body=json.write(new ApprovalRequest(ApprovalRequest.Decision.APPROVE,
            (String)expected.get("reviewSnapshotHash"),"Synthetic review confirmed after read-only previews"));
        var response=client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port
                +"/api/v1/workflows/"+id+"/approvals")).timeout(Duration.ofSeconds(10))
            .header("Authorization","Bearer "+reviewer).header("Idempotency-Key",action.toString())
            .header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(),
            HttpResponse.BodyHandlers.ofString());
        assertEquals(201,response.statusCode(),response.body());var approved=json.map(response.body());
        assertEquals("APPROVED",approved.get("state"));assertEquals("ALLOW",approved.get("decision"));
        UUID approvalId=UUID.fromString((String)approved.get("approvalId"));
        UUID payJobId=UUID.fromString((String)approved.get("payJobId"));
        committed(()->{
            assertEquals(1,count("approval"));assertEquals(0,count("payment_reservation"));assertEquals(0,count("mock_payment"));
            assertEquals("AVAILABLE",db.required("SELECT * FROM approval WHERE id=?",approvalId).get("status"));
            assertEquals(expected.get("reviewSnapshotHash"),db.required("SELECT * FROM approval WHERE id=?",approvalId).get("review_snapshot_hash"));
            assertEquals("APPROVED",workflow(id).get("state"));assertRisk(id,35,0);return null;
        });
        var pay=jobs.claim().orElseThrow();assertEquals("PAY",pay.phase());assertEquals(payJobId,pay.jobId());
        var paid=paymentAgent.execute(pay.jobId(),pay.token());assertEquals("PAID",paid.get("state"));
        committed(()->{
            assertEquals("PAID",workflow(id).get("state"));assertRisk(id,85,0);
            assertEquals(1,count("mock_payment"));assertEquals(1,events("RESERVE"));assertEquals(1,events("CONSUME"));
            assertEquals("CONSUMED",db.required("SELECT * FROM approval WHERE id=?",approvalId).get("status"));
            assertEquals(id,db.required("SELECT * FROM mock_payment").get("workflow_id"));
            assertEquals(independentBefore,workflow(independent));return null;
        });
    }

    @Test void onlyInScopeReviewersMayPreviewAndEveryDeniedRoleIsDurablyReadOnly() throws Exception {
        UUID id=ready102();var expected=expectedPreview(id);var before=snapshot();
        // v2.1 public contract: all non-reviewer roles are FORBIDDEN, even with matching scope.
        // Test both configured service identities; no caller-supplied role is trusted.
        for(String role:List.of("CUSTOMER","SECURITY_OPERATOR","DEVELOPER","KYC_SERVICE","FUSE_WORKER")) {
            for(Set<String> scope:List.of(Set.of("customer-102"),Set.of("customer-101"),Set.<String>of()))
                readOnlyPreview(id,token(role,scope),403,expected,before,role+" scope="+scope);
        }
        for(Set<String> scope:List.of(Set.of("customer-101"),Set.<String>of()))
            readOnlyPreview(id,token("LOAN_REVIEWER",scope),403,expected,before,"out-of-scope reviewer "+scope);
        readOnlyPreview(id,null,401,expected,before,"missing authentication");
        readOnlyPreview(id,DevActorRegistry.generateToken(),401,expected,before,"unregistered bearer token");
        readOnlyPreview(id,token("LOAN_REVIEWER",Set.of("customer-102")),200,expected,before,"in-scope reviewer control");
    }
}
