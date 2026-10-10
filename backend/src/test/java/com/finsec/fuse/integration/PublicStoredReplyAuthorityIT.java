package com.finsec.fuse.integration;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.testing.DemoTokenFixtureOracle;
import com.finsec.fuse.payment.ApprovalRequest;
import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.quarantine.ResumeRequest;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** Saved success and business DENY replies require current authority AND original action ownership. */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
class PublicStoredReplyAuthorityIT extends PaymentFixture {
    private static final String RESUME_REASON="Request further evaluation / synthetic dependency recovered";
    @Value("${local.server.port}") int port;
    @Autowired DevActorRegistry registry;
    @Autowired FusePolicy policy;
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private record Identity(String token,Actor actor) {}
    private record Saved(UUID workflowId,UUID actionId,String path,String body,int status,
                         Map<String,Object> reply,Identity owner) {}
    private record StoredDeny(Saved saved,String receiptJson,byte[] replayBody,Map<String,List<String>> rows) {}

    private DemoTokenFixtureOracle authOracle() { return new DemoTokenFixtureOracle(tokenFixture,json,this::durableRows); }

    private Identity identity(String role) {
        String token=DevActorRegistry.generateToken();
        var actor=new Actor("stored-reply-"+UUID.randomUUID(),role,Set.of("customer-102"));
        authOracle().issue(token,actor);
        assertEquals(actor,registry.resolve(token));
        return new Identity(token,actor);
    }
    private HttpResponse<String> post(Saved saved,Identity caller) throws Exception {
        return client.send(request(saved,caller),HttpResponse.BodyHandlers.ofString());
    }
    private HttpRequest request(Saved saved,Identity caller) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+saved.path()))
            .timeout(Duration.ofSeconds(10))
            .header("Authorization","Bearer "+caller.token())
            .header("Idempotency-Key",saved.actionId().toString())
            .header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(saved.body())).build();
    }
    private Saved save(UUID workflowId,String route,Object request,int status,Identity owner,String decision,
                       List<String> reasons,String actionType,String auditType) throws Exception {
        var pending=new Saved(workflowId,UUID.randomUUID(),"/api/v1/workflows/"+workflowId+route,
            json.write(request),status,Map.of(),owner);
        var response=post(pending,owner);
        assertEquals(status,response.statusCode(),response.body());
        var reply=json.map(response.body());
        assertEquals(decision,reply.get("decision"));assertEquals(reasons,reply.get("reasonCodes"));
        assertEquals(false,reply.get("replayed"));assertEquals(workflowId.toString(),reply.get("workflowId"));
        assertEquals(pending.actionId().toString(),reply.get("requestId"));
        var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",pending.actionId());
        assertEquals(owner.actor().actorId(),receipt.get("actor_id"));
        assertEquals(workflowId,receipt.get("workflow_id"));assertEquals(actionType,receipt.get("action_type"));
        assertEquals("SUCCEEDED",receipt.get("status"));assertEquals(decision,receipt.get("decision"));
        assertEquals(reply,json.map(receipt.get("result_json").toString()));
        var audit=db.query("SELECT * FROM audit_event WHERE action_id=?",pending.actionId());
        assertEquals(1,audit.size());assertEquals(auditType,audit.getFirst().get("event_type"));
        assertEquals(owner.actor().actorId(),audit.getFirst().get("actor_id"));
        return new Saved(workflowId,pending.actionId(),pending.path(),pending.body(),status,reply,owner);
    }
    private UUID populatedIndependentWorkflow() {
        UUID id=start("customer-103");
        var prepared=prepareKyc();assertEquals(id,prepared.input().workflowId());
        kyc.apply(prepared,verified(prepared));
        var loan=jobs.claim().orElseThrow();assertEquals("LOAN",loan.phase());loans.execute(loan.jobId(),loan.token());
        assertEquals("REJECTED",workflow(id).get("state"));
        assertFalse(db.query("SELECT id FROM agent_result WHERE workflow_id=?",id).isEmpty());
        assertFalse(db.query("SELECT id FROM risk_ledger WHERE workflow_id=?",id).isEmpty());
        assertFalse(db.query("SELECT id FROM audit_event WHERE workflow_id=?",id).isEmpty());
        assertTrue(jobs.claim().isEmpty());
        return id;
    }

    @Timeout(60) @Test
    void savedApprovalSuccessChecksCurrentAuthorityAndActionOwnershipBeforeReturningHistory() throws Exception {
        UUID independent=populatedIndependentWorkflow(),target=ready102();
        var owner=identity("LOAN_REVIEWER");
        String hash=(String)approvals.preview(owner.actor(),target).get("reviewSnapshotHash");
        var saved=save(target,"/approvals",new ApprovalRequest(ApprovalRequest.Decision.APPROVE,hash,
            "Synthetic application reviewed"),201,owner,"ALLOW",List.of(),"APPROVAL","LOAN_REVIEWER_APPROVED");
        assertEquals("APPROVED",saved.reply().get("state"));
        assertNotNull(saved.reply().get("approvalId"));assertNotNull(saved.reply().get("payJobId"));
        var pay=jobs.claim().orElseThrow();assertEquals("PAY",pay.phase());paymentAgent.execute(pay.jobId(),pay.token());
        assertEquals("PAID",workflow(target).get("state"));
        assertEquals(1,count("mock_payment"));assertEquals(1,events("CONSUME"));assertRisk(target,85,0);
        // Historical APPROVED is intentionally different from the now-PAID workflow and expired approval.
        clock.set(clock.now().plusSeconds(policy.approvalTtlSeconds()+3600L));
        exerciseAuthorityMatrix(saved,independent);
        assertEquals("PAID",workflow(target).get("state"));
        assertEquals(1,count("approval"));assertEquals(1,count("mock_payment"));assertEquals(1,events("CONSUME"));
    }

    @Timeout(60) @Test
    void savedExhaustedResumeDenyChecksCurrentAuthorityAndActionOwnershipBeforeReturningHistory() throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var saved=exhaustedResumeDeny(identity("LOAN_REVIEWER"),"Request further evaluation");
        exerciseAuthorityMatrix(saved,independent);
    }

    private Saved exhaustedResumeDeny(Identity owner,String reason) throws Exception {
        UUID target=start("customer-102");
        // Exhaust the real run allowance through production prepare/reap/resume, never forged counters/receipts.
        for(int generation=1;generation<=policy.maxRunsPerStage();generation++) {
            var prepared=prepareKyc();assertEquals(target,prepared.input().workflowId());
            assertEquals(generation,prepared.input().generation());
            var job=db.required("SELECT * FROM workflow_job WHERE id=?",prepared.jobId());
            clock.set(instant(job,"lease_until").plusMillis(1));jobs.reapNonPayment(prepared.jobId());
            assertEquals("ON_HOLD",workflow(target).get("state"));
            if(generation<policy.maxRunsPerStage()) {
                var resumed=recovery.resume(owner.actor(),target,UUID.randomUUID(),
                    new ResumeRequest(generation,"Retry unavailable synthetic dependency"));
                assertEquals("ALLOW",resumed.get("decision"));assertEquals("KYC_PENDING",resumed.get("state"));
            }
        }
        var saved=save(target,"/resume",new ResumeRequest(policy.maxRunsPerStage(),reason),
            202,owner,"DENY",List.of("MANUAL_REVIEW_REQUIRED"),"WORKFLOW_RESUME","MANUAL_REVIEW_REQUIRED");
        assertEquals("ON_HOLD",saved.reply().get("state"));
        assertEquals("MANUAL_REVIEW_REQUIRED",workflow(target).get("last_reason_code"));
        assertEquals(policy.maxRunsPerStage(),integer(db.required(
            "SELECT * FROM workflow_stage WHERE workflow_id=? AND stage='KYC'",target),"run_count"));
        assertRisk(target,policy.kycRisk(),0);
        assertEquals(0,count("approval"));assertEquals(0,count("payment_reservation"));assertEquals(0,count("mock_payment"));
        return saved;
    }

    @Timeout(60) @Test
    void parsedEquivalentJsonReplaysStoredResumeDenyWithoutAnyDurableMutation() throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var original=storedResumeDeny();var saved=original.saved();
        resumeDenyReplay(original,saved.body());
        String reordered="{\"reason\":"+json.write(RESUME_REASON)+",\"expectedGeneration\":"+policy.maxRunsPerStage()+"}";
        String spaced=" { \n \"expectedGeneration\" : "+policy.maxRunsPerStage()
            +" , \"reason\" : "+json.write(RESUME_REASON)+" \n } \t";
        // Construct the JSON escape at runtime; the source inventory rejects Java Unicode escapes.
        String escaped=saved.body().replace("Request","\\"+"u0052equest").replace(" / "," \\/ ");
        for(String body:List.of(reordered,spaced,escaped)) {
            assertNotEquals(saved.body(),body,"Each normalization control must change the actual request bytes");
            assertEquals(json.map(saved.body()),json.map(body));
            assertEquals(json.read(saved.body(),ResumeRequest.class),json.read(body,ResumeRequest.class));
            resumeDenyReplay(original,body);
        }
        // Normalization must not let another actor, forbidden role, withdrawn scope or revoked token see history.
        var afterAuthority=exerciseAuthorityMatrix(withBody(saved,escaped),independent);
        original=new StoredDeny(original.saved(),original.receiptJson(),original.replayBody(),afterAuthority);
        assertStoredDenyUnchanged(original);
    }

    @Timeout(60) @Test
    void changedResumeReasonAndGenerationConflictWithoutPoisoningStoredDeny() throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var original=storedResumeDeny();
        resumeDenyReplay(original,original.saved().body());
        resumeDenyConflict(original,new ResumeRequest(policy.maxRunsPerStage(),"Different synthetic recovery reason"));
        // Value whitespace is meaningful even though whitespace between JSON tokens is not.
        resumeDenyConflict(original,new ResumeRequest(policy.maxRunsPerStage(),RESUME_REASON+" "));
        resumeDenyConflict(original,new ResumeRequest(policy.maxRunsPerStage()+1,RESUME_REASON));
        assertEquals("REJECTED",workflow(independent).get("state"));
        assertStoredDenyUnchanged(original);
    }

    private StoredDeny storedResumeDeny() throws Exception {
        var saved=exhaustedResumeDeny(identity("LOAN_REVIEWER"),RESUME_REASON);
        assertTrue(jobs.claim().isEmpty(),"No asynchronous work may race the committed-row oracle");
        var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",saved.actionId());
        assertNotNull(receipt.get("completed_at"));
        String receiptJson=receipt.get("result_json").toString();
        var replay=json.map(receiptJson);assertEquals(saved.reply(),replay);
        replay.put("replayed",true);
        return new StoredDeny(saved,receiptJson,json.bytes(replay),durableRows());
    }
    private Saved withBody(Saved saved,String body) {
        return new Saved(saved.workflowId(),saved.actionId(),saved.path(),body,saved.status(),saved.reply(),saved.owner());
    }
    private void resumeDenyReplay(StoredDeny original,String body) throws Exception {
        clock.set(clock.now().plusSeconds(1));
        var saved=withBody(original.saved(),body);
        var response=client.send(request(saved,saved.owner()),HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(202,response.statusCode());assertEquals(saved.status(),response.statusCode());
        var expected=new LinkedHashMap<>(saved.reply());expected.put("replayed",true);
        assertEquals(expected,json.map(response.body()),"Only replayed may change in the original business DENY reply");
        assertArrayEquals(original.replayBody(),response.body(),"Return the encoded stored reply with only replayed changed");
        assertStoredDenyUnchanged(original);
    }
    private void resumeDenyConflict(StoredDeny original,ResumeRequest changed) throws Exception {
        var saved=original.saved();String body=json.write(changed);
        assertNotEquals(json.read(saved.body(),ResumeRequest.class),changed);
        assertNotEquals(json.map(saved.body()),json.map(body));
        clock.set(clock.now().plusSeconds(1));
        var response=post(withBody(saved,body),saved.owner());assertEquals(409,response.statusCode(),response.body());
        var error=json.map(response.body());
        assertEquals(Set.of("requestId","workflowId","generation","state","decision","reasonCodes","message","replayed"),
            error.keySet(),"Conflict must not disclose the saved DENY receipt");
        assertEquals(saved.actionId().toString(),error.get("requestId"));
        assertEquals("DENY",error.get("decision"));assertEquals(List.of("REPLAY_CONFLICT"),error.get("reasonCodes"));
        assertEquals(false,error.get("replayed"));
        for(String field:List.of("workflowId","generation","state"))assertNull(error.get(field));
        assertNotEquals(saved.reply().get("message"),error.get("message"));
        assertFalse(response.body().contains(saved.workflowId().toString()));
        assertFalse(response.body().contains("MANUAL_REVIEW_REQUIRED"));
        assertStoredDenyUnchanged(original);
        resumeDenyReplay(original,saved.body()); // Each conflict leaves the original action replayable.
    }
    private void assertStoredDenyUnchanged(StoredDeny original) {
        var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",original.saved().actionId());
        assertEquals(original.receiptJson(),receipt.get("result_json").toString(),"Stored JSON bytes must remain untouched");
        assertEquals("SUCCEEDED",receipt.get("status"));assertEquals("DENY",receipt.get("decision"));
        assertEquals(original.rows(),durableRows(),"Preserve every committed row and timestamp, including the independent workflow");
    }

    private Map<String,List<String>> exerciseAuthorityMatrix(Saved saved,UUID independent) throws Exception {
        assertTrue(jobs.claim().isEmpty(),"No asynchronous work may race the committed-row oracle");
        // Each issue is independently checked for its exact auth-only delta before the HTTP baseline.
        var others=List.of("LOAN_REVIEWER","CUSTOMER","SECURITY_OPERATOR","DEVELOPER","FUSE_WORKER","KYC_SERVICE")
            .stream().map(this::identity).toList();
        var before=durableRows();
        ownerReplay(saved,before);
        // The other reviewer has valid route permission and customer scope, but does not own this action.
        for(var other:others)denied(saved,other,403,"FORBIDDEN",before);
        before=authOracle().updateScope(saved.owner().actor().actorId(),Set.of("customer-103"));
        assertEquals(Set.of("customer-103"),registry.resolve(saved.owner().token()).customerIds());
        denied(saved,saved.owner(),403,"FORBIDDEN",before);
        before=authOracle().updateScope(saved.owner().actor().actorId(),Set.of("customer-102"));
        assertEquals(saved.owner().actor(),registry.resolve(saved.owner().token()));
        ownerReplay(saved,before); // Rejections must neither consume nor replace the original receipt.
        before=authOracle().revoke(saved.owner().actor().actorId());assertNull(registry.resolve(saved.owner().token()));
        denied(saved,saved.owner(),401,"UNAUTHENTICATED",before);
        assertEquals("REJECTED",workflow(independent).get("state"));
        assertEquals(before,durableRows(),"Include the populated independent workflow and its complete history");
        return before;
    }
    private void ownerReplay(Saved saved,Map<String,List<String>> before) throws Exception {
        clock.set(clock.now().plusSeconds(1));
        var response=post(saved,saved.owner());assertEquals(saved.status(),response.statusCode(),response.body());
        var expected=new LinkedHashMap<>(saved.reply());expected.put("replayed",true);
        assertEquals(expected,json.map(response.body()),"Only replayed changes in the saved historical response");
        assertEquals(before,durableRows(),"Replay must not refresh timestamps, append audit, or duplicate business effects");
    }
    private void denied(Saved saved,Identity caller,int status,String reason,Map<String,List<String>> before) throws Exception {
        clock.set(clock.now().plusSeconds(1));
        var response=post(saved,caller);assertEquals(status,response.statusCode(),caller.actor().role()+": "+response.body());
        var error=json.map(response.body());
        assertEquals(Set.of("requestId","workflowId","generation","state","decision","reasonCodes","message","replayed"),
            error.keySet(),"No saved receipt fields may escape in the public authorization envelope");
        assertEquals("DENY",error.get("decision"));assertEquals(List.of(reason),error.get("reasonCodes"));
        assertEquals(false,error.get("replayed"));
        for(String field:List.of("workflowId","generation","state","approvalId","payJobId","kycJobId","reviewSnapshotHash"))
            assertNull(error.get(field),"Authorization error must not disclose historical "+field);
        assertNotEquals(saved.reply().get("message"),error.get("message"));
        assertFalse(response.body().contains(saved.workflowId().toString()));
        assertFalse(response.body().contains("MANUAL_REVIEW_REQUIRED"));
        assertEquals(before,durableRows(),"Denied replay must preserve all committed rows and receipts");
    }
    private Map<String,List<String>> durableRows() {
        var fresh=new TransactionTemplate(Objects.requireNonNull(tx.getTransactionManager()));
        fresh.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        fresh.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);fresh.setReadOnly(true);
        return fresh.execute(status->{
            var rows=new LinkedHashMap<String,List<String>>();
            var tables=db.jdbc().queryForList("SELECT table_name FROM information_schema.tables "
                +"WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name",String.class);
            assertTrue(tables.containsAll(List.of("demo_auth_registry","demo_token","workflow","workflow_job","workflow_stage","agent_run","agent_result",
                "delegation_grant","approval","payment_reservation","mock_payment","risk_ledger","action_request","audit_event")));
            // Every column including JSON receipts and timestamps; catches updates as well as extra rows.
            for(String table:tables)rows.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM public.\""
                +table.replace("\"","\"\"")+"\" t ORDER BY to_jsonb(t)::text",String.class));
            return rows;
        });
    }

    private static final String REJECTION_COMMENT="Reviewed synthetic application / rejected";
    private record StoredRejection(Saved saved,String reviewHash,String receiptJson,byte[] replayBody,
                                   Map<String,List<String>> rows) {}

    @Timeout(60) @Test
    void parsedEquivalentJsonReplaysStoredApprovalRejectionWithoutAnyDurableMutation() throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var original=storedApprovalRejection();var saved=original.saved();
        approvalRejectionReplay(original,saved.body());
        String reordered="{\"comment\":"+json.write(REJECTION_COMMENT)+",\"reviewSnapshotHash\":"
            +json.write(original.reviewHash())+",\"decision\":\"REJECT\"}";
        String spaced=" { \n \"decision\" : \"REJECT\" , \"reviewSnapshotHash\" : "
            +json.write(original.reviewHash())+" , \"comment\" : "+json.write(REJECTION_COMMENT)+" \n } \t";
        // Construct JSON escapes at runtime without changing the conservative source identity parser.
        String escaped=saved.body().replace("\"decision\"","\""+"\\"+"u0064ecision\"")
            .replace("\"REJECT\"","\""+"\\"+"u0052EJECT\"")
            .replace("Reviewed","\\"+"u0052eviewed").replace(" / "," \\/ ");
        for(String body:List.of(reordered,spaced,escaped)) {
            assertNotEquals(saved.body(),body,"Each normalization control must change the actual request bytes");
            assertEquals(json.map(saved.body()),json.map(body));
            assertEquals(json.read(saved.body(),ApprovalRequest.class),json.read(body,ApprovalRequest.class));
            approvalRejectionReplay(original,body);
        }
        // Equivalent representations cannot bypass present authority or original action ownership.
        original=exerciseRejectionAuthorityMatrix(original,escaped,independent);
        assertStoredRejectionUnchanged(original);
    }

    @Timeout(60) @Test
    void changedApprovalRejectionFieldsConflictWithoutPoisoningStoredReceipt() throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var original=storedApprovalRejection();
        approvalRejectionReplay(original,original.saved().body());
        approvalRejectionConflict(original,new ApprovalRequest(ApprovalRequest.Decision.APPROVE,
            original.reviewHash(),REJECTION_COMMENT));
        String changedHash=(original.reviewHash().charAt(0)=='0'?"1":"0")+original.reviewHash().substring(1);
        assertTrue(changedHash.matches("[0-9a-f]{64}"));assertNotEquals(original.reviewHash(),changedHash);
        approvalRejectionConflict(original,new ApprovalRequest(ApprovalRequest.Decision.REJECT,
            changedHash,REJECTION_COMMENT));
        approvalRejectionConflict(original,new ApprovalRequest(ApprovalRequest.Decision.REJECT,
            original.reviewHash(),"Different synthetic rejection reason"));
        // Whitespace inside a comment is meaningful, unlike whitespace between JSON tokens.
        approvalRejectionConflict(original,new ApprovalRequest(ApprovalRequest.Decision.REJECT,
            original.reviewHash(),REJECTION_COMMENT+" "));
        assertEquals("REJECTED",workflow(independent).get("state"));
        assertStoredRejectionUnchanged(original);
    }

    private StoredRejection storedApprovalRejection() throws Exception {
        UUID target=ready102();var owner=identity("LOAN_REVIEWER");
        String hash=(String)approvals.preview(owner.actor(),target).get("reviewSnapshotHash");
        var saved=save(target,"/approvals",new ApprovalRequest(ApprovalRequest.Decision.REJECT,hash,
            REJECTION_COMMENT),201,owner,"ALLOW",List.of("REVIEWER_REJECTED"),"APPROVAL","LOAN_REVIEWER_REJECTED");
        assertEquals("REJECTED",saved.reply().get("state"));
        assertEquals(1,((Number)saved.reply().get("generation")).intValue());
        assertNotNull(saved.reply().get("approvalId"));assertNull(saved.reply().get("payJobId"));
        assertEquals(0,((Number)saved.reply().get("extraRiskLimit")).intValue());
        assertEquals(policy.automaticRiskLimit(),((Number)saved.reply().get("riskLimit")).intValue());
        var approval=db.required("SELECT * FROM approval WHERE id=?",
            UUID.fromString(saved.reply().get("approvalId").toString()));
        assertEquals(target,approval.get("workflow_id"));assertEquals(owner.actor().actorId(),approval.get("actor_id"));
        assertEquals("REJECTED",approval.get("status"));assertEquals(hash,approval.get("review_snapshot_hash"));
        assertEquals(REJECTION_COMMENT,approval.get("comment"));assertEquals(0,integer(approval,"extra_risk"));
        assertEquals(policy.automaticRiskLimit(),integer(approval,"risk_limit"));
        assertEquals(instant(approval,"expires_at"),java.time.Instant.parse(saved.reply().get("expiresAt").toString()));
        assertEquals("REJECTED",workflow(target).get("state"));
        assertEquals("REVIEWER_REJECTED",workflow(target).get("last_reason_code"));
        assertRisk(target,policy.kycRisk()+policy.loanRisk(),0);
        assertEquals(1,count("approval"));assertEquals(0,count("payment_reservation"));
        assertEquals(0,count("mock_payment"));assertEquals(0,events("CONSUME"));
        assertTrue(db.query("SELECT id FROM workflow_job WHERE phase='PAY'").isEmpty());
        assertTrue(jobs.claim().isEmpty(),"No asynchronous work may race the committed-row oracle");
        var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",saved.actionId());
        assertNotNull(receipt.get("completed_at"));
        String receiptJson=receipt.get("result_json").toString();
        var replay=json.map(receiptJson);assertEquals(saved.reply(),replay);replay.put("replayed",true);
        return new StoredRejection(saved,hash,receiptJson,json.bytes(replay),durableRows());
    }

    private void approvalRejectionReplay(StoredRejection original,String body) throws Exception {
        clock.set(clock.now().plusSeconds(1));
        var saved=withBody(original.saved(),body);
        var response=client.send(request(saved,saved.owner()),HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(201,response.statusCode());assertEquals(saved.status(),response.statusCode());
        var expected=new LinkedHashMap<>(saved.reply());expected.put("replayed",true);
        assertEquals(expected,json.map(response.body()),"Only replayed may change in the original reviewer rejection");
        assertArrayEquals(original.replayBody(),response.body(),"Return the encoded stored reply with only replayed changed");
        assertStoredRejectionUnchanged(original);
    }

    private void approvalRejectionConflict(StoredRejection original,ApprovalRequest changed) throws Exception {
        var saved=original.saved();String body=json.write(changed);
        assertNotEquals(json.read(saved.body(),ApprovalRequest.class),changed);
        assertNotEquals(json.map(saved.body()),json.map(body));
        clock.set(clock.now().plusSeconds(1));
        var response=post(withBody(saved,body),saved.owner());assertEquals(409,response.statusCode(),response.body());
        var error=json.map(response.body());
        assertEquals(Set.of("requestId","workflowId","generation","state","decision","reasonCodes","message","replayed"),
            error.keySet(),"Conflict must not disclose the saved reviewer-rejection receipt");
        assertEquals(saved.actionId().toString(),error.get("requestId"));
        assertEquals("DENY",error.get("decision"));assertEquals(List.of("REPLAY_CONFLICT"),error.get("reasonCodes"));
        assertEquals(false,error.get("replayed"));
        for(String field:List.of("workflowId","generation","state"))assertNull(error.get(field));
        assertNotEquals(saved.reply().get("message"),error.get("message"));
        assertRejectionReceiptHidden(original,response.body());
        assertRejectionReceiptHidden(original,String.valueOf(error));
        assertStoredRejectionUnchanged(original);
        approvalRejectionReplay(original,saved.body()); // Each conflict leaves the original action replayable.
    }

    private void assertStoredRejectionUnchanged(StoredRejection original) {
        var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",original.saved().actionId());
        assertEquals(original.receiptJson(),receipt.get("result_json").toString(),"Stored JSON bytes must remain untouched");
        assertEquals("SUCCEEDED",receipt.get("status"));assertEquals("ALLOW",receipt.get("decision"));
        assertEquals(original.rows(),durableRows(),"Preserve every committed row and timestamp, including the independent workflow");
    }

    private StoredRejection exerciseRejectionAuthorityMatrix(StoredRejection original,String body,UUID independent) throws Exception {
        var saved=original.saved();
        assertTrue(jobs.claim().isEmpty(),"No asynchronous work may race the committed-row oracle");
        assertStoredRejectionUnchanged(original);
        var others=List.of("LOAN_REVIEWER","CUSTOMER","SECURITY_OPERATOR","DEVELOPER","FUSE_WORKER","KYC_SERVICE")
            .stream().map(this::identity).toList();
        original=rebase(original,durableRows());
        approvalRejectionReplay(original,body);
        for(var other:others)approvalRejectionDenied(original,body,other,403,"FORBIDDEN");
        original=rebase(original,authOracle().updateScope(saved.owner().actor().actorId(),Set.of("customer-103")));
        assertEquals(Set.of("customer-103"),registry.resolve(saved.owner().token()).customerIds());
        approvalRejectionDenied(original,body,saved.owner(),403,"FORBIDDEN");
        original=rebase(original,authOracle().updateScope(saved.owner().actor().actorId(),Set.of("customer-102")));
        assertEquals(saved.owner().actor(),registry.resolve(saved.owner().token()));
        approvalRejectionReplay(original,body);
        original=rebase(original,authOracle().revoke(saved.owner().actor().actorId()));assertNull(registry.resolve(saved.owner().token()));
        approvalRejectionDenied(original,body,saved.owner(),401,"UNAUTHENTICATED");
        assertEquals("REJECTED",workflow(independent).get("state"));
        assertStoredRejectionUnchanged(original);
        return original;
    }
    private StoredRejection rebase(StoredRejection original,Map<String,List<String>> rows) {
        return new StoredRejection(original.saved(),original.reviewHash(),original.receiptJson(),original.replayBody(),rows);
    }

    private void approvalRejectionDenied(StoredRejection original,String body,Identity caller,int status,String reason)
        throws Exception {
        clock.set(clock.now().plusSeconds(1));
        var saved=withBody(original.saved(),body);
        var response=post(saved,caller);assertEquals(status,response.statusCode(),caller.actor().role()+": "+response.body());
        var error=json.map(response.body());
        assertEquals(Set.of("requestId","workflowId","generation","state","decision","reasonCodes","message","replayed"),
            error.keySet(),"No saved receipt fields may escape in the public authorization envelope");
        assertEquals("DENY",error.get("decision"));assertEquals(List.of(reason),error.get("reasonCodes"));
        assertEquals(false,error.get("replayed"));
        for(String field:List.of("workflowId","generation","state","approvalId","payJobId","kycJobId","reviewSnapshotHash"))
            assertNull(error.get(field),"Authorization error must not disclose historical "+field);
        assertNotEquals(saved.reply().get("message"),error.get("message"));
        assertRejectionReceiptHidden(original,response.body());
        assertRejectionReceiptHidden(original,String.valueOf(error));
        assertStoredRejectionUnchanged(original);
    }

    private void assertRejectionReceiptHidden(StoredRejection original,String responseBody) {
        var saved=original.saved();
        assertFalse(responseBody.contains(saved.workflowId().toString()));
        assertFalse(responseBody.contains(saved.reply().get("approvalId").toString()));
        assertFalse(responseBody.contains(original.reviewHash()));
        assertFalse(responseBody.contains(REJECTION_COMMENT));
        assertFalse(responseBody.contains("REVIEWER_REJECTED"));
    }
}
