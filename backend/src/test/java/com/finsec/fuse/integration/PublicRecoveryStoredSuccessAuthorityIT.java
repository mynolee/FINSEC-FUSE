package com.finsec.fuse.integration;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.quarantine.QuarantineRequest;
import com.finsec.fuse.quarantine.ReleaseRequest;
import com.finsec.fuse.quarantine.ResumeRequest;
import com.finsec.fuse.testing.DemoTokenFixtureOracle;
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

/** Public saved recovery successes retain current authority, request binding and exact durable history. */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
class PublicRecoveryStoredSuccessAuthorityIT extends PaymentFixture {
    private static final String RELEASE_NOTE="Reviewed synthetic recovery / release only";
    private static final String RESUME_REASON="Request synthetic evaluation / dependency recovered";
    private static final List<String> ROLES=List.of("CUSTOMER","LOAN_REVIEWER","SECURITY_OPERATOR",
        "DEVELOPER","FUSE_WORKER","KYC_SERVICE");
    @Value("${local.server.port}") int port;
    @Autowired DevActorRegistry registry;
    @Autowired FusePolicy policy;
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private record Identity(String token,Actor actor) {}
    private record Incident(UUID workflowId,UUID quarantineId,UUID runId) {}
    private record Saved(Incident incident,UUID actionId,String path,String body,int status,
                         Map<String,Object> reply,Identity owner,String receiptJson,String receiptRowJson,byte[] replayBody,
                         Map<String,List<String>> rows) {}

    @Test @Timeout(60)
    void savedReleaseSuccessChecksCurrentAuthorityOwnershipAndParsedEquivalentBodies() throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var saved=storedRelease();
        replay(saved,saved.body(),saved.owner());
        String equivalent=exerciseReleaseNormalization(saved);
        saved=exerciseAuthorityMatrix(saved,equivalent);
        assertReleaseOnly(saved.incident());
        assertEquals("REJECTED",workflow(independent).get("state"));
        assertUnchanged(saved);
    }

    @Test @Timeout(60)
    void changedReleaseRemediationConflictsWithoutPoisoningSavedSuccess() throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var saved=storedRelease();
        var r=json.read(saved.body(),ReleaseRequest.class).remediation();
        replay(saved,saved.body(),saved.owner());
        var variants=List.of(
            new ReleaseRequest.Remediation(UUID.randomUUID(),r.safeDocumentVersion(),r.checkEvidenceIds(),null,null,r.note()),
            new ReleaseRequest.Remediation(r.safeDocumentId(),r.safeDocumentVersion()+1,r.checkEvidenceIds(),null,null,r.note()),
            new ReleaseRequest.Remediation(r.safeDocumentId(),r.safeDocumentVersion(),List.of(r.checkEvidenceIds().getFirst()),null,null,r.note()),
            new ReleaseRequest.Remediation(r.safeDocumentId(),r.safeDocumentVersion(),r.checkEvidenceIds(),"synthetic-other-agent",null,r.note()),
            new ReleaseRequest.Remediation(r.safeDocumentId(),r.safeDocumentVersion(),r.checkEvidenceIds(),null,1,r.note()),
            new ReleaseRequest.Remediation(r.safeDocumentId(),r.safeDocumentVersion(),r.checkEvidenceIds(),null,null,"Different synthetic release note"),
            new ReleaseRequest.Remediation(r.safeDocumentId(),r.safeDocumentVersion(),r.checkEvidenceIds(),null,null,r.note()+" "));
        for(var changed:variants) {
            var request=new ReleaseRequest(changed);
            assertNotEquals(json.read(saved.body(),ReleaseRequest.class),request);
            conflict(saved,json.write(request));
        }
        assertReleaseOnly(saved.incident());
        assertEquals("REJECTED",workflow(independent).get("state"));
        assertUnchanged(saved);
    }

    @Test @Timeout(60)
    void savedResumeSuccessChecksCurrentAuthorityOwnershipAndParsedEquivalentBodies() throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var saved=storedResume();
        replay(saved,saved.body(),saved.owner());
        String reordered="{\"reason\":"+json.write(RESUME_REASON)+",\"expectedGeneration\":1}";
        String spaced=" { \n \"expectedGeneration\" : 1 , \"reason\" : "+json.write(RESUME_REASON)+" \n } \t";
        // Construct JSON escapes at runtime; no Java Unicode escapes enter the source inventory.
        String escaped=saved.body().replace("\"reason\"","\""+"\\"+"u0072eason\"")
            .replace("Request","\\"+"u0052equest").replace(" / "," \\/ ");
        for(String body:List.of(reordered,spaced,escaped)) {
            assertNotEquals(saved.body(),body);
            assertEquals(json.map(saved.body()),json.map(body));
            assertEquals(json.read(saved.body(),ResumeRequest.class),json.read(body,ResumeRequest.class));
            replay(saved,body,saved.owner());
        }
        saved=exerciseAuthorityMatrix(saved,escaped);
        assertResumedHistory(saved);
        assertEquals("REJECTED",workflow(independent).get("state"));
        assertUnchanged(saved);
    }

    @Test @Timeout(60)
    void changedResumeSuccessReasonAndGenerationConflictWithoutPoisoningSavedSuccess() throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var saved=storedResume();
        replay(saved,saved.body(),saved.owner());
        for(var changed:List.of(new ResumeRequest(1,"Different synthetic recovery reason"),
            new ResumeRequest(1,RESUME_REASON+" "),new ResumeRequest(2,RESUME_REASON))) {
            assertNotEquals(json.read(saved.body(),ResumeRequest.class),changed);
            conflict(saved,json.write(changed));
        }
        assertResumedHistory(saved);
        assertEquals("REJECTED",workflow(independent).get("state"));
        assertUnchanged(saved);
    }

    private Saved storedRelease() throws Exception {
        var incident=blockedRun();var owner=identity("SECURITY_OPERATOR");
        var evidenceIds=db.query("SELECT id FROM trusted_evidence WHERE customer_id='customer-102' ORDER BY id")
            .stream().map(row->uuid(row,"id")).toList();
        assertEquals(2,evidenceIds.size());
        var request=new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,evidenceIds,null,null,RELEASE_NOTE));
        var before=durableRows();UUID action=UUID.randomUUID();String body=json.write(request);
        var response=post("/api/v1/quarantines/"+incident.quarantineId()+"/release",action,body,owner);
        assertEquals(200,response.statusCode(),response.body());
        var reply=json.map(response.body());
        assertEquals("RELEASED",reply.get("state"));assertEquals("RUN",reply.get("scope"));
        assertEquals(incident.quarantineId().toString(),reply.get("quarantineId"));
        assertEquals(Map.of("runId",incident.runId().toString()),reply.get("target"));
        assertNull(reply.get("workflowId"));assertNull(reply.get("generation"));
        assertReleaseOnly(incident);
        var after=durableRows();
        for(String table:List.of("workflow_job","workflow_stage","agent_run","agent_result","delegation_grant",
            "approval","payment_reservation","mock_payment","risk_ledger"))
            assertEquals(before.get(table),after.get(table),"Release alone cannot create or restart execution in "+table);
        var quarantine=db.required("SELECT * FROM quarantine WHERE id=?",incident.quarantineId());
        assertEquals(owner.actor().actorId(),quarantine.get("released_by"));assertNotNull(quarantine.get("released_at"));
        assertEquals(json.map(json.write(request.remediation())),json.map(quarantine.get("remediation_json").toString()));
        assertEquals(List.of("QUARANTINE_RELEASED","QUARANTINE_RELEASED","RECOVERY_CHECKED"),
            db.jdbc().queryForList("SELECT event_type FROM audit_event WHERE action_id=? ORDER BY event_type",String.class,action));
        assertEquals(1,db.query("SELECT id FROM audit_event WHERE action_id=? AND event_type='QUARANTINE_RELEASED' AND workflow_id=?",action,incident.workflowId()).size());
        return saved(incident,action,"/api/v1/quarantines/"+incident.quarantineId()+"/release",body,200,
            reply,owner,"QUARANTINE_RELEASE",null,Json.ordered("quarantineId",incident.quarantineId(),"remediation",request.remediation()));
    }

    private Saved storedResume() throws Exception {
        var release=storedRelease();var incident=release.incident();
        // The successful release above left generation 1 blocked and no runnable job. Only this POST resumes it.
        assertReleaseOnly(incident);
        var owner=identity("LOAN_REVIEWER");UUID action=UUID.randomUUID();
        var request=new ResumeRequest(1,RESUME_REASON);String body=json.write(request);
        String path="/api/v1/workflows/"+incident.workflowId()+"/resume";
        var response=post(path,action,body,owner);assertEquals(202,response.statusCode(),response.body());
        var reply=json.map(response.body());
        assertEquals("KYC_PENDING",reply.get("state"));assertEquals(2,((Number)reply.get("generation")).intValue());
        assertEquals(incident.workflowId().toString(),reply.get("workflowId"));
        UUID jobId=UUID.fromString(reply.get("kycJobId").toString());
        var job=db.required("SELECT * FROM workflow_job WHERE id=?",jobId);
        assertEquals(incident.workflowId(),job.get("workflow_id"));assertEquals(2,integer(job,"generation"));
        assertEquals("KYC",job.get("phase"));assertEquals("PENDING",job.get("state"));
        assertEquals(1,db.query("SELECT id FROM workflow_job WHERE workflow_id=? AND generation=2",incident.workflowId()).size());
        assertEquals(2,integer(workflow(incident.workflowId()),"generation"));assertRisk(incident.workflowId(),policy.kycRisk(),0);
        assertEquals(1,integer(db.required("SELECT * FROM workflow_stage WHERE workflow_id=? AND stage='KYC'",incident.workflowId()),"run_count"));
        assertEquals(List.of("WORKFLOW_RESUMED"),db.jdbc().queryForList(
            "SELECT event_type FROM audit_event WHERE action_id=? ORDER BY event_type",String.class,action));
        var stored=saved(incident,action,path,body,202,reply,owner,"WORKFLOW_RESUME",incident.workflowId(),request);
        // Finish the queued synthetic KYC/Loan through real services before the zero-write windows.
        // The stored KYC_PENDING success must remain historical even when current state is WAIT_APPROVAL.
        var prepared=prepareKyc();assertEquals(jobId,prepared.jobId());
        assertEquals(2,prepared.input().generation());kyc.apply(prepared,verified(prepared));
        var loan=jobs.claim().orElseThrow();assertEquals("LOAN",loan.phase());loans.execute(loan.jobId(),loan.token());
        assertTrue(jobs.claim().isEmpty());
        stored=rebase(stored,durableRows());assertResumedHistory(stored);assertUnchanged(stored);
        // Release history also survives the later explicit resume without creating another generation.
        replay(rebase(release,durableRows()),release.body(),release.owner());
        assertResumedHistory(stored);assertUnchanged(stored);
        return stored;
    }

    private Incident blockedRun() {
        UUID workflowId=start("customer-102");var prepared=prepareKyc();
        assertEquals(workflowId,prepared.input().workflowId());assertEquals(1,prepared.input().generation());
        UUID runId=prepared.input().runId();
        var blocked=quarantines.apply(SECURITY,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.RUN,
            runId,null,null,null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Synthetic recovery boundary"));
        UUID quarantineId=(UUID)blocked.get("quarantineId");
        assertEquals("ACTIVE",db.required("SELECT status FROM quarantine WHERE id=?",quarantineId).get("status"));
        assertEquals("BLOCKED",workflow(workflowId).get("state"));assertRisk(workflowId,policy.kycRisk(),0);
        assertTrue(jobs.claim().isEmpty());return new Incident(workflowId,quarantineId,runId);
    }

    private void assertReleaseOnly(Incident incident) {
        var workflow=workflow(incident.workflowId());
        assertEquals("RELEASED",db.required("SELECT status FROM quarantine WHERE id=?",incident.quarantineId()).get("status"));
        assertEquals("BLOCKED",workflow.get("state"));assertEquals(1,integer(workflow,"generation"));
        assertEquals(DOCUMENT,workflow.get("recovery_document_id"));assertEquals(1,integer(workflow,"recovery_document_version"));
        assertRisk(incident.workflowId(),policy.kycRisk(),0);
        assertEquals(1,integer(db.required("SELECT * FROM workflow_stage WHERE workflow_id=? AND stage='KYC'",incident.workflowId()),"run_count"));
        assertTrue(db.query("SELECT id FROM workflow_job WHERE workflow_id=? AND (generation<>1 OR state IN ('PENDING','RUNNING'))",incident.workflowId()).isEmpty());
        assertNoApprovalOrPayment();
    }

    private void assertResumedHistory(Saved saved) {
        UUID workflowId=saved.incident().workflowId();
        assertEquals("KYC_PENDING",saved.reply().get("state"));assertEquals("WAIT_APPROVAL",workflow(workflowId).get("state"));
        assertEquals(2,integer(workflow(workflowId),"generation"));assertRisk(workflowId,policy.kycRisk()+policy.loanRisk(),0);
        assertEquals(2,integer(db.required("SELECT * FROM workflow_stage WHERE workflow_id=? AND stage='KYC'",workflowId),"run_count"));
        assertEquals("SUCCEEDED",db.required("SELECT state FROM workflow_job WHERE id=?",UUID.fromString(saved.reply().get("kycJobId").toString())).get("state"));
        assertTrue(db.query("SELECT id FROM workflow_job WHERE state IN ('PENDING','RUNNING')").isEmpty());
        assertNoApprovalOrPayment();
    }

    private void assertNoApprovalOrPayment() {
        assertEquals(0,count("approval"));assertEquals(0,count("payment_reservation"));
        assertEquals(0,count("mock_payment"));assertEquals(0,events("CONSUME"));
        assertTrue(db.query("SELECT id FROM workflow_job WHERE phase='PAY'").isEmpty());
    }

    private Saved saved(Incident incident,UUID action,String path,String body,int status,Map<String,Object> reply,
        Identity owner,String actionType,UUID receiptWorkflow,Object canonicalBody) {
        assertEquals(action.toString(),reply.get("requestId"));assertEquals("ALLOW",reply.get("decision"));
        assertEquals(List.of(),reply.get("reasonCodes"));assertEquals(false,reply.get("replayed"));
        var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",action);
        assertEquals(owner.actor().actorId(),receipt.get("actor_id"));assertEquals(actionType,receipt.get("action_type"));
        assertEquals(receiptWorkflow,receipt.get("workflow_id"));assertEquals("SUCCEEDED",receipt.get("status"));
        assertEquals("ALLOW",receipt.get("decision"));assertNotNull(receipt.get("created_at"));assertNotNull(receipt.get("completed_at"));
        assertEquals(json.hash(Json.ordered("actorId",owner.actor().actorId(),"actionType",actionType,
            "workflowId",receiptWorkflow,"body",canonicalBody)),receipt.get("payload_hash"));
        var audit=db.query("SELECT * FROM audit_event WHERE action_id=?",action);assertFalse(audit.isEmpty());
        for(var event:audit)assertEquals(owner.actor().actorId(),event.get("actor_id"));
        String receiptJson=receipt.get("result_json").toString();var replay=json.map(receiptJson);
        assertEquals(reply,replay);replay.put("replayed",true);
        String receiptRowJson=db.jdbc().queryForObject("SELECT to_jsonb(a)::text FROM action_request a WHERE action_id=?",String.class,action);
        return new Saved(incident,action,path,body,status,reply,owner,receiptJson,receiptRowJson,json.bytes(replay),durableRows());
    }

    private String exerciseReleaseNormalization(Saved saved) throws Exception {
        var r=json.read(saved.body(),ReleaseRequest.class).remediation();
        String reordered=json.write(Json.ordered("remediation",Json.ordered("note",r.note(),"safeAgentVersion",r.safeAgentVersion(),
            "safeAgentId",r.safeAgentId(),"checkEvidenceIds",r.checkEvidenceIds(),"safeDocumentVersion",r.safeDocumentVersion(),"safeDocumentId",r.safeDocumentId())));
        String spaced=" \n "+saved.body().replace("{","{ \n ").replace(",",", \n ").replace("}"," \n }")+" \t";
        String escaped=saved.body().replace("\"remediation\"","\""+"\\"+"u0072emediation\"")
            .replace("Reviewed","\\"+"u0052eviewed").replace(" / "," \\/ ");
        for(String body:List.of(reordered,spaced,escaped)) {
            assertNotEquals(saved.body(),body);
            assertEquals(json.map(saved.body()),json.map(body));
            assertEquals(json.read(saved.body(),ReleaseRequest.class),json.read(body,ReleaseRequest.class));
            replay(saved,body,saved.owner());
        }
        return escaped;
    }

    private Saved exerciseAuthorityMatrix(Saved saved,String body) throws Exception {
        assertTrue(jobs.claim().isEmpty());assertUnchanged(saved);
        // Each issuance is checked for exactly one auth-only row before beginning any HTTP no-write window.
        var owner=saved.owner().actor();
        var other=identity(owner.role());
        var samePrincipal=identity(owner.actorId(),owner.role());
        var forbidden=ROLES.stream().filter(role->!role.equals(owner.role()))
            .map(role->identity(owner.actorId(),role)).toList();
        saved=rebase(saved,durableRows());replay(saved,body,saved.owner());
        assertNotEquals(other.actor().actorId(),saved.owner().actor().actorId());
        assertEquals(saved.owner().actor().role(),registry.resolve(other.token()).role());
        assertEquals(saved.owner().actor().customerIds(),registry.resolve(other.token()).customerIds());
        denied(saved,body,other,403,"FORBIDDEN");
        // Ownership is principal-bound, but current role is still required on a second credential for that principal.
        assertEquals(saved.owner().actor(),registry.resolve(samePrincipal.token()));
        replay(saved,body,samePrincipal);
        for(var caller:forbidden) {
            assertEquals(saved.owner().actor().actorId(),registry.resolve(caller.token()).actorId());
            assertEquals(saved.owner().actor().customerIds(),registry.resolve(caller.token()).customerIds());
            denied(saved,body,caller,403,"FORBIDDEN");
        }
        saved=rebase(saved,authOracle().updateScope(saved.owner().actor().actorId(),Set.of("customer-103")));
        assertEquals(Set.of("customer-103"),registry.resolve(saved.owner().token()).customerIds());
        denied(saved,body,saved.owner(),403,"FORBIDDEN");
        saved=rebase(saved,authOracle().updateScope(saved.owner().actor().actorId(),Set.of("customer-102")));
        assertEquals(saved.owner().actor(),registry.resolve(saved.owner().token()));
        replay(saved,body,saved.owner());
        saved=rebase(saved,authOracle().revoke(saved.owner().actor().actorId()));
        assertNull(registry.resolve(saved.owner().token()));denied(saved,body,saved.owner(),401,"UNAUTHENTICATED");
        assertUnchanged(saved);return saved;
    }

    private void replay(Saved saved,String body,Identity caller) throws Exception {
        clock.set(clock.now().plusSeconds(1));
        var response=client.send(request(saved.path(),saved.actionId(),body,caller),HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(saved.status(),response.statusCode());assertEquals("no-store",response.headers().firstValue("Cache-Control").orElseThrow());
        var expected=new LinkedHashMap<>(saved.reply());expected.put("replayed",true);
        assertEquals(expected,json.map(response.body()),"Only replayed changes in the saved success");
        assertArrayEquals(saved.replayBody(),response.body(),"Return the encoded stored receipt, not a reconstruction from current state");
        assertUnchanged(saved);
    }

    private void conflict(Saved saved,String body) throws Exception {
        assertNotEquals(json.map(saved.body()),json.map(body));
        clock.set(clock.now().plusSeconds(1));
        var response=post(saved.path(),saved.actionId(),body,saved.owner());
        assertEquals(409,response.statusCode(),response.body());
        assertError(saved,response,"REPLAY_CONFLICT");
        assertEquals(saved.actionId().toString(),json.map(response.body()).get("requestId"));
        assertUnchanged(saved);replay(saved,saved.body(),saved.owner());
    }

    private void denied(Saved saved,String body,Identity caller,int status,String reason) throws Exception {
        clock.set(clock.now().plusSeconds(1));
        var response=post(saved.path(),saved.actionId(),body,caller);
        assertEquals(status,response.statusCode(),caller.actor().role()+": "+response.body());
        assertError(saved,response,reason);assertUnchanged(saved);
    }

    private void assertError(Saved saved,HttpResponse<String> response,String reason) {
        var error=json.map(response.body());
        assertEquals(Set.of("requestId","workflowId","generation","state","decision","reasonCodes","message","replayed"),error.keySet());
        assertEquals("DENY",error.get("decision"));assertEquals(List.of(reason),error.get("reasonCodes"));assertEquals(false,error.get("replayed"));
        for(String key:List.of("workflowId","generation","state","kycJobId","quarantineId","scope","target"))assertNull(error.get(key));
        assertNotEquals(saved.reply().get("message"),error.get("message"));
        for(String hidden:List.of(saved.incident().workflowId().toString(),saved.incident().quarantineId().toString(),
            saved.incident().runId().toString(),RELEASE_NOTE,RESUME_REASON))assertFalse(response.body().contains(hidden));
        if(saved.reply().containsKey("kycJobId"))assertFalse(response.body().contains(saved.reply().get("kycJobId").toString()));
        assertEquals("no-store",response.headers().firstValue("Cache-Control").orElseThrow());
    }

    private void assertUnchanged(Saved saved) {
        var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",saved.actionId());
        assertEquals(saved.receiptJson(),receipt.get("result_json").toString(),"Saved JSON text remains exactly unchanged");
        assertEquals(saved.receiptRowJson(),db.jdbc().queryForObject(
            "SELECT to_jsonb(a)::text FROM action_request a WHERE action_id=?",String.class,saved.actionId()),
            "Every original receipt column, including fingerprint and timestamps, remains unchanged");
        assertEquals("SUCCEEDED",receipt.get("status"));assertEquals("ALLOW",receipt.get("decision"));
        assertEquals(saved.rows(),durableRows(),"Preserve every committed row and timestamp, including other workflows and auth history");
    }

    private Saved rebase(Saved saved,Map<String,List<String>> rows) {
        return new Saved(saved.incident(),saved.actionId(),saved.path(),saved.body(),saved.status(),saved.reply(),
            saved.owner(),saved.receiptJson(),saved.receiptRowJson(),saved.replayBody(),rows);
    }
    private Identity identity(String role) {return identity("recovery-reply-"+UUID.randomUUID(),role);}
    private Identity identity(String actorId,String role) {
        String token=DevActorRegistry.generateToken();var actor=new Actor(actorId,role,Set.of("customer-102"));
        authOracle().issue(token,actor);assertEquals(actor,registry.resolve(token));return new Identity(token,actor);
    }
    private DemoTokenFixtureOracle authOracle() {return new DemoTokenFixtureOracle(tokenFixture,json,this::durableRows);}
    private HttpResponse<String> post(String path,UUID action,String body,Identity caller) throws Exception {
        return client.send(request(path,action,body,caller),HttpResponse.BodyHandlers.ofString());
    }
    private HttpRequest request(String path,UUID action,String body,Identity caller) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path)).timeout(Duration.ofSeconds(10))
            .header("Authorization","Bearer "+caller.token()).header("Idempotency-Key",action.toString())
            .header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }
    private UUID populatedIndependentWorkflow() {
        UUID id=start("customer-103");var prepared=prepareKyc();assertEquals(id,prepared.input().workflowId());
        kyc.apply(prepared,verified(prepared));var loan=jobs.claim().orElseThrow();assertEquals("LOAN",loan.phase());
        loans.execute(loan.jobId(),loan.token());assertEquals("REJECTED",workflow(id).get("state"));
        for(String table:List.of("agent_result","risk_ledger","audit_event"))
            assertFalse(db.query("SELECT id FROM "+table+" WHERE workflow_id=?",id).isEmpty());
        assertTrue(jobs.claim().isEmpty());return id;
    }
    private Map<String,List<String>> durableRows() {
        var fresh=new TransactionTemplate(Objects.requireNonNull(tx.getTransactionManager()));
        fresh.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        fresh.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);fresh.setReadOnly(true);
        return fresh.execute(status->{
            var rows=new LinkedHashMap<String,List<String>>();
            var tables=db.jdbc().queryForList("SELECT table_name FROM information_schema.tables "
                +"WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name",String.class);
            assertTrue(tables.containsAll(List.of("demo_auth_registry","demo_token","workflow","workflow_job","workflow_stage",
                "agent_run","agent_result","delegation_grant","approval","payment_reservation","mock_payment","risk_ledger",
                "quarantine","action_request","audit_event")));
            for(String table:tables)rows.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM public.\""
                +table.replace("\"","\"\"")+"\" t ORDER BY to_jsonb(t)::text",String.class));
            return rows;
        });
    }
}
