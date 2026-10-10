package com.finsec.fuse.integration;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.quarantine.QuarantineRequest;
import com.finsec.fuse.quarantine.ReleaseRequest;
import com.finsec.fuse.quarantine.ResumeRequest;
import com.finsec.fuse.workflow.StartWorkflowRequest;
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

/** Workflow-start historical replies require current role/scope and original action ownership. */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
class PublicWorkflowStartStoredReplyAuthorityIT extends PaymentFixture {
    private static final String CUSTOMER="customer-102";
    private static final String INDEPENDENT_CUSTOMER="customer-103";
    private static final Set<String> ENVELOPE_FIELDS=Set.of("requestId","workflowId","generation","state",
        "decision","reasonCodes","message","replayed");
    @Value("${local.server.port}") int port;
    @Autowired DevActorRegistry registry;
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private record Identity(String token,Actor actor) {}
    private record Saved(UUID workflowId,UUID actionId,String body,Map<String,Object> reply,Identity owner) {}
    private record StoredStartAllow(Saved saved,String receiptJson,byte[] replayBody,Map<String,List<String>> rows) {}
    private record StoredStartDeny(Saved saved,String receiptJson,byte[] replayBody,Map<String,List<String>> rows) {}
    private enum Rejection {
        OWNER(403,"FORBIDDEN","Action receipt is outside the current actor's access",false),
        ROLE(403,"FORBIDDEN","This role cannot perform the requested action",false),
        SCOPE(403,"FORBIDDEN","Customer is outside the authenticated actor's access scope",false),
        SERVICE(403,"FORBIDDEN","Service identities cannot access the public API",true),
        REVOKED(401,"UNAUTHENTICATED","A valid bearer token is required",true);
        final int status;final String reason,message;final boolean filter;
        Rejection(int status,String reason,String message,boolean filter) {
            this.status=status;this.reason=reason;this.message=message;this.filter=filter;
        }
    }

    private Identity identity(String role) {
        return identity("start-reply-"+UUID.randomUUID(),role);
    }
    private Identity identity(String actorId,String role) {
        String token=DevActorRegistry.generateToken();
        var actor=new Actor(actorId,role,Set.of(CUSTOMER));
        registry.register(token,actor);
        assertEquals(actor,registry.resolve(token),"Every caller must be a recognized server-side identity");
        return new Identity(token,actor);
    }
    private HttpResponse<String> post(UUID action,String body,Identity caller) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/api/v1/workflows"))
            .timeout(Duration.ofSeconds(10)).header("Authorization","Bearer "+caller.token())
            .header("Idempotency-Key",action.toString()).header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
    }
    private Saved saveStart(Identity owner,String state,String decision,List<String> reasons) throws Exception {
        UUID action=UUID.randomUUID();
        String body=json.write(new StartWorkflowRequest("APP-DEMO-102-001",CUSTOMER,1000000L,
            UUID.fromString("00000000-0000-4000-8000-000000000102")));
        var response=post(action,body,owner);
        assertEquals(202,response.statusCode(),response.body());
        var reply=json.map(response.body());
        assertEquals(ENVELOPE_FIELDS,reply.keySet());
        assertEquals(action.toString(),reply.get("requestId"));assertEquals(false,reply.get("replayed"));
        assertEquals(state,reply.get("state"));assertEquals(decision,reply.get("decision"));
        assertEquals(reasons,reply.get("reasonCodes"));assertEquals(1,((Number)reply.get("generation")).intValue());
        UUID workflowId=UUID.fromString((String)reply.get("workflowId"));
        var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",action);
        assertEquals(owner.actor().actorId(),receipt.get("actor_id"));
        assertEquals("START_WORKFLOW",receipt.get("action_type"));
        // START_WORKFLOW fingerprints have no path workflow ID, even when reusing an existing application.
        assertNull(receipt.get("workflow_id"));
        assertEquals("SUCCEEDED",receipt.get("status"));assertEquals(decision,receipt.get("decision"));
        assertNotNull(receipt.get("completed_at"));
        assertEquals(reply,json.map(receipt.get("result_json").toString()));
        return new Saved(workflowId,action,body,reply,owner);
    }
    private Saved saveInitialStart(Identity owner) throws Exception {
        var before=durableRows();
        var saved=saveStart(owner,"KYC_PENDING","ALLOW",List.of());
        assertRowsAdded(before,durableRows(),Map.of("loan_application",1,"workflow",1,"workflow_stage",3,
            "workflow_job",1,"action_request",1,"audit_event",1));
        assertCreationActor(saved);
        return saved;
    }
    private void assertCreationActor(Saved saved) {
        assertEquals(saved.owner().actor().actorId(),workflow(saved.workflowId()).get("principal_id"));
        var audit=db.query("SELECT * FROM audit_event WHERE action_id=?",saved.actionId());
        assertEquals(1,audit.size());
        assertEquals("WORKFLOW_CREATED",audit.getFirst().get("event_type"));
        assertEquals(saved.owner().actor().actorId(),audit.getFirst().get("actor_id"));
        assertEquals(saved.workflowId(),audit.getFirst().get("workflow_id"));
    }
    private void finishEvaluation(UUID workflowId,String state) {
        var prepared=prepareKyc();assertEquals(workflowId,prepared.input().workflowId());
        kyc.apply(prepared,verified(prepared));
        var loan=jobs.claim().orElseThrow();assertEquals("LOAN",loan.phase());
        loans.execute(loan.jobId(),loan.token());
        assertEquals(state,workflow(workflowId).get("state"));
        assertTrue(jobs.claim().isEmpty(),"No asynchronous work may race the committed-row oracle");
    }
    private UUID populatedIndependentWorkflow() {
        UUID id=start(INDEPENDENT_CUSTOMER);finishEvaluation(id,"REJECTED");
        for(String table:List.of("agent_result","risk_ledger","audit_event"))
            assertFalse(db.query("SELECT * FROM "+table+" WHERE workflow_id=?",id).isEmpty());
        return id;
    }

    @Timeout(60) @Test
    void savedStartAllowRequiresCurrentAuthorityForCustomer() throws Exception {
        savedStartAllowChecksBothAllowedRolesCurrentScopeAndActionOwnership("CUSTOMER");
    }

    @Timeout(60) @Test
    void savedStartAllowRequiresCurrentAuthorityForLoanReviewer() throws Exception {
        savedStartAllowChecksBothAllowedRolesCurrentScopeAndActionOwnership("LOAN_REVIEWER");
    }

    private void savedStartAllowChecksBothAllowedRolesCurrentScopeAndActionOwnership(String role) throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var saved=saveInitialStart(identity(role));
        finishEvaluation(saved.workflowId(),"WAIT_APPROVAL");
        // The saved KYC_PENDING reply must not be rebuilt from the now-WAIT_APPROVAL workflow.
        exerciseAuthorityMatrix(saved,independent);
        assertEquals("WAIT_APPROVAL",workflow(saved.workflowId()).get("state"));
        assertCreationActor(saved);
    }

    @Timeout(60) @Test
    void parsedEquivalentJsonReplaysStoredStartAllowWithoutAnyDurableMutation() throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var original=storedStartAllow();var saved=original.saved();
        var request=json.read(saved.body(),StartWorkflowRequest.class);
        String reordered="{\"payoutAccountId\":"+json.write(request.payoutAccountId())
            +",\"amountKrw\":"+request.amountKrw()+",\"customerId\":"+json.write(request.customerId())
            +",\"businessReference\":"+json.write(request.businessReference())+"}";
        String spaced=" { \n \"businessReference\" : "+json.write(request.businessReference())
            +" , \"customerId\" : "+json.write(request.customerId())+" , \n \"amountKrw\" : "+request.amountKrw()
            +" , \"payoutAccountId\" : "+json.write(request.payoutAccountId())+" \n } \t";
        // Decode both a member name and a string value; construct the JSON escapes at runtime.
        String escaped=saved.body().replace("customerId","customer"+"\\"+"u0049d")
            .replace("APP-DEMO","\\"+"u0041PP-DEMO");
        for(String body:List.of(reordered,spaced,escaped)) {
            assertNotEquals(saved.body(),body,"Each normalization control must change the actual request bytes");
            assertEquals(json.map(saved.body()),json.map(body));
            assertEquals(request,json.read(body,StartWorkflowRequest.class));
            startAllowReplay(original,body);
        }
        // A value-space changes meaning; token-space and escaped representation must not erase it.
        String changed=spaced.replace(json.write(request.businessReference()),
            json.write(request.businessReference()+" "));
        assertEquals(new StartWorkflowRequest(request.businessReference()+" ",request.customerId(),
            request.amountKrw(),request.payoutAccountId()),json.read(changed,StartWorkflowRequest.class));
        assertNotEquals(request,json.read(changed,StartWorkflowRequest.class));
        assertNotEquals(json.map(saved.body()),json.map(changed));
        clock.set(clock.now().plusSeconds(1));
        var conflict=post(saved.actionId(),changed,saved.owner());
        assertEquals(409,conflict.statusCode(),conflict.body());assertSafeHeaders(conflict);
        var expected=Json.ordered("requestId",saved.actionId().toString(),"workflowId",null,"generation",null,
            "state",null,"decision","DENY","reasonCodes",List.of("REPLAY_CONFLICT"),
            "message","Idempotency key was already used for a different request","replayed",false);
        assertEquals(expected,json.map(conflict.body()),"Conflict must return only the exact safe public envelope");
        assertFalse(conflict.body().contains(saved.workflowId().toString()));
        assertStoredStartAllowUnchanged(original);
        startAllowReplay(original,saved.body());
        startAllowReplay(original,escaped); // The conflict cannot poison original or equivalent replay.
        // Encoded equivalence must still pass the unchanged current authority and receipt-owner checks.
        exerciseAuthorityMatrix(withBody(saved,escaped),independent);
        assertStoredStartAllowUnchanged(original);
    }

    private StoredStartAllow storedStartAllow() throws Exception {
        var saved=saveInitialStart(identity("CUSTOMER"));
        String receiptJson=db.required("SELECT * FROM action_request WHERE action_id=?",saved.actionId())
            .get("result_json").toString();
        var replay=json.map(receiptJson);assertEquals(saved.reply(),replay);
        replay.put("replayed",true);
        finishEvaluation(saved.workflowId(),"WAIT_APPROVAL");
        var request=new QuarantineRequest(QuarantineRequest.Scope.WORKFLOW,null,null,saved.workflowId(),
            null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Synthetic workflow investigation");
        UUID incident=(UUID)quarantines.apply(SECURITY,UUID.randomUUID(),request).get("quarantineId");
        assertEquals("BLOCKED",workflow(saved.workflowId()).get("state"));
        assertEquals("DENY",workflow(saved.workflowId()).get("last_decision"));
        var evidenceIds=db.jdbc().queryForList("SELECT id FROM trusted_evidence "
            +"WHERE customer_id=? AND status='ACTIVE' AND outcome='PASS' ORDER BY id",UUID.class,CUSTOMER);
        assertFalse(evidenceIds.isEmpty());
        var release=new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,evidenceIds,null,null,
            "Reviewed synthetic remediation"));
        quarantines.release(SECURITY,incident,UUID.randomUUID(),release);
        assertEquals("RELEASED",db.required("SELECT * FROM quarantine WHERE id=?",incident).get("status"));
        var resumed=recovery.resume(REVIEWER,saved.workflowId(),UUID.randomUUID(),
            new ResumeRequest(1,"Resume after synthetic remediation"));
        assertEquals("ALLOW",resumed.get("decision"));assertEquals(2,((Number)resumed.get("generation")).intValue());
        finishEvaluation(saved.workflowId(),"WAIT_APPROVAL");
        assertCreationActor(saved);
        var original=new StoredStartAllow(saved,receiptJson,json.bytes(replay),durableRows());
        assertStoredStartAllowUnchanged(original); // The initial receipt also survives legitimate advancement.
        return original;
    }
    private void startAllowReplay(StoredStartAllow original,String body) throws Exception {
        clock.set(clock.now().plusSeconds(1));
        var saved=original.saved();
        var response=client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/api/v1/workflows"))
            .timeout(Duration.ofSeconds(10)).header("Authorization","Bearer "+saved.owner().token())
            .header("Idempotency-Key",saved.actionId().toString()).header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(202,response.statusCode(),"Preserve the original accepted ALLOW HTTP status");
        assertEquals("no-store",response.headers().firstValue("Cache-Control").orElseThrow());
        assertEquals("nosniff",response.headers().firstValue("X-Content-Type-Options").orElseThrow());
        var expected=new LinkedHashMap<>(saved.reply());expected.put("replayed",true);
        assertEquals(expected,json.map(response.body()),"Only replayed may change in the historical KYC_PENDING ALLOW reply");
        assertArrayEquals(original.replayBody(),response.body(),"Return the encoded stored reply with only replayed changed");
        assertStoredStartAllowUnchanged(original);
    }
    private void assertStoredStartAllowUnchanged(StoredStartAllow original) {
        var saved=original.saved();
        var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",saved.actionId());
        assertEquals(original.receiptJson(),receipt.get("result_json").toString(),"Stored JSON bytes must remain untouched");
        assertEquals("SUCCEEDED",receipt.get("status"));assertEquals("ALLOW",receipt.get("decision"));
        assertEquals(2,integer(workflow(saved.workflowId()),"generation"));
        assertEquals("WAIT_APPROVAL",workflow(saved.workflowId()).get("state"));
        assertEquals(0,count("approval"));assertEquals(0,count("payment_reservation"));assertEquals(0,count("mock_payment"));
        assertEquals(original.rows(),durableRows(),"Preserve every committed row and timestamp, including the independent workflow");
    }

    @Timeout(60) @Test
    void savedStartBusinessDenyRequiresCurrentAuthorityForCustomer() throws Exception {
        savedStartBusinessDenyChecksBothAllowedRolesCurrentScopeAndActionOwnership("CUSTOMER");
    }

    @Timeout(60) @Test
    void savedStartBusinessDenyRequiresCurrentAuthorityForLoanReviewer() throws Exception {
        savedStartBusinessDenyChecksBothAllowedRolesCurrentScopeAndActionOwnership("LOAN_REVIEWER");
    }

    private void savedStartBusinessDenyChecksBothAllowedRolesCurrentScopeAndActionOwnership(String role) throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var owner=identity(role);
        var original=saveInitialStart(owner);
        finishEvaluation(original.workflowId(),"WAIT_APPROVAL");
        var request=new QuarantineRequest(QuarantineRequest.Scope.WORKFLOW,null,null,original.workflowId(),
            null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Synthetic workflow investigation");
        UUID incident=(UUID)quarantines.apply(SECURITY,UUID.randomUUID(),request).get("quarantineId");
        assertEquals("BLOCKED",workflow(original.workflowId()).get("state"));
        assertEquals("DENY",workflow(original.workflowId()).get("last_decision"));
        var beforeSave=durableRows();
        // This is a real accepted duplicate-application snapshot, not a fabricated failed HTTP receipt.
        var saved=saveStart(owner,"BLOCKED","DENY",List.of("SECURITY_INVESTIGATION"));
        assertNotEquals(original.actionId(),saved.actionId());assertEquals(original.workflowId(),saved.workflowId());
        assertRowsAdded(beforeSave,durableRows(),Map.of("action_request",1));
        assertTrue(db.query("SELECT * FROM audit_event WHERE action_id=?",saved.actionId()).isEmpty(),
            "Returning an existing workflow must not attribute its earlier quarantine to the start caller");

        // Real release/resume makes both the saved state and generation historical before replay checks.
        var evidenceIds=db.jdbc().queryForList("SELECT id FROM trusted_evidence "
            +"WHERE customer_id=? AND status='ACTIVE' AND outcome='PASS' ORDER BY id",UUID.class,CUSTOMER);
        assertFalse(evidenceIds.isEmpty());
        var release=new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,evidenceIds,null,null,
            "Reviewed synthetic remediation"));
        quarantines.release(SECURITY,incident,UUID.randomUUID(),release);
        assertEquals("RELEASED",db.required("SELECT * FROM quarantine WHERE id=?",incident).get("status"));
        var resumed=recovery.resume(REVIEWER,saved.workflowId(),UUID.randomUUID(),
            new ResumeRequest(1,"Resume after synthetic remediation"));
        assertEquals("ALLOW",resumed.get("decision"));assertEquals(2,((Number)resumed.get("generation")).intValue());
        finishEvaluation(saved.workflowId(),"WAIT_APPROVAL");
        exerciseAuthorityMatrix(saved,independent);
        assertEquals(2,integer(workflow(saved.workflowId()),"generation"));
        assertEquals("WAIT_APPROVAL",workflow(saved.workflowId()).get("state"));
        assertCreationActor(original);
    }

    @Timeout(60) @Test
    void parsedEquivalentJsonReplaysStoredStartDenyWithoutAnyDurableMutation() throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var original=storedStartDeny();var saved=original.saved();
        startDenyReplay(original,saved.body());
        var request=json.read(saved.body(),StartWorkflowRequest.class);
        String reordered="{\"payoutAccountId\":"+json.write(request.payoutAccountId())
            +",\"amountKrw\":"+request.amountKrw()+",\"customerId\":"+json.write(request.customerId())
            +",\"businessReference\":"+json.write(request.businessReference())+"}";
        String spaced=" { \n \"businessReference\" : "+json.write(request.businessReference())
            +" , \"customerId\" : "+json.write(request.customerId())+" , \n \"amountKrw\" : "+request.amountKrw()
            +" , \"payoutAccountId\" : "+json.write(request.payoutAccountId())+" \n } \t";
        // Decode both a member name and a string value; construct the JSON escapes at runtime.
        String escaped=saved.body().replace("customerId","customer"+"\\"+"u0049d")
            .replace("APP-DEMO","\\"+"u0041PP-DEMO");
        for(String body:List.of(reordered,spaced,escaped)) {
            assertNotEquals(saved.body(),body,"Each normalization control must change the actual request bytes");
            assertEquals(json.map(saved.body()),json.map(body));
            assertEquals(request,json.read(body,StartWorkflowRequest.class));
            startDenyReplay(original,body);
        }
        // Equivalent wire forms still require current authority and the original action's owner.
        exerciseAuthorityMatrix(withBody(saved,escaped),independent);
        assertStoredStartDenyUnchanged(original);
    }

    @Timeout(60) @Test
    void changedStartBusinessFieldsConflictWithoutPoisoningStoredDeny() throws Exception {
        UUID independent=populatedIndependentWorkflow();
        var original=storedStartDeny();var saved=original.saved();
        var request=json.read(saved.body(),StartWorkflowRequest.class);
        startDenyReplay(original,saved.body());
        startDenyConflict(original,new StartWorkflowRequest("APP-DEMO-102-CHANGED",request.customerId(),
            request.amountKrw(),request.payoutAccountId()));
        // Value whitespace remains meaningful even though whitespace between JSON tokens does not.
        startDenyConflict(original,new StartWorkflowRequest(request.businessReference()+" ",request.customerId(),
            request.amountKrw(),request.payoutAccountId()));
        startDenyConflict(original,new StartWorkflowRequest(request.businessReference(),request.customerId(),
            request.amountKrw()+1,request.payoutAccountId()));
        startDenyConflict(original,new StartWorkflowRequest(request.businessReference(),request.customerId(),
            request.amountKrw(),UUID.fromString("00000000-0000-4000-8000-000000000103")));
        // The changed customer must also be authorized, so this control reaches fingerprint comparison.
        registry.updateScope(saved.owner().actor().actorId(),Set.of(CUSTOMER,INDEPENDENT_CUSTOMER));
        assertEquals(Set.of(CUSTOMER,INDEPENDENT_CUSTOMER),registry.resolve(saved.owner().token()).customerIds());
        startDenyConflict(original,new StartWorkflowRequest(request.businessReference(),INDEPENDENT_CUSTOMER,
            request.amountKrw(),request.payoutAccountId()));
        registry.updateScope(saved.owner().actor().actorId(),Set.of(CUSTOMER));
        assertEquals(saved.owner().actor(),registry.resolve(saved.owner().token()));
        startDenyReplay(original,saved.body());
        assertEquals("REJECTED",workflow(independent).get("state"));
        assertStoredStartDenyUnchanged(original);
    }

    private StoredStartDeny storedStartDeny() throws Exception {
        var owner=identity("CUSTOMER");
        var original=saveInitialStart(owner);
        finishEvaluation(original.workflowId(),"WAIT_APPROVAL");
        var request=new QuarantineRequest(QuarantineRequest.Scope.WORKFLOW,null,null,original.workflowId(),
            null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Synthetic workflow investigation");
        UUID incident=(UUID)quarantines.apply(SECURITY,UUID.randomUUID(),request).get("quarantineId");
        assertEquals("BLOCKED",workflow(original.workflowId()).get("state"));
        assertEquals("DENY",workflow(original.workflowId()).get("last_decision"));
        var beforeSave=durableRows();
        // Store a real duplicate-application business DENY through the public start route.
        var saved=saveStart(owner,"BLOCKED","DENY",List.of("SECURITY_INVESTIGATION"));
        assertNotEquals(original.actionId(),saved.actionId());assertEquals(original.workflowId(),saved.workflowId());
        assertRowsAdded(beforeSave,durableRows(),Map.of("action_request",1));
        assertTrue(db.query("SELECT * FROM audit_event WHERE action_id=?",saved.actionId()).isEmpty());
        var evidenceIds=db.jdbc().queryForList("SELECT id FROM trusted_evidence "
            +"WHERE customer_id=? AND status='ACTIVE' AND outcome='PASS' ORDER BY id",UUID.class,CUSTOMER);
        assertFalse(evidenceIds.isEmpty());
        var release=new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,evidenceIds,null,null,
            "Reviewed synthetic remediation"));
        quarantines.release(SECURITY,incident,UUID.randomUUID(),release);
        assertEquals("RELEASED",db.required("SELECT * FROM quarantine WHERE id=?",incident).get("status"));
        var resumed=recovery.resume(REVIEWER,saved.workflowId(),UUID.randomUUID(),
            new ResumeRequest(1,"Resume after synthetic remediation"));
        assertEquals("ALLOW",resumed.get("decision"));assertEquals(2,((Number)resumed.get("generation")).intValue());
        finishEvaluation(saved.workflowId(),"WAIT_APPROVAL");
        assertCreationActor(original);
        var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",saved.actionId());
        assertNotNull(receipt.get("completed_at"));
        String receiptJson=receipt.get("result_json").toString();
        var replay=json.map(receiptJson);assertEquals(saved.reply(),replay);
        replay.put("replayed",true);
        return new StoredStartDeny(saved,receiptJson,json.bytes(replay),durableRows());
    }
    private Saved withBody(Saved saved,String body) {
        return new Saved(saved.workflowId(),saved.actionId(),body,saved.reply(),saved.owner());
    }
    private void startDenyReplay(StoredStartDeny original,String body) throws Exception {
        clock.set(clock.now().plusSeconds(1));
        var saved=original.saved();
        var response=client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/api/v1/workflows"))
            .timeout(Duration.ofSeconds(10)).header("Authorization","Bearer "+saved.owner().token())
            .header("Idempotency-Key",saved.actionId().toString()).header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(202,response.statusCode(),"Preserve the original accepted business DENY HTTP status");
        assertEquals("no-store",response.headers().firstValue("Cache-Control").orElseThrow());
        assertEquals("nosniff",response.headers().firstValue("X-Content-Type-Options").orElseThrow());
        var expected=new LinkedHashMap<>(saved.reply());expected.put("replayed",true);
        assertEquals(expected,json.map(response.body()),"Only replayed may change in the original business DENY reply");
        assertArrayEquals(original.replayBody(),response.body(),"Return the encoded stored reply with only replayed changed");
        assertStoredStartDenyUnchanged(original);
    }
    private void startDenyConflict(StoredStartDeny original,StartWorkflowRequest changed) throws Exception {
        var saved=original.saved();String body=json.write(changed);
        assertNotEquals(json.read(saved.body(),StartWorkflowRequest.class),changed);
        assertNotEquals(json.map(saved.body()),json.map(body));
        clock.set(clock.now().plusSeconds(1));
        var response=post(saved.actionId(),body,saved.owner());assertEquals(409,response.statusCode(),response.body());
        assertSafeHeaders(response);
        var expected=Json.ordered("requestId",saved.actionId().toString(),"workflowId",null,"generation",null,
            "state",null,"decision","DENY","reasonCodes",List.of("REPLAY_CONFLICT"),
            "message","Idempotency key was already used for a different request","replayed",false);
        assertEquals(expected,json.map(response.body()),"Conflict must return only the exact safe public envelope");
        assertFalse(response.body().contains(saved.workflowId().toString()));
        assertFalse(response.body().contains("SECURITY_INVESTIGATION"));
        assertStoredStartDenyUnchanged(original);
        startDenyReplay(original,saved.body()); // Each conflict leaves the original action replayable.
    }
    private void assertStoredStartDenyUnchanged(StoredStartDeny original) {
        var saved=original.saved();
        var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",saved.actionId());
        assertEquals(original.receiptJson(),receipt.get("result_json").toString(),"Stored JSON bytes must remain untouched");
        assertEquals("SUCCEEDED",receipt.get("status"));assertEquals("DENY",receipt.get("decision"));
        assertEquals(2,integer(workflow(saved.workflowId()),"generation"));
        assertEquals("WAIT_APPROVAL",workflow(saved.workflowId()).get("state"));
        assertEquals(0,count("approval"));assertEquals(0,count("payment_reservation"));assertEquals(0,count("mock_payment"));
        assertEquals(original.rows(),durableRows(),"Preserve every committed row and timestamp, including the independent workflow");
    }

    private void exerciseAuthorityMatrix(Saved saved,UUID independent) throws Exception {
        assertTrue(jobs.claim().isEmpty());
        var before=durableRows();
        ownerReplay(saved,before);
        // Both roles may start this customer's workflow, but neither other actor owns the saved action.
        for(String role:List.of("CUSTOMER","LOAN_REVIEWER"))
            denied(saved,identity(role),Rejection.OWNER,before);
        // Same-principal registry credentials isolate current role checks from receipt-owner checks.
        for(String role:List.of("CUSTOMER","LOAN_REVIEWER"))
            authorizedReplay(saved,identity(saved.owner().actor().actorId(),role),before);
        for(String role:List.of("SECURITY_OPERATOR","DEVELOPER"))
            denied(saved,identity(saved.owner().actor().actorId(),role),Rejection.ROLE,before);
        for(String role:List.of("FUSE_WORKER","KYC_SERVICE"))
            denied(saved,identity(saved.owner().actor().actorId(),role),Rejection.SERVICE,before);
        for(Set<String> scope:List.of(Set.<String>of(),Set.of(INDEPENDENT_CUSTOMER))) {
            registry.updateScope(saved.owner().actor().actorId(),scope);
            assertEquals(scope,registry.resolve(saved.owner().token()).customerIds());
            denied(saved,saved.owner(),Rejection.SCOPE,before);
        }
        registry.updateScope(saved.owner().actor().actorId(),Set.of(CUSTOMER));
        assertEquals(saved.owner().actor(),registry.resolve(saved.owner().token()));
        ownerReplay(saved,before); // Denied attempts must neither consume nor replace the original receipt.
        registry.updateScope(saved.owner().actor().actorId(),Set.of(CUSTOMER,INDEPENDENT_CUSTOMER));
        assertEquals(Set.of(CUSTOMER,INDEPENDENT_CUSTOMER),registry.resolve(saved.owner().token()).customerIds());
        ownerReplay(saved,before); // Authority is current customer membership, not equality with the old scope set.
        registry.updateScope(saved.owner().actor().actorId(),Set.of(CUSTOMER));
        assertEquals(saved.owner().actor(),registry.resolve(saved.owner().token()));
        ownerReplay(saved,before);
        registry.revoke(saved.owner().actor().actorId());assertNull(registry.resolve(saved.owner().token()));
        denied(saved,saved.owner(),Rejection.REVOKED,before);
        assertEquals("REJECTED",workflow(independent).get("state"));
        assertEquals(0,count("approval"));assertEquals(0,count("payment_reservation"));assertEquals(0,count("mock_payment"));
        assertEquals(before,durableRows(),"Include the populated independent workflow and all historical receipts");
    }
    private void ownerReplay(Saved saved,Map<String,List<String>> before) throws Exception {
        authorizedReplay(saved,saved.owner(),before);
    }
    private void authorizedReplay(Saved saved,Identity caller,Map<String,List<String>> before) throws Exception {
        clock.set(clock.now().plusSeconds(1));
        var response=post(saved.actionId(),saved.body(),caller);
        assertEquals(202,response.statusCode(),response.body());
        assertSafeHeaders(response);
        var expected=new LinkedHashMap<>(saved.reply());expected.put("replayed",true);
        assertEquals(expected,json.map(response.body()),"Only replayed may change in the historical response");
        assertEquals(before,durableRows(),"Replay must not refresh timestamps, append audit or restart work");
    }
    private void denied(Saved saved,Identity caller,Rejection denial,Map<String,List<String>> before) throws Exception {
        clock.set(clock.now().plusSeconds(1));
        var response=post(saved.actionId(),saved.body(),caller);
        assertEquals(denial.status,response.statusCode(),caller.actor().role()+": "+response.body());
        assertSafeHeaders(response);
        var error=json.map(response.body());
        var expected=Json.ordered("requestId",denial.filter?null:saved.actionId().toString(),"workflowId",null,
            "generation",null,"state",null,"decision","DENY","reasonCodes",List.of(denial.reason),
            "message",denial.message,"replayed",false);
        assertEquals(expected,error,"Only the exact public authorization envelope may escape");
        assertFalse(response.body().contains(saved.workflowId().toString()));
        assertFalse(response.body().contains("SECURITY_INVESTIGATION"));
        assertEquals(before,durableRows(),"Denied replay must preserve every committed row and the original receipt");
    }
    private void assertSafeHeaders(HttpResponse<String> response) {
        assertEquals("no-store",response.headers().firstValue("Cache-Control").orElseThrow());
        assertEquals("nosniff",response.headers().firstValue("X-Content-Type-Options").orElseThrow());
    }
    private void assertRowsAdded(Map<String,List<String>> before,Map<String,List<String>> after,Map<String,Integer> additions) {
        assertEquals(before.keySet(),after.keySet());
        for(String table:before.keySet()) {
            assertEquals(before.get(table).size()+additions.getOrDefault(table,0),after.get(table).size(),table);
            assertTrue(after.get(table).containsAll(before.get(table)),table+" must preserve every preexisting row");
            if(!additions.containsKey(table))assertEquals(before.get(table),after.get(table),table+" must remain unchanged");
        }
    }
    private Map<String,List<String>> durableRows() {
        var fresh=new TransactionTemplate(Objects.requireNonNull(tx.getTransactionManager()));
        fresh.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        fresh.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);fresh.setReadOnly(true);
        return fresh.execute(status->{
            var rows=new LinkedHashMap<String,List<String>>();
            var tables=db.jdbc().queryForList("SELECT table_name FROM information_schema.tables "
                +"WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name",String.class);
            assertTrue(tables.containsAll(List.of("workflow","workflow_job","workflow_stage","agent_run","agent_result",
                "delegation_grant","approval","quarantine","payment_reservation","mock_payment","risk_ledger",
                "action_request","audit_event")));
            // Every column, including JSON receipts and timestamps, detects updates as well as extra rows.
            for(String table:tables)rows.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM public.\""
                +table.replace("\"","\"\"")+"\" t ORDER BY to_jsonb(t)::text",String.class));
            return rows;
        });
    }
}
