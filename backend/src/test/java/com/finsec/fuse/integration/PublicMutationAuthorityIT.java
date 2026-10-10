package com.finsec.fuse.integration;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.experiments.ExperimentRequest;
import com.finsec.fuse.payment.ApprovalRequest;
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
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import static org.junit.jupiter.api.Assertions.*;

/** v2.1 sections 4.4, 15.1, 15.5 and 15.6: public mutation authority is server-owned. */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
class PublicMutationAuthorityIT extends PaymentFixture {
    @Value("${local.server.port}") int port;
    @Value("${fuse.service-token}") String serviceToken;
    @Autowired DevActorRegistry registry;
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private record Identity(String token,Actor actor) {}
    private record Prepared(UUID target,UUID independent,String approvalBody,QuarantineRequest quarantine) {}

    @Override protected UUID start(String customer) {
        String suffix=customer.substring(customer.length()-3);
        return (UUID)workflows.start(new Actor("authority-start-"+UUID.randomUUID(),"CUSTOMER",Set.of(customer)),
            UUID.randomUUID(),new StartWorkflowRequest("APP-DEMO-"+suffix+"-001",customer,1000000L,
                UUID.fromString("00000000-0000-4000-8000-000000000"+suffix))).get("workflowId");
    }
    private Identity identity(String role) {
        String token=DevActorRegistry.generateToken();
        var actor=new Actor("authority-"+UUID.randomUUID(),role,Set.of("customer-102"));
        registry.register(token,actor);
        assertEquals(actor,registry.resolve(token),"The test must use a recognized server-side identity");
        return new Identity(token,actor);
    }
    private Prepared prepared() {
        UUID target=ready102(),independent=start("customer-103");
        var kycInput=prepareKyc();kyc.apply(kycInput,verified(kycInput));
        var loan=jobs.claim().orElseThrow();assertEquals("LOAN",loan.phase());
        loans.execute(loan.jobId(),loan.token());
        assertEquals("REJECTED",workflow(independent).get("state"));
        assertTrue(jobs.claim().isEmpty(),"Background work must not race the no-mutation oracle");
        String hash=(String)approvals.preview(REVIEWER,target).get("reviewSnapshotHash");
        var approval=new ApprovalRequest(ApprovalRequest.Decision.APPROVE,hash,"Synthetic review confirmed");
        var quarantine=new QuarantineRequest(QuarantineRequest.Scope.WORKFLOW,null,null,target,null,null,null,null,
            QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Synthetic investigation");
        return new Prepared(target,independent,json.write(approval),quarantine);
    }
    private String approvalPath(Prepared fixture) {return "/api/v1/workflows/"+fixture.target()+"/approvals";}
    private HttpResponse<String> post(String path,String token,String internalToken,UUID action,String body) throws Exception {
        var request=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path))
            .timeout(Duration.ofSeconds(10)).header("Idempotency-Key",action.toString())
            .header("Content-Type","application/json");
        if(token!=null)request.header("Authorization","Bearer "+token);
        if(internalToken!=null)request.header("X-Fuse-Service-Token",internalToken);
        return client.send(request.POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
    }
    private <T> T committed(Supplier<T> observation) {
        var fresh=new TransactionTemplate(Objects.requireNonNull(tx.getTransactionManager()));
        fresh.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        fresh.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        fresh.setReadOnly(true);
        return fresh.execute(status->observation.get());
    }
    private String quoted(String table) {return "\""+table.replace("\"","\"\"")+"\"";}
    private Map<String,List<String>> snapshot() {
        return committed(()->{
            var rows=new LinkedHashMap<String,List<String>>();
            var tables=db.jdbc().queryForList("SELECT table_name FROM information_schema.tables "
                +"WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name",String.class);
            assertTrue(tables.containsAll(List.of("execution_gate","application_registry","loan_application",
                "workflow","workflow_job","agent_run","agent_result","delegation_grant","approval",
                "quarantine","payment_reservation","mock_payment","risk_ledger","audit_event","action_request")));
            // Include every persisted column, timestamp, receipt and future table, not just counts.
            for(String table:tables)rows.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM public."
                +quoted(table)+" t ORDER BY to_jsonb(t)::text",String.class));
            return rows;
        });
    }
    private Map<String,List<String>> independentRows(UUID id) {
        return committed(()->{
            var rows=new LinkedHashMap<String,List<String>>();
            var tables=db.jdbc().queryForList("SELECT c.table_name FROM information_schema.columns c "
                +"JOIN information_schema.tables t ON t.table_schema=c.table_schema AND t.table_name=c.table_name "
                +"WHERE c.table_schema='public' AND c.column_name='workflow_id' AND t.table_type='BASE TABLE' "
                +"ORDER BY c.table_name",String.class);
            for(String table:tables)rows.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM public."
                +quoted(table)+" t WHERE workflow_id=? ORDER BY to_jsonb(t)::text",String.class,id));
            rows.put("workflow",db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM workflow t WHERE id=?",String.class,id));
            rows.put("loan_application",db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM loan_application t "
                +"WHERE id=(SELECT application_id FROM workflow WHERE id=?)",String.class,id));
            return rows;
        });
    }
    private void denied(String label,String path,String token,String internalToken,String body,int status,String reason) throws Exception {
        var before=snapshot();
        // Make accidental updated_at writes visible even with the deterministic harness clock.
        clock.set(clock.now().plusSeconds(1));
        var response=post(path,token,internalToken,UUID.randomUUID(),body);
        assertEquals(status,response.statusCode(),label+": "+response.body());
        var error=json.map(response.body());
        assertEquals("DENY",error.get("decision"),label);
        assertEquals(List.of(reason),error.get("reasonCodes"),label);
        assertEquals(false,error.get("replayed"),label);
        assertNull(error.get("workflowId"),label);assertNull(error.get("generation"),label);assertNull(error.get("state"),label);
        assertEquals(before,snapshot(),label+" must preserve every committed durable row, including the independent workflow");
    }
    private void forbidden(String label,String path,Identity actor,String body) throws Exception {
        denied(label,path,actor.token(),null,body,403,"FORBIDDEN");
    }

    @Test void customerReviewerAndSecurityCannotAcquireEachOthersMutationAuthority() throws Exception {
        var fixture=prepared();String quarantineBody=json.write(fixture.quarantine());
        var customer=identity("CUSTOMER");var reviewer=identity("LOAN_REVIEWER");var security=identity("SECURITY_OPERATOR");
        // All identities are in scope and both bodies/targets are valid: only the role is wrong.
        forbidden("SC-T02-B01 customer approval",approvalPath(fixture),customer,fixture.approvalBody());
        forbidden("SC-T02-B02 customer quarantine","/api/v1/quarantines",customer,quarantineBody);
        forbidden("SC-T02-B03 reviewer quarantine","/api/v1/quarantines",reviewer,quarantineBody);
        forbidden("SC-T02-B04 security approval",approvalPath(fixture),security,fixture.approvalBody());
        assertEquals("WAIT_APPROVAL",workflow(fixture.target()).get("state"));
        assertEquals("REJECTED",workflow(fixture.independent()).get("state"));
    }

    @Test void recognizedWorkerIsForbiddenOnEveryPublicMutationPath() throws Exception {
        var fixture=prepared();var worker=identity("FUSE_WORKER");
        // SC-T02-B05: a recognized internal identity, not an invalid bearer, hits all six POST routes.
        forbidden("worker approval",approvalPath(fixture),worker,fixture.approvalBody());
        forbidden("worker quarantine","/api/v1/quarantines",worker,json.write(fixture.quarantine()));
        var start=new StartWorkflowRequest("APP-DEMO-102-001","customer-102",1000000L,
            UUID.fromString("00000000-0000-4000-8000-000000000102"));
        forbidden("worker workflow start","/api/v1/workflows",worker,json.write(start));
        var experiment=new ExperimentRequest("mvp-security-v1",List.of("T02_MISSING_EVIDENCE"),
            ExperimentRequest.Mode.PAIRED,ExperimentRequest.ModelMode.REPLAY,1);
        forbidden("worker experiment","/api/v1/experiments",worker,json.write(experiment));

        // Prepare real, valid release/resume contexts rather than nonexistent UUIDs or invalid states.
        UUID incident=(UUID)quarantines.apply(SECURITY,UUID.randomUUID(),fixture.quarantine()).get("quarantineId");
        assertEquals("ACTIVE",db.required("SELECT * FROM quarantine WHERE id=?",incident).get("status"));
        var evidenceIds=db.jdbc().queryForList("SELECT id FROM trusted_evidence "
            +"WHERE customer_id='customer-102' AND status='ACTIVE' AND outcome='PASS' ORDER BY id",UUID.class);
        assertFalse(evidenceIds.isEmpty());
        var release=new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,evidenceIds,null,null,"Reviewed synthetic evidence"));
        forbidden("worker quarantine release","/api/v1/quarantines/"+incident+"/release",worker,json.write(release));
        quarantines.release(SECURITY,incident,UUID.randomUUID(),release);
        assertEquals("RELEASED",db.required("SELECT * FROM quarantine WHERE id=?",incident).get("status"));
        assertEquals("BLOCKED",workflow(fixture.target()).get("state"));
        forbidden("worker workflow resume","/api/v1/workflows/"+fixture.target()+"/resume",worker,
            json.write(new ResumeRequest(1,"Resume after verified remediation")));
    }

    @Test void internalServiceHeaderAloneDoesNotAuthenticatePublicMutations() throws Exception {
        var fixture=prepared();
        assertNotNull(registry.resolve(serviceToken),"Use the actual configured internal credential");
        assertEquals("KYC_SERVICE",registry.resolve(serviceToken).role());
        denied("SC-T02-B07 service header approval",approvalPath(fixture),null,serviceToken,
            fixture.approvalBody(),401,"UNAUTHENTICATED");
        denied("SC-T02-B07 service header quarantine","/api/v1/quarantines",null,serviceToken,
            json.write(fixture.quarantine()),401,"UNAUTHENTICATED");
    }

    private void rejectAuthorityField(String field,String value,String branch) throws Exception {
        var fixture=prepared();var reviewer=identity("LOAN_REVIEWER");var security=identity("SECURITY_OPERATOR");
        var approval=new LinkedHashMap<>(json.map(fixture.approvalBody()));approval.put(field,value);
        var quarantine=new LinkedHashMap<>(json.map(json.write(fixture.quarantine())));quarantine.put(field,value);
        // Authorized roles are essential: a role403 must not hide a missing strict DTO400 check.
        denied(branch+" approval",approvalPath(fixture),reviewer.token(),null,json.write(approval),400,"INVALID_REQUEST");
        denied(branch+" quarantine","/api/v1/quarantines",security.token(),null,json.write(quarantine),400,"INVALID_REQUEST");
        assertEquals(reviewer.actor(),registry.resolve(reviewer.token()));
        assertEquals(security.actor(),registry.resolve(security.token()));
        // The exact same registered identities and clean bodies remain usable after rejection.
        positiveControls(fixture,reviewer,security);
    }
    @Test void authorizedActorsCannotInjectRoleIntoMutationDtos() throws Exception {
        rejectAuthorityField("role","FUSE_WORKER","SC-T02-B09");
    }
    @Test void authorizedActorsCannotInjectPrincipalIntoMutationDtos() throws Exception {
        rejectAuthorityField("principalId","synthetic-impostor","SC-T02-B10");
    }
    @Test void authorizedActorsCannotInjectApproverIntoMutationDtos() throws Exception {
        rejectAuthorityField("approverId","synthetic-impostor","SC-T02-B11");
    }
    private void positiveControls(Prepared fixture,Identity reviewer,Identity security) throws Exception {
        // Partial SC-T02-B12 only: in-scope approval and quarantine, not the whole allowed-role matrix.
        var independent=independentRows(fixture.independent());
        UUID approvalAction=UUID.randomUUID();
        var response=post(approvalPath(fixture),reviewer.token(),null,approvalAction,fixture.approvalBody());
        assertEquals(201,response.statusCode(),response.body());var approved=json.map(response.body());
        assertEquals("APPROVED",approved.get("state"));assertEquals("ALLOW",approved.get("decision"));
        assertEquals(List.of(),approved.get("reasonCodes"));assertEquals(false,approved.get("replayed"));
        UUID approvalId=UUID.fromString((String)approved.get("approvalId"));
        UUID payJob=UUID.fromString((String)approved.get("payJobId"));
        committed(()->{
            var row=db.required("SELECT * FROM approval WHERE id=?",approvalId);
            assertEquals(fixture.target(),row.get("workflow_id"));assertEquals(reviewer.actor().actorId(),row.get("actor_id"));
            assertEquals("AVAILABLE",row.get("status"));
            assertEquals(json.map(fixture.approvalBody()).get("reviewSnapshotHash"),row.get("review_snapshot_hash"));
            assertEquals("PENDING",db.required("SELECT * FROM workflow_job WHERE id=?",payJob).get("state"));
            assertReceiptActor(approvalAction,reviewer.actor().actorId(),"APPROVAL",approved);
            assertAuditActor(approvalAction,reviewer.actor().actorId(),"LOAN_REVIEWER_APPROVED");
            assertEquals(1,count("approval"));assertEquals(0,count("mock_payment"));return null;
        });
        assertEquals(independent,independentRows(fixture.independent()));

        UUID quarantineAction=UUID.randomUUID();
        var quarantined=post("/api/v1/quarantines",security.token(),null,quarantineAction,json.write(fixture.quarantine()));
        assertEquals(201,quarantined.statusCode(),quarantined.body());var result=json.map(quarantined.body());
        assertEquals("ACTIVE",result.get("state"));assertEquals("ALLOW",result.get("decision"));
        assertEquals(List.of(),result.get("reasonCodes"));assertEquals(false,result.get("replayed"));
        UUID incident=UUID.fromString((String)result.get("quarantineId"));
        committed(()->{
            var row=db.required("SELECT * FROM quarantine WHERE id=?",incident);
            assertEquals(fixture.target(),row.get("workflow_id"));assertEquals(security.actor().actorId(),row.get("actor_id"));
            assertEquals(quarantineAction,row.get("action_id"));assertEquals("ACTIVE",row.get("status"));
            assertReceiptActor(quarantineAction,security.actor().actorId(),"QUARANTINE",result);
            assertAuditActor(quarantineAction,security.actor().actorId(),"QUARANTINE_APPLIED");
            assertEquals("BLOCKED",workflow(fixture.target()).get("state"));
            assertEquals("REVOKED",db.required("SELECT * FROM approval WHERE id=?",approvalId).get("status"));
            assertEquals("FAILED",db.required("SELECT * FROM workflow_job WHERE id=?",payJob).get("state"));
            assertEquals(1,count("quarantine"));assertEquals(0,count("payment_reservation"));assertEquals(0,count("mock_payment"));
            return null;
        });
        assertEquals(independent,independentRows(fixture.independent()),"Authorized target mutation must leave the independent workflow intact");
    }
    private void assertReceiptActor(UUID action,String actor,String type,Map<String,Object> response) {
        var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",action);
        assertEquals(actor,receipt.get("actor_id"));assertEquals(type,receipt.get("action_type"));
        assertEquals("SUCCEEDED",receipt.get("status"));assertEquals(response,json.map(receipt.get("result_json").toString()));
        assertEquals(action.toString(),response.get("requestId"));
    }
    private void assertAuditActor(UUID action,String actor,String event) {
        var events=db.query("SELECT * FROM audit_event WHERE action_id=?",action);
        assertFalse(events.isEmpty());
        for(var row:events) {
            assertEquals(actor,row.get("actor_id"));assertEquals(event,row.get("event_type"));
        }
    }
}
