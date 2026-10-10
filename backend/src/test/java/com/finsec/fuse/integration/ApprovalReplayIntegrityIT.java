package com.finsec.fuse.integration;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.payment.ApprovalRequest;
import com.finsec.fuse.payment.PaymentFixture;
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

/** SC-T23-B03/B04: real HTTP approval replay with a committed, all-table PostgreSQL oracle. */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApprovalReplayIntegrityIT extends PaymentFixture {
    private static final String COMMENT="Reviewed mock application / approved";
    @Value("${local.server.port}") int port;
    @Autowired DevActorRegistry registry;
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private record Original(String token,String actorId,UUID workflow,UUID action,String hash,
                            String body,Map<String,Object> response,Map<String,List<String>> rows) {}

    @Override protected UUID start(String customer) {
        String suffix=customer.substring(customer.length()-3);
        return (UUID)workflows.start(new Actor("approval-start-"+UUID.randomUUID(),"CUSTOMER",Set.of(customer)),
            UUID.randomUUID(),new StartWorkflowRequest("APP-DEMO-"+suffix+"-001",customer,1000000L,
                UUID.fromString("00000000-0000-4000-8000-000000000"+suffix))).get("workflowId");
    }
    private HttpResponse<String> post(String token,UUID workflow,UUID action,String body) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port
                +"/api/v1/workflows/"+workflow+"/approvals"))
            .timeout(Duration.ofSeconds(10)).header("Authorization","Bearer "+token)
            .header("Idempotency-Key",action.toString()).header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
    }
    private String body(ApprovalRequest.Decision decision,String hash,String comment) {
        return json.write(new ApprovalRequest(decision,hash,comment));
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
            assertTrue(tables.containsAll(List.of("action_request","approval","workflow","workflow_job",
                "delegation_grant","payment_reservation","mock_payment","risk_ledger","audit_event")));
            for(String table:tables) {
                String quoted="\""+table.replace("\"","\"\"")+"\"";
                rows.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM public."+quoted
                    +" t ORDER BY to_jsonb(t)::text",String.class));
            }
            return rows;
        });
    }
    private Original approveOriginal(UUID workflow) throws Exception {
        String actorId="approval-replay-"+UUID.randomUUID(),token=DevActorRegistry.generateToken();
        var actor=new Actor(actorId,"LOAN_REVIEWER",Set.of("customer-102","customer-103"));
        registry.register(token,actor);
        String hash=(String)approvals.preview(actor,workflow).get("reviewSnapshotHash");
        String body=body(ApprovalRequest.Decision.APPROVE,hash,COMMENT);UUID action=UUID.randomUUID();
        var response=post(token,workflow,action,body);
        assertEquals(201,response.statusCode(),response.body());
        var result=json.map(response.body());
        assertEquals(action.toString(),result.get("requestId"));assertEquals(workflow.toString(),result.get("workflowId"));
        assertEquals(1,((Number)result.get("generation")).intValue());
        assertEquals("APPROVED",result.get("state"));assertEquals("ALLOW",result.get("decision"));
        assertEquals(List.of(),result.get("reasonCodes"));assertEquals(false,result.get("replayed"));
        assertNotNull(result.get("approvalId"));assertNotNull(result.get("payJobId"));
        committed(()->{
            var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",action);
            assertEquals(actorId,receipt.get("actor_id"));assertEquals("APPROVAL",receipt.get("action_type"));
            assertEquals(workflow,receipt.get("workflow_id"));assertEquals("SUCCEEDED",receipt.get("status"));
            assertEquals("ALLOW",receipt.get("decision"));assertNotNull(receipt.get("completed_at"));
            assertEquals(result,json.map(receipt.get("result_json").toString()));
            var approval=db.required("SELECT * FROM approval WHERE id=?",UUID.fromString((String)result.get("approvalId")));
            assertEquals(workflow,approval.get("workflow_id"));assertEquals(actorId,approval.get("actor_id"));
            assertEquals("AVAILABLE",approval.get("status"));assertEquals(hash,approval.get("review_snapshot_hash"));
            assertEquals(COMMENT,approval.get("comment"));assertEquals(1,count("approval"));
            var job=db.required("SELECT * FROM workflow_job WHERE id=?",UUID.fromString((String)result.get("payJobId")));
            assertEquals(workflow,job.get("workflow_id"));assertEquals("PAY",job.get("phase"));assertEquals("PENDING",job.get("state"));
            assertEquals(1,db.jdbc().queryForObject("SELECT count(*) FROM workflow_job WHERE phase='PAY'",Integer.class));
            assertEquals("APPROVED",workflow(workflow).get("state"));
            assertEquals(0,count("mock_payment"));assertEquals(0,count("payment_reservation"));
            return null;
        });
        return new Original(token,actorId,workflow,action,hash,body,result,snapshot());
    }
    private void replay(Original original,String body) throws Exception {
        var response=post(original.token(),original.workflow(),original.action(),body);
        assertEquals(201,response.statusCode(),response.body());
        var expected=new LinkedHashMap<>(original.response());expected.put("replayed",true);
        assertEquals(expected,json.map(response.body()),"Replay must return the complete original receipt");
        assertEquals(original.rows(),snapshot(),"Replay must not mutate any durable row, including timestamps and receipts");
    }
    private void conflict(Original original,UUID target,String body) throws Exception {
        var response=post(original.token(),target,original.action(),body);
        assertEquals(409,response.statusCode(),response.body());
        var error=json.map(response.body());
        assertEquals(original.action().toString(),error.get("requestId"));
        assertEquals("DENY",error.get("decision"));assertEquals(List.of("REPLAY_CONFLICT"),error.get("reasonCodes"));
        assertEquals(false,error.get("replayed"));assertNull(error.get("workflowId"));
        assertNull(error.get("generation"));assertNull(error.get("state"));
        assertEquals(original.rows(),snapshot(),"Conflict must not revoke/replace approval, enqueue PAY, or change any durable row");
        replay(original,original.body());
    }

    @Test void parsedEquivalentJsonReplaysOriginalReceiptWithoutAnyDurableMutation() throws Exception {
        var original=approveOriginal(ready102());
        replay(original,original.body());
        replay(original,"{\"comment\":"+json.write(COMMENT)+",\"reviewSnapshotHash\":\""+original.hash()+"\",\"decision\":\"APPROVE\"}");
        replay(original," { \n \"decision\" : \"APPROVE\" , \"reviewSnapshotHash\" : \""+original.hash()
            +"\" , \"comment\" : "+json.write(COMMENT)+" \n } \t");
        // JSON string escapes change wire bytes but not the parsed comment value.
        String escaped=original.body().replace("Reviewed","\\u0052eviewed").replace(" / "," \\/ ");
        assertNotEquals(original.body(),escaped);assertEquals(json.map(original.body()),json.map(escaped));
        replay(original,escaped);
    }
    @Test void changedDecisionHashAndCommentConflictWithoutPoisoningOriginalReceipt() throws Exception {
        var original=approveOriginal(ready102());
        conflict(original,original.workflow(),body(ApprovalRequest.Decision.REJECT,original.hash(),COMMENT));
        String changedHash=(original.hash().charAt(0)=='0'?"1":"0")+original.hash().substring(1);
        assertTrue(changedHash.matches("[0-9a-f]{64}"));assertNotEquals(original.hash(),changedHash);
        conflict(original,original.workflow(),body(ApprovalRequest.Decision.APPROVE,changedHash,COMMENT));
        conflict(original,original.workflow(),body(ApprovalRequest.Decision.APPROVE,original.hash(),"Different mock review"));
        // The contract preserves comment values; whitespace inside the value is meaningful.
        conflict(original,original.workflow(),body(ApprovalRequest.Decision.APPROVE,original.hash(),COMMENT+" "));
    }
    @Test void otherAccessibleWorkflowCannotReuseApprovalActionOrAlterEitherWorkflow() throws Exception {
        UUID workflow=ready102(),other=start("customer-103");
        var original=approveOriginal(workflow);
        assertNotEquals(workflow,other);assertEquals("KYC_PENDING",workflow(other).get("state"));
        // Reviewer is scoped to both customers, so this reaches target-bound replay validation.
        conflict(original,other,original.body());
    }
}
