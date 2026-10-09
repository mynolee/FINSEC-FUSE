package com.finsec.fuse.integration;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.DevActorRegistry;
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

/** SC-T23-B07: actual Spring MVC parsing/authentication and committed PostgreSQL state. */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
class PublicBodyReplayIT extends PaymentFixture {
    private static final String VALID_BODY="""
        {"businessReference":"APP-DEMO-102-001","customerId":"customer-102",
         "amountKrw":1000000,"payoutAccountId":"00000000-0000-4000-8000-000000000102"}
        """.strip();
    // Include composite-key tables, gate/registries, evidence, grants, reservations and incidents,
    // not just the workflow and receipt counts. Row JSON keeps bytea/JSON/timestamps comparable.
    private static final List<String> TABLES=List.of(
        "execution_gate","agent_registry","mock_account","mock_profile","application_registry",
        "source_document_version","trusted_evidence","loan_application","workflow","workflow_stage",
        "agent_run","agent_result","run_source_use","run_evidence_use","run_dependency","action_request",
        "approval","workflow_job","delegation_grant","payment_reservation","risk_ledger","mock_payment",
        "quarantine","quarantine_workflow_hold","audit_event","experiment","experiment_case_result",
        "experiment_arm_binding");
    @Value("${local.server.port}") int port;
    @Autowired DevActorRegistry registry;
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    private HttpResponse<String> post(String token,UUID action,String body) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/api/v1/workflows"))
            .timeout(Duration.ofSeconds(10)).header("Authorization","Bearer "+token)
            .header("Idempotency-Key",action.toString()).header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
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
            for(String table:TABLES)
                rows.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM "+table+" t ORDER BY to_jsonb(t)::text",String.class));
            return rows;
        });
    }
    private void error(HttpResponse<String> response,UUID action,int status,String reason) {
        assertEquals(status,response.statusCode(),response.body());
        var body=json.map(response.body());
        assertEquals(action.toString(),body.get("requestId"));
        assertEquals(List.of(reason),body.get("reasonCodes"));
        assertEquals("DENY",body.get("decision")); // HTTP error envelope, not a saved policy DENY.
        assertNull(body.get("workflowId"));assertNull(body.get("generation"));assertNull(body.get("state"));
        assertEquals(false,body.get("replayed"));
    }
    private void rejectedBodyCanBeCorrectedAndReplayed(String rejectedBody) throws Exception {
        String actorId="body-"+UUID.randomUUID(),token=DevActorRegistry.generateToken();
        registry.register(token,new Actor(actorId,"CUSTOMER",Set.of("customer-102")));
        UUID action=UUID.randomUUID();
        var before=snapshot();
        assertTrue(before.get("action_request").isEmpty());
        error(post(token,action,rejectedBody),action,400,"INVALID_REQUEST");
        assertEquals(before,snapshot(),"Parser rejection must leave every durable row unchanged, including DENY receipts");

        var accepted=post(token,action,VALID_BODY);
        assertEquals(202,accepted.statusCode(),accepted.body());
        var result=json.map(accepted.body());
        assertEquals(action.toString(),result.get("requestId"));
        UUID workflowId=UUID.fromString((String)result.get("workflowId"));
        assertEquals("KYC_PENDING",result.get("state"));assertEquals("ALLOW",result.get("decision"));
        assertEquals(1,((Number)result.get("generation")).intValue());
        assertEquals(List.of(),result.get("reasonCodes"));assertEquals(false,result.get("replayed"));
        var after=snapshot();
        var expectedCounts=Map.of("loan_application",1,"workflow",1,"workflow_stage",3,
            "workflow_job",1,"audit_event",1,"action_request",1);
        for(String table:TABLES) {
            if(expectedCounts.containsKey(table)) {
                assertTrue(before.get(table).isEmpty(),table+" must start empty");
                assertEquals(expectedCounts.get(table).intValue(),after.get(table).size(),table);
            } else assertEquals(before.get(table),after.get(table),table+" must not change on workflow admission");
        }
        committed(()->{
            var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",action);
            assertEquals(actorId,receipt.get("actor_id"));assertEquals("START_WORKFLOW",receipt.get("action_type"));
            assertEquals("SUCCEEDED",receipt.get("status"));assertEquals("ALLOW",receipt.get("decision"));
            assertEquals(result,json.map(receipt.get("result_json").toString()));
            assertNotNull(receipt.get("completed_at"));
            var workflow=db.required("SELECT * FROM workflow WHERE id=?",workflowId);
            assertEquals(actorId,workflow.get("principal_id"));assertEquals("KYC_PENDING",workflow.get("state"));
            var application=db.required("SELECT * FROM loan_application WHERE id=?",workflow.get("application_id"));
            assertEquals("APP-DEMO-102-001",application.get("business_reference"));
            assertEquals("customer-102",application.get("customer_id"));
            assertEquals(1000000L,((Number)application.get("amount_krw")).longValue());
            assertEquals(UUID.fromString("00000000-0000-4000-8000-000000000102"),application.get("payout_account_id"));
            var job=db.required("SELECT * FROM workflow_job WHERE workflow_id=?",workflowId);
            assertEquals("PENDING",job.get("state"));assertEquals("KYC",job.get("phase"));
            var audit=db.required("SELECT * FROM audit_event WHERE action_id=?",action);
            assertEquals("WORKFLOW_CREATED",audit.get("event_type"));assertEquals(workflowId,audit.get("workflow_id"));
            return null;
        });

        var replay=post(token,action,VALID_BODY);
        assertEquals(202,replay.statusCode(),replay.body());
        var replayResult=json.map(replay.body());
        var expectedReplay=new LinkedHashMap<>(result);expectedReplay.put("replayed",true);
        assertEquals(expectedReplay,replayResult);
        assertEquals(after,snapshot(),"Exact replay must add or alter no durable rows");

        // Still well-formed, in-range input: the consumed action key must reject a new fingerprint.
        error(post(token,action,VALID_BODY.replace("1000000","1000001")),action,409,"REPLAY_CONFLICT");
        assertEquals(after,snapshot(),"Changed-body conflict must preserve the original successful receipt and all business rows");
        var replayAfterConflict=post(token,action,VALID_BODY);
        assertEquals(202,replayAfterConflict.statusCode());
        assertEquals(expectedReplay,json.map(replayAfterConflict.body()));
        assertEquals(after,snapshot(),"A conflict must not poison later exact replay");
    }
    @Test void malformedJsonLeavesNoReceiptAndCorrectedSameActionSucceedsExactlyOnce() throws Exception {
        rejectedBodyCanBeCorrectedAndReplayed(VALID_BODY.substring(0,VALID_BODY.length()-1));
    }
    @Test void unknownFieldLeavesNoReceiptAndCorrectedSameActionSucceedsExactlyOnce() throws Exception {
        rejectedBodyCanBeCorrectedAndReplayed(VALID_BODY.substring(0,VALID_BODY.length()-1)+",\"role\":\"SECURITY_OPERATOR\"}");
    }
}
