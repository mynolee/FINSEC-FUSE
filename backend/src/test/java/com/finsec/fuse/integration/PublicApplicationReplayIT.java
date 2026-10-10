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

/** Application identity and action identity are separate public HTTP admission boundaries. */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
class PublicApplicationReplayIT extends PaymentFixture {
    private static final UUID ACCOUNT_102=UUID.fromString("00000000-0000-4000-8000-000000000102");
    private static final UUID ALTERNATE_102=UUID.fromString("00000000-0000-4000-8000-000000009102");
    @Value("${local.server.port}") int port;
    @Autowired DevActorRegistry registry;
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    private String token(String role,Set<String> customers) {
        String token=DevActorRegistry.generateToken();
        registry.register(token,new Actor("application-replay-"+UUID.randomUUID(),role,customers));
        return token;
    }
    private String body(String reference,String customer,long amount,UUID account) {
        return json.write(Map.of("businessReference",reference,"customerId",customer,
            "amountKrw",amount,"payoutAccountId",account));
    }
    private String originalBody() {
        return body("APP-DEMO-102-001","customer-102",1000000L,ACCOUNT_102);
    }
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
            // Discover all base tables, including future tables and Flyway history. Full row JSON
            // catches changes to timestamps, receipts, audit/risk ledgers and composite-key rows.
            var tables=db.jdbc().queryForList("SELECT table_name FROM information_schema.tables "
                +"WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name",String.class);
            assertTrue(tables.containsAll(List.of("application_registry","action_request","workflow",
                "workflow_job","risk_ledger","mock_payment")));
            for(String table:tables) {
                String quoted="\""+table.replace("\"","\"\"")+"\"";
                rows.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM public."+quoted
                    +" t ORDER BY to_jsonb(t)::text",String.class));
            }
            return rows;
        });
    }
    private Map<String,Object> accepted(HttpResponse<String> response,UUID action) {
        assertEquals(202,response.statusCode(),response.body());
        var result=json.map(response.body());
        assertEquals(action.toString(),result.get("requestId"));
        assertNotNull(result.get("workflowId"));
        assertEquals(1,((Number)result.get("generation")).intValue());
        assertEquals("KYC_PENDING",result.get("state"));assertEquals("ALLOW",result.get("decision"));
        assertEquals(List.of(),result.get("reasonCodes"));assertEquals(false,result.get("replayed"));
        return result;
    }
    private void rejected(HttpResponse<String> response,UUID action,int status,String reason) {
        assertEquals(status,response.statusCode(),response.body());
        var result=json.map(response.body());
        assertEquals(action.toString(),result.get("requestId"));
        assertEquals(List.of(reason),result.get("reasonCodes"));assertEquals("DENY",result.get("decision"));
        assertNull(result.get("workflowId"));assertNull(result.get("generation"));assertNull(result.get("state"));
        assertEquals(false,result.get("replayed"));
    }
    private void exactReplay(String token,UUID action,Map<String,Object> original,
                             Map<String,List<String>> expectedRows) throws Exception {
        var response=post(token,action,originalBody());
        assertEquals(202,response.statusCode(),response.body());
        var expected=new LinkedHashMap<>(original);expected.put("replayed",true);
        assertEquals(expected,json.map(response.body()));
        assertEquals(expectedRows,snapshot(),"Exact replay must preserve every durable row and the original receipt");
    }
    private void independentApplication(String token,String originalWorkflow) throws Exception {
        var before=snapshot();UUID action=UUID.randomUUID();
        var result=accepted(post(token,action,body("APP-DEMO-103-001","customer-103",1000000L,
            UUID.fromString("00000000-0000-4000-8000-000000000103"))),action);
        assertNotEquals(originalWorkflow,result.get("workflowId"));
        var after=snapshot();
        var additions=Map.of("loan_application",1,"workflow",1,"workflow_stage",3,
            "workflow_job",1,"audit_event",1,"action_request",1);
        assertEquals(before.keySet(),after.keySet());
        for(String table:before.keySet()) {
            assertEquals(before.get(table).size()+additions.getOrDefault(table,0),after.get(table).size(),table);
            assertTrue(after.get(table).containsAll(before.get(table)),table+" must retain existing rows");
            if(!additions.containsKey(table))assertEquals(before.get(table),after.get(table),table);
        }
        committed(()->{
            var row=db.required("SELECT a.* FROM loan_application a JOIN workflow w ON w.application_id=a.id WHERE w.id=?",
                UUID.fromString((String)result.get("workflowId")));
            assertEquals("APP-DEMO-103-001",row.get("business_reference"));
            assertEquals("customer-103",row.get("customer_id"));
            return null;
        });
    }
    private void registryConflict(String changedBody) throws Exception {
        // Both requested customers are explicitly in the authenticated principal's scope.
        String token=token("LOAN_REVIEWER",Set.of("customer-102","customer-103"));
        UUID originalAction=UUID.randomUUID();
        var original=accepted(post(token,originalAction,originalBody()),originalAction);
        var before=snapshot();UUID freshAction=UUID.randomUUID();
        rejected(post(token,freshAction,changedBody),freshAction,409,"APPLICATION_CONFLICT");
        assertEquals(before,snapshot(),"Registry conflict must leave every durable row unchanged, without a DENY receipt");
        // The identical changed body under the consumed key hits the receipt boundary first.
        rejected(post(token,originalAction,changedBody),originalAction,409,"REPLAY_CONFLICT");
        assertEquals(before,snapshot(),"Changed-body replay must not overwrite or append rows");
        exactReplay(token,originalAction,original,before);
        independentApplication(token,(String)original.get("workflowId"));
        exactReplay(token,originalAction,original,snapshot());
    }

    @Test void changedAmountWithFreshActionConflictsWithRegisteredApplication() throws Exception {
        registryConflict(body("APP-DEMO-102-001","customer-102",1000001L,ACCOUNT_102));
    }
    @Test void changedActiveCustomerOwnedPayoutAccountConflictsWithRegisteredApplication() throws Exception {
        tx.executeWithoutResult(status->{
            db.gate();
            db.update("INSERT INTO mock_account(id,customer_id,status) VALUES(?,'customer-102','ACTIVE')",ALTERNATE_102);
        });
        registryConflict(body("APP-DEMO-102-001","customer-102",1000000L,ALTERNATE_102));
    }
    @Test void authorizedCustomerMismatchReachesApplicationRegistryValidation() throws Exception {
        registryConflict(body("APP-DEMO-102-001","customer-103",1000000L,
            UUID.fromString("00000000-0000-4000-8000-000000000103")));
    }
    @Test void customerOutsidePrincipalScopeIsForbiddenBeforeRegistryValidation() throws Exception {
        String token=token("CUSTOMER",Set.of("customer-102"));UUID originalAction=UUID.randomUUID();
        var original=accepted(post(token,originalAction,originalBody()),originalAction);
        var before=snapshot();UUID freshAction=UUID.randomUUID();
        rejected(post(token,freshAction,body("APP-DEMO-102-001","customer-103",1000000L,
            UUID.fromString("00000000-0000-4000-8000-000000000103"))),freshAction,403,"FORBIDDEN");
        assertEquals(before,snapshot(),"Scope rejection must occur without recording a receipt or mutating business state");
        exactReplay(token,originalAction,original,before);
    }
    @Test void matchingTermsWithFreshActionReuseApplicationAndWorkflowAndOnlyAppendReceipt() throws Exception {
        String token=token("LOAN_REVIEWER",Set.of("customer-102","customer-103"));
        UUID originalAction=UUID.randomUUID();
        var original=accepted(post(token,originalAction,originalBody()),originalAction);
        var before=snapshot();UUID freshAction=UUID.randomUUID();
        var duplicate=accepted(post(token,freshAction,originalBody()),freshAction);
        var expected=new LinkedHashMap<>(original);expected.put("requestId",freshAction.toString());
        assertEquals(expected,duplicate,"Fresh action refers to the existing workflow, but has its own receipt");
        var after=snapshot();assertEquals(before.keySet(),after.keySet());
        for(String table:before.keySet()) {
            if(table.equals("action_request")) {
                assertEquals(before.get(table).size()+1,after.get(table).size());
                assertTrue(after.get(table).containsAll(before.get(table)),"Original receipt must remain byte-for-byte unchanged");
            } else assertEquals(before.get(table),after.get(table),table+" must not change for identical registered terms");
        }
        committed(()->{
            assertEquals(1,count("loan_application"));assertEquals(1,count("workflow"));
            assertEquals(1,count("workflow_job"));assertEquals(0,count("risk_ledger"));
            assertEquals(0,count("payment_reservation"));assertEquals(0,count("mock_payment"));
            var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",freshAction);
            assertEquals("START_WORKFLOW",receipt.get("action_type"));assertEquals("SUCCEEDED",receipt.get("status"));
            assertEquals("ALLOW",receipt.get("decision"));assertNotNull(receipt.get("completed_at"));
            assertEquals(duplicate,json.map(receipt.get("result_json").toString()));
            return null;
        });
        exactReplay(token,originalAction,original,after);
        exactReplay(token,freshAction,duplicate,after);
        rejected(post(token,originalAction,body("APP-DEMO-102-001","customer-102",1000001L,ACCOUNT_102)),
            originalAction,409,"REPLAY_CONFLICT");
        assertEquals(after,snapshot());
        exactReplay(token,originalAction,original,after);
        independentApplication(token,(String)original.get("workflowId"));
        var afterIndependent=snapshot();
        exactReplay(token,originalAction,original,afterIndependent);
        exactReplay(token,freshAction,duplicate,afterIndependent);
    }
}
