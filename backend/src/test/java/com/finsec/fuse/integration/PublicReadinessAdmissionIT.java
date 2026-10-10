package com.finsec.fuse.integration;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.config.FuseReadinessHealthIndicator;
import com.finsec.fuse.payment.PaymentAgentService;
import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.workflow.*;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Readiness failure must close fresh execution admission, while durable receipts remain readable. */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
class PublicReadinessAdmissionIT extends PaymentFixture {
    @Value("${local.server.port}") int port;
    @Autowired DevActorRegistry actors;
    @Autowired FuseReadinessHealthIndicator readiness;
    @Autowired FusePolicy policy;
    @Autowired TransactionRetries retries;
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    private String token() {
        String token=DevActorRegistry.generateToken();
        actors.register(token,new Actor("readiness-"+UUID.randomUUID(),"LOAN_REVIEWER",
            Set.of("customer-102","customer-103")));
        return token;
    }
    private String startBody(String suffix) {
        return json.write(Map.of("businessReference","APP-DEMO-"+suffix+"-001","customerId","customer-"+suffix,
            "amountKrw",1000000,"payoutAccountId","00000000-0000-4000-8000-000000000"+suffix));
    }
    private HttpResponse<String> post(String token,String path,UUID action,String body) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/api/v1/workflows"+path))
            .timeout(Duration.ofSeconds(10)).header("Authorization","Bearer "+token)
            .header("Idempotency-Key",action.toString()).header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
    }
    private void health(boolean up) throws Exception {
        var response=client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/actuator/health/readiness"))
            .timeout(Duration.ofSeconds(10)).GET().build(),HttpResponse.BodyHandlers.ofString());
        assertEquals(up?200:503,response.statusCode(),response.body());
        assertEquals(up?"UP":"DOWN",json.map(response.body()).get("status"));
    }
    private <T> T committed(Supplier<T> observation) {
        var fresh=new TransactionTemplate(Objects.requireNonNull(tx.getTransactionManager()));
        fresh.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        fresh.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);fresh.setReadOnly(true);
        return fresh.execute(status->observation.get());
    }
    private Map<String,List<String>> snapshot() {
        return committed(()->{
            var result=new LinkedHashMap<String,List<String>>();
            var tables=db.jdbc().queryForList("SELECT table_name FROM information_schema.tables "
                +"WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name",String.class);
            assertTrue(tables.containsAll(List.of("workflow_job","delegation_grant","risk_ledger","mock_payment","action_request")));
            for(String table:tables) {
                String quoted="\""+table.replace("\"","\"\"")+"\"";
                result.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM public."+quoted
                    +" t ORDER BY to_jsonb(t)::text",String.class));
            }
            return result;
        });
    }
    private Map<String,Object> disable(String agent,boolean missing) {
        return tx.execute(status->{
            db.gate();var original=db.required("SELECT * FROM agent_registry WHERE agent_id=? AND version=1",agent);
            assertEquals(1,db.update(missing?"DELETE FROM agent_registry WHERE agent_id=? AND version=1":
                "UPDATE agent_registry SET status='REVOKED' WHERE agent_id=? AND version=1",agent));
            return original;
        });
    }
    private void restore(Map<String,Object> original) {
        tx.executeWithoutResult(status->{
            db.gate();db.update("INSERT INTO agent_registry(agent_id,version,role,auth_subject,status) VALUES(?,?,?,?,?) "
                +"ON CONFLICT(agent_id,version) DO UPDATE SET status=EXCLUDED.status",
                original.get("agent_id"),original.get("version"),original.get("role"),original.get("auth_subject"),original.get("status"));
        });
    }
    private void unavailable(HttpResponse<String> response,UUID action) {
        assertEquals(503,response.statusCode(),response.body());var body=json.map(response.body());
        assertEquals(action.toString(),body.get("requestId"));assertEquals("ERROR",body.get("decision"));
        assertEquals(List.of("DEPENDENCY_UNAVAILABLE"),body.get("reasonCodes"));
        assertNull(body.get("workflowId"));assertNull(body.get("generation"));assertNull(body.get("state"));
        assertEquals(false,body.get("replayed"));
    }
    private Map<String,Object> accepted(HttpResponse<String> response,int status) {
        assertEquals(status,response.statusCode(),response.body());var body=json.map(response.body());
        assertEquals("ALLOW",body.get("decision"));assertEquals(false,body.get("replayed"));return body;
    }
    private void replay(String token,String path,UUID action,String body,Map<String,Object> original,int status) throws Exception {
        var before=snapshot();var response=post(token,path,action,body);
        assertEquals(status,response.statusCode(),response.body());
        var expected=new LinkedHashMap<>(original);expected.put("replayed",true);
        assertEquals(expected,json.map(response.body()));assertEquals(before,snapshot());
    }
    private void workerMustNotClaim(UUID queuedWorkflow) {
        // The application scheduler is disabled. Exercise an explicitly ENABLED worker, with
        // real transactional claims and no possible network/model/payment execution.
        var kycExecution=mock(KycTransactions.class);var gateway=mock(KycGateway.class);
        var loanExecution=mock(LoanTransactions.class);var payExecution=mock(PaymentAgentService.class);
        var before=snapshot();
        var worker=new JobWorker(jobs,kycExecution,gateway,loanExecution,payExecution,retries,db,policy,readiness,true);
        try {worker.poll();} finally {worker.stop();}
        assertEquals(before,snapshot(),"Enabled worker must not claim or mutate any queued job while unready");
        verifyNoInteractions(kycExecution,gateway,loanExecution,payExecution);
        committed(()->{
            var job=db.required("SELECT * FROM workflow_job WHERE workflow_id=? AND state='PENDING'",queuedWorkflow);
            assertNull(job.get("lease_token"));assertNull(job.get("lease_until"));return null;
        });
    }

    @ParameterizedTest
    @CsvSource({"FUSE,true","KYC,true","LOAN,true","PAYMENT,true",
        "FUSE,false","KYC,false","LOAN,false","PAYMENT,false"})
    void everyMissingOrDeactivatedRequiredAgentClosesStartAndWorker(String agent,boolean missing) throws Exception {
        String token=token();UUID priorAction=UUID.randomUUID();String priorBody=startBody("103");
        var prior=accepted(post(token,"",priorAction,priorBody),202);
        UUID queued=UUID.fromString((String)prior.get("workflowId"));
        var original=disable(agent,missing);health(false);var before=snapshot();
        UUID action=UUID.randomUUID();String body=startBody("102");
        unavailable(post(token,"",action,body),action);
        assertEquals(before,snapshot(),"Rejected start must not create a workflow, receipt, grant, charge, payment, or audit row");
        workerMustNotClaim(queued);
        replay(token,"",priorAction,priorBody,prior,202);
        var conflict=post(token,"",priorAction,body);
        assertEquals(409,conflict.statusCode(),conflict.body());
        assertEquals(List.of("REPLAY_CONFLICT"),json.map(conflict.body()).get("reasonCodes"));
        assertEquals(before,snapshot());
        restore(original);health(true);
        var restored=accepted(post(token,"",action,body),202);
        assertNotEquals(prior.get("workflowId"),restored.get("workflowId"));
        assertEquals("KYC_PENDING",restored.get("state"));
        replay(token,"",action,body,restored,202);
    }

    @ParameterizedTest @ValueSource(strings={"FUSE","KYC","LOAN","PAYMENT"})
    void resumeRejectsUnreadyAdmissionWithoutConsumingActionOrGeneration(String agent) throws Exception {
        UUID workflow=start("customer-102");
        var lease=jobs.claim().orElseThrow();jobs.fail(lease.jobId(),lease.token(),"DEPENDENCY_UNAVAILABLE");
        UUID independent=start("customer-103");String token=token();UUID action=UUID.randomUUID();
        String path="/"+workflow+"/resume",body=json.write(Map.of("expectedGeneration",1,"reason","Dependency repaired"));
        var original=disable(agent,false);health(false);var before=snapshot();
        unavailable(post(token,path,action,body),action);assertEquals(before,snapshot());workerMustNotClaim(independent);
        restore(original);health(true);var restored=accepted(post(token,path,action,body),202);
        assertEquals(2,((Number)restored.get("generation")).intValue());assertEquals("KYC_PENDING",restored.get("state"));
        disable(agent,false);replay(token,path,action,body,restored,202);
    }

    @ParameterizedTest @ValueSource(strings={"FUSE","KYC","LOAN","PAYMENT"})
    void approvalRejectsUnreadyExecutionWithoutConsumingReviewOrAction(String agent) throws Exception {
        UUID workflow=ready102(),independent=start("customer-103");
        var preview=approvals.preview(REVIEWER,workflow);String token=token();UUID action=UUID.randomUUID();
        String path="/"+workflow+"/approvals",body=json.write(Map.of("decision","APPROVE",
            "reviewSnapshotHash",preview.get("reviewSnapshotHash"),"comment","Reviewed mock request"));
        var original=disable(agent,false);health(false);var before=snapshot();
        unavailable(post(token,path,action,body),action);assertEquals(before,snapshot());workerMustNotClaim(independent);
        restore(original);health(true);var restored=accepted(post(token,path,action,body),201);
        assertEquals("APPROVED",restored.get("state"));assertNotNull(restored.get("payJobId"));
        disable(agent,false);replay(token,path,action,body,restored,201);
    }

    @Test void readinessDoesNotBlockReviewerRejection() throws Exception {
        UUID workflow=ready102();var preview=approvals.preview(REVIEWER,workflow);
        disable("FUSE",false);health(false);
        String token=token();UUID action=UUID.randomUUID();String path="/"+workflow+"/approvals";
        String body=json.write(Map.of("decision","REJECT","reviewSnapshotHash",preview.get("reviewSnapshotHash"),"comment","Declined mock request"));
        var result=accepted(post(token,path,action,body),201);assertEquals("REJECTED",result.get("state"));
        committed(()->{assertEquals(0,db.query("SELECT id FROM workflow_job WHERE phase='PAY'").size());
            assertEquals(0,count("mock_payment"));return null;});
        replay(token,path,action,body,result,201);
    }
}
