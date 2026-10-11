package com.finsec.fuse.payment;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.config.FuseReadinessHealthIndicator;
import com.finsec.fuse.quarantine.QuarantineRequest;
import com.finsec.fuse.quarantine.ResumeRequest;
import com.finsec.fuse.workflow.JobTransactions;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** Real PostgreSQL transactions; loss of registry availability happens after the PAY claim. */
class PaymentAgentAvailabilityIT extends PaymentFixture {
    @Autowired FuseReadinessHealthIndicator readiness;

    @Test void missingPaymentAgentAfterClaimIsOperationalHold() {
        assertAvailabilityFailure(true);
    }

    @Test void deactivatedPaymentAgentAfterClaimIsOperationalHold() {
        assertAvailabilityFailure(false);
    }

    @Test void restoredPaymentRegistryRequiresExplicitResumeAndFreshApproval() {
        var attempt=claimedPayment();var original=disablePayment(true);
        try {
            var before=snapshot();
            assertOperationalHold(attempt,paymentAgent.execute(attempt.lease().jobId(),attempt.lease().token()),before);
            UUID resumeAction=UUID.randomUUID();var request=new ResumeRequest(1,"Payment registry restored");
            var held=snapshot();
            // Current service scope still precedes replay/readiness; this is not a token-auth test.
            var outside=new Actor(REVIEWER.actorId(),REVIEWER.role(),Set.of("customer-101"));
            var denied=assertThrows(ApiException.class,()->recovery.resume(outside,attempt.workflowId(),resumeAction,request));
            assertEquals(403,denied.status());assertEquals("FORBIDDEN",denied.reasonCode());assertEquals(held,snapshot());
            var unavailable=assertThrows(ApiException.class,()->recovery.resume(REVIEWER,attempt.workflowId(),resumeAction,request));
            assertEquals(503,unavailable.status());assertEquals("DEPENDENCY_UNAVAILABLE",unavailable.reasonCode());
            assertEquals(held,snapshot());

            restorePayment(original);
            assertUnchangedExcept(held,snapshot(),Set.of("agent_registry"));
            assertEquals("ON_HOLD",str(workflow(attempt.workflowId()),"state"));assertRisk(attempt.workflowId(),35,0);
            assertEquals(0,count("mock_payment"));assertEquals(0,count("quarantine"));
            var resumed=recovery.resume(REVIEWER,attempt.workflowId(),resumeAction,request);
            assertEquals("KYC_PENDING",resumed.get("state"));assertEquals(2,resumed.get("generation"));
            assertRisk(attempt.workflowId(),35,0);assertStageCounts(attempt.workflowId(),1,1,0);
            assertNull(workflow(attempt.workflowId()).get("current_kyc_result_id"));
            assertNull(workflow(attempt.workflowId()).get("current_loan_result_id"));
            assertEquals(1,scalar("select count(*) n from workflow_job where workflow_id=? and state='PENDING' and phase='KYC' and generation=2",attempt.workflowId()));
            assertEquals("REVOKED",row("approval","id",attempt.approvalId()).get("status"));
            var afterResume=snapshot();
            var expectedReplay=normalized(resumed);expectedReplay.put("replayed",true);
            assertEquals(expectedReplay,normalized(recovery.resume(REVIEWER,attempt.workflowId(),resumeAction,request)));
            assertEquals(afterResume,snapshot());

            var late=paymentAgent.execute(attempt.lease().jobId(),attempt.lease().token());
            assertEquals("DENY",late.get("decision"));assertEquals(List.of("STALE_LEASE"),late.get("reasonCodes"));
            assertUnchangedExcept(afterResume,snapshot(),Set.of("audit_event"));
            assertEquals("FAILED",row("workflow_job","id",attempt.lease().jobId()).get("state"));
            assertEquals("REVOKED",row("approval","id",attempt.approvalId()).get("status"));

            var freshKyc=prepareKyc();assertEquals(2,freshKyc.input().generation());
            assertEquals(DOCUMENT,freshKyc.input().documents().getFirst().documentId());
            assertEquals(1,freshKyc.input().documents().getFirst().documentVersion());
            kyc.apply(freshKyc,verified(freshKyc));
            var freshLoan=jobs.claim().orElseThrow();assertEquals("LOAN",freshLoan.phase());
            loans.execute(freshLoan.jobId(),freshLoan.token());
            assertEquals("WAIT_APPROVAL",str(workflow(attempt.workflowId()),"state"));
            assertRisk(attempt.workflowId(),35,0);assertStageCounts(attempt.workflowId(),2,2,0);
            assertEquals(2,events("CHARGE"));assertEquals(0,count("mock_payment"));
            assertEquals(1,count("approval"));

            var freshPay=approve(attempt.workflowId());
            var freshJob=row("workflow_job","id",freshPay.jobId());
            assertNotEquals(attempt.lease().jobId(),freshPay.jobId());
            assertNotEquals(attempt.actionId().toString(),freshJob.get("execution_action_id"));
            UUID freshApproval=UUID.fromString(freshJob.get("approval_id").toString());
            assertNotEquals(attempt.approvalId(),freshApproval);
            var approved=row("approval","id",freshApproval);assertEquals(2,approved.get("generation"));
            assertEquals(uuid(workflow(attempt.workflowId()),"current_kyc_result_id").toString(),approved.get("kyc_result_id"));
            assertEquals(uuid(workflow(attempt.workflowId()),"current_loan_result_id").toString(),approved.get("loan_result_id"));
            assertEquals("PAID",paymentAgent.execute(freshPay.jobId(),freshPay.token()).get("state"));
            assertRisk(attempt.workflowId(),85,0);assertStageCounts(attempt.workflowId(),2,2,1);
            assertEquals(1,count("mock_payment"));assertEquals(1,events("RESERVE"));assertEquals(1,events("CONSUME"));
            assertEquals(0,events("RELEASE"));assertEquals(2,events("CHARGE"));
            assertEquals("REVOKED",row("approval","id",attempt.approvalId()).get("status"));
            assertEquals("CONSUMED",row("approval","id",freshApproval).get("status"));
            assertEquals("FAILED",row("workflow_job","id",attempt.lease().jobId()).get("state"));
            assertEquals(0,count("quarantine"));assertEquals(0,count("quarantine_workflow_hold"));
        } finally {restorePayment(original);}
    }

    @Test void activePaymentAgentQuarantineStillRecordsPolicyHold() {
        assertQuarantineStillBlocks(false);
    }

    @Test void quarantinedAndDeactivatedPaymentAgentStillRecordsPolicyHold() {
        assertQuarantineStillBlocks(true);
    }

    @Test void unavailablePinnedPaymentReplacementNeverFallsBack() {
        var attempt=claimedPayment();
        tx.executeWithoutResult(status->{
            db.gate();db.lockWorkflow(attempt.workflowId());
            // Defensive persisted-binding fixture, not an approved release to this unreviewed v2.
            // The recovery FK requires keeping the pinned row; ordinary reviewed v1 remains ACTIVE.
            db.update("insert into agent_registry(agent_id,version,role,auth_subject,status) values('PAYMENT',2,'PAYMENT','unavailable-payment-fixture','REVOKED')");
            db.update("update workflow set recovery_agent_id='PAYMENT',recovery_agent_version=2 where id=?",attempt.workflowId());
        });
        assertEquals("ACTIVE",row("agent_registry","version",1,"agent_id='PAYMENT'").get("status"));
        var before=snapshot();
        assertOperationalHold(attempt,paymentAgent.execute(attempt.lease().jobId(),attempt.lease().token()),before);
        assertEquals("PAYMENT",workflow(attempt.workflowId()).get("recovery_agent_id"));
        assertEquals(2,integer(workflow(attempt.workflowId()),"recovery_agent_version"));
        assertEquals("ACTIVE",row("agent_registry","version",1,"agent_id='PAYMENT'").get("status"));
    }

    @Test void healthyPaymentAndHistoricalReplayRemainUnchanged() {
        var attempt=claimedPayment();
        var receipt=paymentAgent.execute(attempt.lease().jobId(),attempt.lease().token());
        assertEquals("PAID",receipt.get("state"));assertRisk(attempt.workflowId(),85,0);
        assertEquals(1,count("mock_payment"));assertEquals(1,events("RESERVE"));assertEquals(1,events("CONSUME"));
        assertEquals(0,events("RELEASE"));assertEquals(0,count("quarantine"));assertStageCounts(attempt.workflowId(),1,1,1);
        var original=disablePayment(false);
        try {
            var before=snapshot();var expected=normalized(receipt);expected.put("replayed",true);
            assertEquals(expected,normalized(paymentAgent.execute(attempt.lease().jobId(),attempt.lease().token())));
            assertEquals(before,snapshot(),"Historical receipt lookup must precede current registry availability checks");
        } finally {restorePayment(original);}
    }

    private void assertAvailabilityFailure(boolean missing) {
        var attempt=claimedPayment();var original=disablePayment(missing);
        try {
            var before=snapshot();
            assertOperationalHold(attempt,paymentAgent.execute(attempt.lease().jobId(),attempt.lease().token()),before);
        } finally {restorePayment(original);}
    }

    private Attempt claimedPayment() {
        UUID workflowId=ready102();var lease=approve(workflowId);
        var job=db.required("select * from workflow_job where id=?",lease.jobId());
        assertEquals("APPROVED",str(workflow(workflowId),"state"));assertEquals("RUNNING",str(job,"state"));
        assertTrue(clock.now().isBefore(instant(job,"lease_until")));assertNull(job.get("run_id"));
        assertRisk(workflowId,35,0);assertStageCounts(workflowId,1,1,0);assertNoPaymentArtifacts();
        assertEquals(org.springframework.boot.health.contributor.Status.UP,readiness.health().getStatus());
        return new Attempt(workflowId,lease,uuid(job,"approval_id"),uuid(job,"execution_action_id"));
    }

    private Map<String,Object> disablePayment(boolean missing) {
        return tx.execute(status->{
            db.gate();var original=db.required("select * from agent_registry where agent_id='PAYMENT' and version=1");
            assertEquals(1,db.update(missing?"delete from agent_registry where agent_id='PAYMENT' and version=1":
                "update agent_registry set status='REVOKED' where agent_id='PAYMENT' and version=1"));
            return original;
        });
    }

    private void restorePayment(Map<String,Object> original) {
        tx.executeWithoutResult(status->{
            db.gate();db.update("insert into agent_registry(agent_id,version,role,auth_subject,status) values(?,?,?,?,?) "+
                "on conflict(agent_id,version) do update set status=EXCLUDED.status",
                original.get("agent_id"),original.get("version"),original.get("role"),original.get("auth_subject"),original.get("status"));
        });
    }

    private void assertOperationalHold(Attempt attempt,Map<String,Object> response,Map<String,List<String>> before) {
        assertEquals("ON_HOLD",response.get("state"));assertEquals("ERROR",response.get("decision"));
        assertEquals(List.of("DEPENDENCY_UNAVAILABLE"),response.get("reasonCodes"));
        assertEquals(attempt.actionId(),response.get("requestId"));assertEquals(false,response.get("replayed"));
        assertStopped(attempt,"ON_HOLD","ERROR","DEPENDENCY_UNAVAILABLE");
        assertUnchangedExcept(before,snapshot(),Set.of("workflow","workflow_job","approval","audit_event"));
        assertChangedColumnsOnly(before,"workflow",attempt.workflowId(),Set.of("state","last_decision","last_reason_code","reason_codes","updated_at"));
        assertChangedColumnsOnly(before,"workflow_job",attempt.lease().jobId(),Set.of("state","last_error","completed_at"));
        assertChangedColumnsOnly(before,"approval",attempt.approvalId(),Set.of("status"));
        assertEquals(before.get("audit_event").size()+1,snapshot().get("audit_event").size());
        var errors=db.query("select * from audit_event where action_id=? and event_type='SYSTEM_ERROR'",attempt.actionId());
        assertEquals(1,errors.size());var error=errors.getFirst();
        assertEquals(attempt.workflowId(),uuid(error,"workflow_id"));assertNull(error.get("run_id"));assertNull(error.get("quarantine_id"));
        assertEquals("fuse-worker",str(error,"actor_id"));assertEquals("DEPENDENCY_UNAVAILABLE",str(error,"reason_code"));
        assertEquals(Map.of("jobId",attempt.lease().jobId().toString()),json.map(str(error,"details_json")));
        assertEquals(0,scalar("select count(*) n from audit_event where action_id=? and event_type in ('POLICY_DENIED','APPROVAL_WAITING')",attempt.actionId()));
        assertEquals(0,count("quarantine"));assertEquals(0,count("quarantine_workflow_hold"));
    }

    private void assertQuarantineStillBlocks(boolean deactivate) {
        var attempt=claimedPayment();
        var incident=quarantines.apply(SECURITY,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.AGENT_VERSION,
            null,null,null,null,null,"PAYMENT",1,QuarantineRequest.Reason.AGENT_COMPROMISED,"Investigate selected payment agent"));
        UUID incidentId=(UUID)incident.get("quarantineId");
        assertEquals("APPROVED",str(workflow(attempt.workflowId()),"state"));
        assertEquals(0,count("quarantine_workflow_hold"));
        Map<String,Object> original=deactivate?disablePayment(false):null;
        try {
            var before=snapshot();var response=paymentAgent.execute(attempt.lease().jobId(),attempt.lease().token());
            assertEquals("BLOCKED",response.get("state"));assertEquals("DENY",response.get("decision"));
            assertEquals(List.of("QUARANTINED"),response.get("reasonCodes"));
            assertStopped(attempt,"BLOCKED","DENY","QUARANTINED");
            assertUnchangedExcept(before,snapshot(),Set.of("workflow","workflow_job","approval","audit_event","quarantine_workflow_hold"));
            var holds=db.query("select * from quarantine_workflow_hold where workflow_id=?",attempt.workflowId());
            assertEquals(1,holds.size());assertEquals(incidentId,uuid(holds.getFirst(),"quarantine_id"));
            assertEquals(1,integer(holds.getFirst(),"generation"));assertEquals(1,count("quarantine"));
            assertEquals("ACTIVE",row("quarantine","id",incidentId).get("status"));
            assertEquals(1,scalar("select count(*) n from audit_event where action_id=? and event_type='POLICY_DENIED' and reason_code='QUARANTINED'",attempt.actionId()));
            assertEquals(0,scalar("select count(*) n from audit_event where action_id=? and event_type='SYSTEM_ERROR'",attempt.actionId()));
            if(original!=null)restorePayment(original);
            var blocked=snapshot();
            var denied=assertThrows(ApiException.class,()->recovery.resume(REVIEWER,attempt.workflowId(),UUID.randomUUID(),new ResumeRequest(1,"Incident still active")));
            assertEquals("QUARANTINED",denied.reasonCode());assertEquals(blocked,snapshot());
        } finally {if(original!=null)restorePayment(original);}
    }

    private void assertStopped(Attempt attempt,String state,String decision,String reason) {
        committed(()->{
            var workflow=workflow(attempt.workflowId());assertEquals(state,str(workflow,"state"));
            assertEquals(decision,str(workflow,"last_decision"));assertEquals(reason,str(workflow,"last_reason_code"));
            assertEquals(1,integer(workflow,"generation"));assertRisk(attempt.workflowId(),35,0);assertStageCounts(attempt.workflowId(),1,1,0);
            var job=db.required("select * from workflow_job where id=?",attempt.lease().jobId());
            assertEquals("FAILED",str(job,"state"));assertEquals(reason,str(job,"last_error"));assertNotNull(job.get("completed_at"));
            assertEquals(attempt.actionId(),uuid(job,"execution_action_id"));assertNull(job.get("run_id"));
            assertEquals(0,scalar("select count(*) n from workflow_job where workflow_id=? and state in ('PENDING','RUNNING')",attempt.workflowId()));
            assertEquals("REVOKED",row("approval","id",attempt.approvalId()).get("status"));
            assertNoPaymentArtifacts();assertEquals(2,events("CHARGE"));
            assertEquals(0,scalar("select count(*) n from action_request where action_id=?",attempt.actionId()));
            return null;
        });
    }

    private void assertNoPaymentArtifacts() {
        assertEquals(0,scalar("select count(*) n from agent_run where role='PAYMENT'"));
        assertEquals(0,scalar("select count(*) n from delegation_grant where target_agent='PAYMENT'"));
        assertEquals(0,count("payment_reservation"));assertEquals(0,count("mock_payment"));
        assertEquals(0,events("RESERVE"));assertEquals(0,events("RELEASE"));assertEquals(0,events("CONSUME"));
    }

    private void assertStageCounts(UUID workflowId,int kyc,int loan,int payment) {
        for(var expected:Map.of("KYC",kyc,"LOAN",loan,"PAYMENT",payment).entrySet())
            assertEquals(expected.getValue().longValue(),scalar("select run_count n from workflow_stage where workflow_id=? and stage=?",workflowId,expected.getKey()));
    }

    private long scalar(String sql,Object... args) {return ((Number)db.required(sql,args).get("n")).longValue();}
    private Map<String,Object> normalized(Map<String,Object> value) {return json.map(json.write(value));}
    private Map<String,Object> row(String table,String key,Object value) {return row(table,key,value,"true");}
    private Map<String,Object> row(String table,String key,Object value,String extra) {
        return json.map(str(db.required("select to_jsonb(t)::text as body from "+table+" t where "+key+"=? and "+extra,value),"body"));
    }

    private <T> T committed(Supplier<T> observation) {
        var read=new TransactionTemplate(Objects.requireNonNull(tx.getTransactionManager()));
        read.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        read.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);read.setReadOnly(true);
        return read.execute(status->observation.get());
    }

    private Map<String,List<String>> snapshot() {
        return committed(()->{
            var result=new LinkedHashMap<String,List<String>>();
            for(String table:db.jdbc().queryForList("select table_name from information_schema.tables where table_schema='public' and table_type='BASE TABLE' order by table_name",String.class)) {
                String quoted="\""+table.replace("\"","\"\"")+"\"";
                result.put(table,db.jdbc().queryForList("select to_jsonb(t)::text from public."+quoted+" t order by to_jsonb(t)::text",String.class));
            }
            return result;
        });
    }

    private void assertUnchangedExcept(Map<String,List<String>> before,Map<String,List<String>> after,Set<String> allowed) {
        assertEquals(before.keySet(),after.keySet());
        for(String table:before.keySet())if(!allowed.contains(table))assertEquals(before.get(table),after.get(table),table);
    }

    private void assertChangedColumnsOnly(Map<String,List<String>> before,String table,UUID id,Set<String> allowed) {
        var original=before.get(table).stream().map(json::map).filter(value->id.toString().equals(value.get("id"))).findFirst().orElseThrow();
        var current=row(table,"id",id);
        for(String key:allowed){original.remove(key);current.remove(key);}
        assertEquals(original,current,table);
    }

    private record Attempt(UUID workflowId,JobTransactions.Lease lease,UUID approvalId,UUID actionId) {}
}
