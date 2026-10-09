package com.finsec.fuse.workflow;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.quarantine.QuarantineService;
import com.finsec.fuse.quarantine.RecoveryService;
import com.finsec.fuse.quarantine.ResumeRequest;
import com.finsec.fuse.quarantine.QuarantineRequest;
import java.util.concurrent.*;
import com.finsec.fuse.testing.FuseIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real PostgreSQL 16.15 lease and delayed-completion checks. No timing sleeps. */
class JobLifecycleIT extends FuseIntegrationTest {
    @Autowired WorkflowService workflows;
    @Autowired JobTransactions jobs;
    @Autowired KycTransactions kyc;
    @Autowired LoanTransactions loan;
    @Autowired QuarantineService quarantine;
    @Autowired LeaseReaper reaper;
    @Autowired RecoveryService recovery;
    @Autowired WorkflowQueryService queries;
    private UUID start(String customer) {
        String suffix=customer.substring(customer.length()-3);
        var response=workflows.start(new Actor(customer,"CUSTOMER",Set.of(customer)),UUID.randomUUID(),
                new StartWorkflowRequest("APP-DEMO-"+suffix+"-001",customer,1_000_000L,UUID.fromString("00000000-0000-4000-8000-000000000"+suffix)));
        return UUID.fromString(response.get("workflowId").toString());
    }
    private KycContract.Prepared prepare() {
        var lease=jobs.claim().orElseThrow();return kyc.prepare(lease.jobId(),lease.token()).orElseThrow();
    }
    private KycContract.Response passing(KycContract.Prepared prepared) {
        var in=prepared.input();
        return new KycContract.Response(in.requestId(),in.workflowId(),in.generation(),in.runId(),in.inputSnapshotHash(),
                new KycContract.Proposal(KycContract.ProposalStatus.VERIFIED,in.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList(),"Independent fixture evidence"),
                new KycContract.ModelMetadata("replay","KYC-PROMPT-1"));
    }
    private long count(String sql,Object...args){return ((Number)db.required(sql,args).get("n")).longValue();}

    @Test void t09QuarantineBeforeCompletionPreventsLatePromotion() {
        UUID workflowId=start("customer-102");var prepared=prepare();
        tx.executeWithoutResult(s->quarantine.automaticRun(prepared.input().runId(),"SCOPE_EXCEEDED","Controlled test quarantine"));
        kyc.apply(prepared,passing(prepared));
        assertEquals("BLOCKED",db.required("SELECT state FROM workflow WHERE id=?",workflowId).get("state"));
        assertEquals(0,count("SELECT count(*) AS n FROM agent_result WHERE workflow_id=? AND status='VALIDATED'",workflowId));
        assertEquals(0,count("SELECT count(*) AS n FROM agent_run WHERE workflow_id=? AND role='LOAN'",workflowId));
        assertEquals(0,count("SELECT count(*) AS n FROM mock_payment WHERE workflow_id=?",workflowId));
        assertEquals(1,count("SELECT count(*) AS n FROM audit_event WHERE workflow_id=? AND event_type='LATE_RESULT_DISCARDED'",workflowId));
    }
    @Test void t12ExpiredKycIsHeldWithoutBlindAiRetryAndLateAnswerIsIgnored() {
        UUID workflowId=start("customer-102");var prepared=prepare();
        clock.set(Instant.parse("2026-10-09T04:01:30Z"));reaper.reap();
        var w=db.required("SELECT * FROM workflow WHERE id=?",workflowId);
        assertEquals("ON_HOLD",w.get("state"));assertEquals(10,((Number)w.get("used_risk")).intValue());
        assertEquals("FAILED",db.required("SELECT state FROM workflow_job WHERE id=?",prepared.jobId()).get("state"));
        assertTrue(jobs.claim().isEmpty());
        kyc.apply(prepared,passing(prepared));
        assertEquals(0,count("SELECT count(*) AS n FROM agent_result WHERE workflow_id=?",workflowId));
        assertEquals(1,count("SELECT count(*) AS n FROM agent_run WHERE workflow_id=?",workflowId));
        assertEquals(1,count("SELECT count(*) AS n FROM risk_ledger WHERE workflow_id=? AND event_type='CHARGE'",workflowId));
    }
    @Test void duplicateCompletionDoesNotCreateAnotherRunOrCharge() {
        UUID workflowId=start("customer-102");var prepared=prepare();var response=passing(prepared);
        kyc.apply(prepared,response);kyc.apply(prepared,response);
        assertEquals(1,count("SELECT count(*) AS n FROM agent_result WHERE workflow_id=?",workflowId));
        assertEquals(1,count("SELECT count(*) AS n FROM workflow_job WHERE workflow_id=? AND phase='LOAN'",workflowId));
        assertEquals(1,count("SELECT count(*) AS n FROM risk_ledger WHERE workflow_id=?",workflowId));
        var lease=jobs.claim().orElseThrow();loan.execute(lease.jobId(),lease.token());
        assertEquals("WAIT_APPROVAL",db.required("SELECT state FROM workflow WHERE id=?",workflowId).get("state"));
        assertEquals(35,((Number)db.required("SELECT used_risk FROM workflow WHERE id=?",workflowId).get("used_risk")).intValue());
    }
    @Test void wrongResponseBindingHoldsWithoutSecurityAttackMetric() {
        UUID workflowId=start("customer-102");var prepared=prepare();var good=passing(prepared);
        var wrong=new KycContract.Response(good.requestId(),good.workflowId(),good.generation(),UUID.randomUUID(),good.inputSnapshotHash(),good.proposal(),good.modelMetadata());
        kyc.apply(prepared,wrong);
        assertEquals("ON_HOLD",db.required("SELECT state FROM workflow WHERE id=?",workflowId).get("state"));
        assertEquals(0,count("SELECT count(*) AS n FROM quarantine"));
        assertEquals(0,count("SELECT count(*) AS n FROM agent_result WHERE workflow_id=?",workflowId));
    }

    @Test void onlyOneWorkerClaimsAnActiveJobUnderConcurrentPolling() throws Exception {
        UUID workflowId=start("customer-102");var ready=new CountDownLatch(2);var start=new CountDownLatch(1);
        try(var executor=Executors.newFixedThreadPool(2)) {
            Callable<Optional<JobTransactions.Lease>> claim=()->{ready.countDown();if(!start.await(5,TimeUnit.SECONDS))throw new AssertionError("barrier timed out");return jobs.claim();};
            var first=executor.submit(claim);var second=executor.submit(claim);assertTrue(ready.await(5,TimeUnit.SECONDS));start.countDown();
            long claimed=java.util.stream.Stream.of(first.get(10,TimeUnit.SECONDS),second.get(10,TimeUnit.SECONDS)).filter(Optional::isPresent).count();
            assertEquals(1,claimed);
        }
        assertEquals(1,count("SELECT count(*) AS n FROM workflow_job WHERE workflow_id=? AND state='RUNNING'",workflowId));
        assertEquals(1,count("SELECT count(*) AS n FROM audit_event WHERE workflow_id=? AND event_type='JOB_CLAIMED'",workflowId));
    }
    @Test void t11RecoveryRetainsStageCostAndRejectsThirdAutomaticKyc() {
        UUID workflowId=start("customer-102");var first=prepare();
        var reviewer=new Actor("staff-01","LOAN_REVIEWER",Set.of("customer-102"));
        clock.set(Instant.parse("2026-10-09T04:01:30Z"));reaper.reap();
        recovery.resume(reviewer,workflowId,UUID.randomUUID(),new ResumeRequest(1,"Dependency recovered"));
        var second=prepare();assertEquals(2,second.input().generation());
        assertEquals(10,((Number)db.required("SELECT used_risk FROM workflow WHERE id=?",workflowId).get("used_risk")).intValue());
        kyc.apply(first,passing(first)); // Prior-generation response cannot finish the current job.
        assertEquals("RUNNING",db.required("SELECT state FROM workflow_job WHERE id=?",second.jobId()).get("state"));
        clock.set(Instant.parse("2026-10-09T04:03:00Z"));reaper.reap();
        var stopped=recovery.resume(reviewer,workflowId,UUID.randomUUID(),new ResumeRequest(2,"Try again"));
        assertEquals("ON_HOLD",stopped.get("state"));assertTrue(jobs.claim().isEmpty());
        assertEquals(2,count("SELECT count(*) AS n FROM agent_run WHERE workflow_id=? AND role='KYC'",workflowId));
        assertEquals(1,count("SELECT count(*) AS n FROM risk_ledger WHERE workflow_id=? AND event_type='CHARGE'",workflowId));
        assertEquals("MANUAL_REVIEW_REQUIRED",db.required("SELECT last_reason_code FROM workflow WHERE id=?",workflowId).get("last_reason_code"));
    }

    private UUID quarantineAgent(String role) {
        var security=new Actor("security-01","SECURITY_OPERATOR",Set.of("customer-101","customer-102","customer-103","customer-104"));
        var response=quarantine.apply(security,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.AGENT_VERSION,null,null,null,null,null,
                role,1,QuarantineRequest.Reason.AGENT_COMPROMISED,"Controlled pre-execution hold"));
        return UUID.fromString(response.get("quarantineId").toString());
    }
    @Test void quarantinedKycVersionCreatesHoldWithoutFakeRunOrCharge() {
        UUID incidentId=quarantineAgent("KYC"),workflowId=start("customer-102");
        var lease=jobs.claim().orElseThrow();assertTrue(kyc.prepare(lease.jobId(),lease.token()).isEmpty());
        assertEquals("BLOCKED",db.required("SELECT state FROM workflow WHERE id=?",workflowId).get("state"));
        assertEquals(0,count("SELECT count(*) AS n FROM agent_run WHERE workflow_id=?",workflowId));
        assertEquals(0,count("SELECT count(*) AS n FROM risk_ledger WHERE workflow_id=?",workflowId));
        assertEquals(1,count("SELECT count(*) AS n FROM quarantine_workflow_hold WHERE workflow_id=? AND quarantine_id=?",workflowId,incidentId));
        var detail=queries.detail(new Actor("staff-01","LOAN_REVIEWER",Set.of("customer-102")),workflowId);
        assertEquals(1,((List<?>)detail.get("activeQuarantines")).size());assertEquals(false,detail.get("canResume"));
    }
    @Test void quarantinedLoanVersionCreatesHoldWithoutFakeLoanDependency() {
        UUID workflowId=start("customer-102");var prepared=prepare();kyc.apply(prepared,passing(prepared));
        UUID incidentId=quarantineAgent("LOAN");var lease=jobs.claim().orElseThrow();loan.execute(lease.jobId(),lease.token());
        assertEquals("BLOCKED",db.required("SELECT state FROM workflow WHERE id=?",workflowId).get("state"));
        assertEquals(0,count("SELECT count(*) AS n FROM agent_run WHERE workflow_id=? AND role='LOAN'",workflowId));
        assertEquals(0,count("SELECT count(*) AS n FROM run_dependency WHERE workflow_id=?",workflowId));
        assertEquals(1,count("SELECT count(*) AS n FROM quarantine_workflow_hold WHERE workflow_id=? AND quarantine_id=?",workflowId,incidentId));
        assertEquals(10,((Number)db.required("SELECT used_risk FROM workflow WHERE id=?",workflowId).get("used_risk")).intValue());
    }
}
