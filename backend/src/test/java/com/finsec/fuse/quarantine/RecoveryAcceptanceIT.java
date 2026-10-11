package com.finsec.fuse.quarantine;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.payment.*;
import com.finsec.fuse.workflow.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import java.io.IOException;
import java.util.function.Function;

/** Synthetic acceptance inputs; every workflow, approval and payment transaction uses PostgreSQL. */
@Import(RecoveryAcceptanceIT.AcceptanceOverrides.class)
class RecoveryAcceptanceIT extends PaymentFixture {
    @Autowired JobWorker worker;
    @Autowired LeaseReaper reaper;
    @Autowired AcceptanceGateway gateway;
    @Autowired AcceptanceProfiles profiles;

    @BeforeEach void deterministicGateway() {
        profiles.override=null;
        gateway.answer=input -> response(input, KycContract.ProposalStatus.VERIFIED);
    }

    @Test void missingFaceEvidenceCompletesOnlyWithFreshGenerationResultsAndApproval() {
        UUID face=UUID.fromString("00000000-0000-4000-8000-000000001022");
        db.update("update trusted_evidence set status='REVOKED' where id=?",face);
        UUID id=start("customer-102");
        var first=prepareKyc();
        assertEquals(1,first.input().evidenceFacts().size());
        kyc.apply(first,response(first.input(),KycContract.ProposalStatus.NOT_VERIFIED));
        assertEquals("ON_HOLD",str(workflow(id),"state"));
        assertEquals("EVIDENCE_MISSING",str(workflow(id),"last_reason_code"));
        UUID oldResult=uuid(db.required("select id from agent_result where run_id=?",first.input().runId()),"id");
        assertEquals(0,count("quarantine"));assertEquals(0,count("approval"));
        // Restore the previously withheld independent PASS record, not an AI-issued substitute.
        db.update("update trusted_evidence set status='ACTIVE' where id=?",face);
        finishRecovery(id,first.input().runId());
        assertNotEquals(oldResult,uuid(workflow(id),"current_kyc_result_id"));
        assertEquals("PROPOSED",str(db.required("select status from agent_result where id=?",oldResult),"status"));
    }

    @Test void realEvidenceTableOutageRecoversThroughLeaseHoldAndFreshGeneration() {
        UUID id=start("customer-102");
        gateway.answer=input -> {
            // Interrupt the actual SQL evidence lookup after the immutable input was prepared.
            // Other durable workflow tables remain available; no fabricated hold/result is inserted.
            db.jdbc().execute("alter table trusted_evidence rename to acceptance_unavailable_evidence");
            return response(input,KycContract.ProposalStatus.VERIFIED);
        };
        try {
            assertTrue(worker.runOne());
            assertEquals("KYC_PENDING",str(workflow(id),"state"));
            assertEquals(0,count("agent_result"));
        } finally {
            db.jdbc().execute("alter table acceptance_unavailable_evidence rename to trusted_evidence");
        }
        UUID oldRun=kycRun(id);
        var job=db.required("select * from workflow_job where workflow_id=?",id);
        clock.set(instant(job,"lease_until").plusSeconds(1));
        reaper.reap();
        assertEquals("ON_HOLD",str(workflow(id),"state"));
        assertEquals("DEPENDENCY_UNAVAILABLE",str(workflow(id),"last_reason_code"));
        assertEquals("FAILED",str(db.required("select status from agent_run where id=?",oldRun),"status"));
        assertEquals(0,count("quarantine"));assertRisk(id,10,0);
        deterministicGateway();
        finishRecovery(id,oldRun);
    }

    @Test void zeroIncomeIsAnOrdinaryBusinessRejection() {
        var zero=new LinkedHashMap<>(profiles.get("customer-102"));
        zero.put("monthly_income_krw",0L);
        zero.put("profile_hash",json.hash(Json.ordered("customerId","customer-102","monthlyIncomeKrw",0L,"maxLoanAmountKrw",zero.get("max_loan_amount_krw"))));
        // Profiles are immutable startup fixtures: alter this test's provider, not an ignored DB row.
        profiles.override=Map.copyOf(zero);
        UUID id=start("customer-102");
        assertTrue(worker.runOne());assertTrue(worker.runOne());
        assertEquals("REJECTED",str(workflow(id),"state"));
        assertEquals("ALLOW",str(workflow(id),"last_decision"));
        assertEquals("LOAN_NOT_ELIGIBLE",str(workflow(id),"last_reason_code"));
        assertRisk(id,35,0);
        assertEquals(0,count("quarantine"));assertEquals(0,count("approval"));assertEquals(0,count("mock_payment"));
        assertFalse(worker.runOne());
    }

    @Test void sameEmployeeRejectionReplayKeepsOneRejectionAndNoPayment() {
        var request=register("customer-102","ACCEPTANCE-REJECTION",500_000L);
        UUID id=startRequest(request);
        assertTrue(worker.runOne());assertTrue(worker.runOne());
        var preview=approvals.preview(REVIEWER,id);
        var body=new ApprovalRequest(ApprovalRequest.Decision.REJECT,(String)preview.get("reviewSnapshotHash"),"Application declined after review");
        UUID action=UUID.randomUUID();
        var original=approvals.decide(REVIEWER,id,action,body);
        var replay=approvals.decide(REVIEWER,id,action,body);
        assertEquals(original.get("approvalId").toString(),replay.get("approvalId").toString());
        assertEquals(true,replay.get("replayed"));
        assertEquals("REJECTED",str(workflow(id),"state"));assertRisk(id,35,0);
        assertEquals(1,count("approval"));
        assertEquals("REJECTED",str(db.required("select status from approval where workflow_id=?",id),"status"));
        assertEquals(1,scalar("select count(*) n from audit_event where event_type='LOAN_REVIEWER_REJECTED'"));
        assertEquals(0,scalar("select count(*) n from workflow_job where phase='PAY'"));
        assertEquals(0,count("mock_payment"));assertEquals(0,count("quarantine"));assertFalse(worker.runOne());
    }

    @Test void quarantinedNewSourceVersionDoesNotBlockFreshSafeVersionWorkflow() {
        quarantineVersionTwo();
        UUID id=ready102();
        assertEquals(1,scalar("select count(*) n from run_source_use where document_id=? and document_version=1",DOCUMENT));
        assertEquals(0,scalar("select count(*) n from run_source_use where document_version=2"));
        var pay=approve(id);paymentAgent.execute(pay.jobId(),pay.token());
        assertPaid(id,1_000_000L);
        assertEquals(1,count("quarantine"));
    }

    @Test void unrelatedSourceQuarantinePreservesExistingApprovalAndQueuedPayment() {
        UUID id=ready102();var pay=approve(id);
        var approval=db.required("select * from approval where workflow_id=?",id);
        quarantineVersionTwo();
        assertEquals("APPROVED",str(workflow(id),"state"));
        assertEquals("AVAILABLE",str(db.required("select status from approval where id=?",uuid(approval,"id")),"status"));
        clock.advance(Duration.ofSeconds(20));
        paymentAgent.execute(pay.jobId(),pay.token());
        assertPaid(id,1_000_000L);
        assertEquals("CONSUMED",str(db.required("select status from approval where id=?",uuid(approval,"id")),"status"));
        assertEquals(1,count("approval"));assertEquals(1,count("quarantine"));
    }

    @Test void twentyMinuteOldStillValidEvidenceCanAuthorizeFreshWorkflow() {
        clock.advance(Duration.ofMinutes(20));
        UUID id=ready102();var pay=approve(id);paymentAgent.execute(pay.jobId(),pay.token());
        assertPaid(id,1_000_000L);assertEquals(0,count("quarantine"));
    }

    @Test void concurrentDifferentCustomersKeepSeparateEvidenceApprovalsAndPayments() throws Exception {
        runConcurrentPair(register("customer-102","ACCEPTANCE-CUSTOMER-A",1_000_000L),
                register("customer-103","ACCEPTANCE-CUSTOMER-B",300_000L));
    }

    @Test void concurrentApplicationsOfSameCustomerAreNotDeduplicatedTogether() throws Exception {
        runConcurrentPair(register("customer-102","ACCEPTANCE-APPLICATION-A",1_000_000L),
                register("customer-102","ACCEPTANCE-APPLICATION-B",500_000L));
    }

    private void finishRecovery(UUID id,UUID oldRun) {
        assertRisk(id,10,0);
        assertEquals(1,scalar("select run_count n from workflow_stage where workflow_id=? and stage='KYC'",id));
        recovery.resume(REVIEWER,id,UUID.randomUUID(),new ResumeRequest(1,"Independent evidence available again"));
        assertEquals(2,integer(workflow(id),"generation"));assertRisk(id,10,0);
        assertNull(workflow(id).get("current_kyc_result_id"));assertNull(workflow(id).get("current_loan_result_id"));
        assertEquals(1,scalar("select run_count n from workflow_stage where workflow_id=? and stage='KYC'",id));
        assertTrue(worker.runOne());assertTrue(worker.runOne());
        assertNotEquals(oldRun,kycRun(id));assertEquals("WAIT_APPROVAL",str(workflow(id),"state"));
        assertEquals(2,scalar("select run_count n from workflow_stage where workflow_id=? and stage='KYC'",id));
        assertRisk(id,35,0);assertEquals(0,count("approval"));assertEquals(0,count("mock_payment"));
        var pay=approve(id);
        var approval=db.required("select * from approval where workflow_id=?",id);
        assertEquals(2,integer(approval,"generation"));
        assertEquals(uuid(workflow(id),"current_kyc_result_id"),uuid(approval,"kyc_result_id"));
        assertEquals(uuid(workflow(id),"current_loan_result_id"),uuid(approval,"loan_result_id"));
        paymentAgent.execute(pay.jobId(),pay.token());assertPaid(id,1_000_000L);
        assertEquals(2,events("CHARGE"));assertEquals(1,events("CONSUME"));assertEquals(0,count("quarantine"));
    }

    private void quarantineVersionTwo() {
        quarantines.apply(SECURITY,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.SOURCE_VERSION,
                null,null,null,DOCUMENT,2,null,null,QuarantineRequest.Reason.SOURCE_COMPROMISED,"Isolate only the unreviewed revision"));
        assertEquals(1,scalar("select count(*) n from quarantine where scope='SOURCE_VERSION' and document_version=2 and status='ACTIVE'"));
    }

    private KycContract.Response response(KycContract.Input input,KycContract.ProposalStatus status) {
        return new KycContract.Response(input.requestId(),input.workflowId(),input.generation(),input.runId(),input.inputSnapshotHash(),
                new KycContract.Proposal(status,input.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList(),"Synthetic deterministic acceptance response"),
                new KycContract.ModelMetadata("replay","KYC-PROMPT-1"));
    }

    private StartWorkflowRequest register(String customer,String reference,long amount) {
        UUID account=uuid(db.required("select id from mock_account where customer_id=?",customer),"id");
        db.update("insert into application_registry(business_reference,customer_id,amount_krw,payout_account_id,document_id,document_version) values(?,?,?,?,?,1)",reference,customer,amount,account,DOCUMENT);
        return new StartWorkflowRequest(reference,customer,amount,account);
    }

    private UUID startRequest(StartWorkflowRequest request) {
        return (UUID)workflows.start(new Actor(request.customerId(),"CUSTOMER",Set.of(request.customerId())),UUID.randomUUID(),request).get("workflowId");
    }

    private void runConcurrentPair(StartWorkflowRequest first,StartWorkflowRequest second) throws Exception {
        List<UUID> ids=concurrent(()->startRequest(first),()->startRequest(second));
        assertNotEquals(ids.get(0),ids.get(1));
        executePair("KYC");executePair("LOAN");
        for(UUID id:ids)assertEquals("WAIT_APPROVAL",str(workflow(id),"state"));
        concurrent(()->approveWithoutClaim(ids.get(0)),()->approveWithoutClaim(ids.get(1)));
        executePair("PAY");
        assertPaid(ids.get(0),first.amountKrw());assertPaid(ids.get(1),second.amountKrw());
        assertEquals(2,count("approval"));assertEquals(2,count("mock_payment"));assertEquals(0,count("quarantine"));
        assertEquals(0,scalar("select count(*) n from run_evidence_use u join trusted_evidence e on e.id=u.evidence_id join agent_run r on r.id=u.run_id join workflow w on w.id=r.workflow_id join loan_application a on a.id=w.application_id where e.customer_id<>a.customer_id"));
        assertEquals(0,scalar("select count(*) n from approval p join workflow w on w.id=p.workflow_id join loan_application a on a.id=w.application_id where p.customer_id<>a.customer_id or p.amount_krw<>a.amount_krw or p.payout_account_id<>a.payout_account_id or p.kyc_result_id<>w.current_kyc_result_id or p.loan_result_id<>w.current_loan_result_id"));
        assertFalse(worker.runOne());
    }

    private void executePair(String phase) throws Exception {
        var a=jobs.claim().orElseThrow();var b=jobs.claim().orElseThrow();
        assertEquals(phase,a.phase());assertEquals(phase,b.phase());
        assertNotEquals(a.workflowId(),b.workflowId());
        concurrent(()->{worker.execute(a);return true;},()->{worker.execute(b);return true;});
    }

    private Map<String,Object> approveWithoutClaim(UUID id) {
        var preview=approvals.preview(REVIEWER,id);
        return approvals.decide(REVIEWER,id,UUID.randomUUID(),new ApprovalRequest(ApprovalRequest.Decision.APPROVE,(String)preview.get("reviewSnapshotHash"),"Separate application reviewed"));
    }

    private <T> List<T> concurrent(Callable<T> first,Callable<T> second) throws Exception {
        var barrier=new CyclicBarrier(2);
        try(var pool=Executors.newFixedThreadPool(2)) {
            var a=pool.submit(()->{barrier.await(10,TimeUnit.SECONDS);return first.call();});
            var b=pool.submit(()->{barrier.await(10,TimeUnit.SECONDS);return second.call();});
            return List.of(a.get(30,TimeUnit.SECONDS),b.get(30,TimeUnit.SECONDS));
        }
    }

    private void assertPaid(UUID id,long amount) {
        assertEquals("PAID",str(workflow(id),"state"));assertRisk(id,85,0);
        assertEquals(1,scalar("select count(*) n from mock_payment where workflow_id=? and amount_krw=?",id,amount));
        assertEquals(1,scalar("select count(*) n from approval where workflow_id=? and status='CONSUMED'",id));
        assertEquals(85,scalar("select sum(points) n from risk_ledger where workflow_id=? and event_type in ('CHARGE','CONSUME')",id));
    }

    @TestConfiguration(proxyBeanMethods=false)
    static class AcceptanceOverrides {
        @Bean @Primary AcceptanceGateway acceptanceGateway() {return new AcceptanceGateway();}
        @Bean @Primary AcceptanceProfiles acceptanceProfiles(Json json) throws IOException {return new AcceptanceProfiles(json);}
    }

    static class AcceptanceGateway implements KycGateway {
        volatile Function<KycContract.Input,KycContract.Response> answer;
        public KycContract.Response evaluate(KycContract.Input input) {return answer.apply(input);}
    }

    static class AcceptanceProfiles extends LoanProfiles {
        volatile Map<String,Object> override;
        AcceptanceProfiles(Json json) throws IOException {super(json);}
        @Override public Map<String,Object> get(String customer) {
            return override!=null && "customer-102".equals(customer)?override:super.get(customer);
        }
    }

    private long scalar(String sql,Object... args) {return ((Number)db.required(sql,args).get("n")).longValue();}
}
