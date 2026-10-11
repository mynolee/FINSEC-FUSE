package com.finsec.fuse.integration;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.payment.*;
import com.finsec.fuse.testing.FuseIntegrationTest;
import com.finsec.fuse.workflow.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import static org.assertj.core.api.Assertions.*;

class WorkflowHappyPathIT extends FuseIntegrationTest {
    @Autowired WorkflowService workflows;
    @Autowired WorkflowQueryService queries;
    @Autowired JobTransactions jobs;
    @Autowired KycTransactions kyc;
    @Autowired LoanTransactions loans;
    @Autowired ApprovalService approvals;
    @Autowired PaymentAgentService payments;
    private static final Actor REVIEWER=new Actor("staff-01","LOAN_REVIEWER",Set.of("customer-101","customer-102","customer-103","customer-104"));

    private StartWorkflowRequest request(int customer) {
        return new StartWorkflowRequest("APP-DEMO-"+customer+"-001","customer-"+customer,1_000_000L,
                UUID.fromString("00000000-0000-4000-8000-000000000"+customer));
    }
    private Actor customer(int id) {return new Actor("customer-"+id,"CUSTOMER",Set.of("customer-"+id));}
    private UUID start(int id) {
        return (UUID)workflows.start(customer(id),UUID.randomUUID(),request(id)).get("workflowId");
    }
    private void drain(boolean wrongCustomer) {
        for(int i=0;i<12;i++) {
            var claimed=jobs.claim(); if(claimed.isEmpty()) return;
            var lease=claimed.get();
            switch(lease.phase()) {
                case "KYC" -> kyc.prepare(lease.jobId(),lease.token()).ifPresent(prepared->{
                    var input=prepared.input();
                    var ids=input.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList();
                    boolean fail=input.evidenceFacts().stream().anyMatch(f->f.result().equals("FAIL"));
                    if(wrongCustomer && input.customerId().equals("customer-101"))
                        ids=List.of(UUID.fromString("00000000-0000-4000-8000-000000001021"),UUID.fromString("00000000-0000-4000-8000-000000001022"));
                    var proposal=new KycContract.Proposal(fail?KycContract.ProposalStatus.NOT_VERIFIED:KycContract.ProposalStatus.VERIFIED,ids,"Deterministic test replay, not live model evidence");
                    kyc.apply(prepared,new KycContract.Response(input.requestId(),input.workflowId(),input.generation(),input.runId(),input.inputSnapshotHash(),proposal,new KycContract.ModelMetadata("replay","KYC-PROMPT-1")));
                });
                case "LOAN" -> loans.execute(lease.jobId(),lease.token());
                case "PAY" -> payments.execute(lease.jobId(),lease.token());
                default -> throw new AssertionError("Unexpected phase "+lease.phase());
            }
        }
        throw new AssertionError("Jobs did not drain within bounded deterministic steps");
    }
    private Map<String,Object> row(UUID id) {return db.required("select * from workflow where id=?",id);}
    private long count(String table) {return db.number(db.required("select count(*) n from "+table),"n");}
    private Map<String,Object> approve(UUID id,UUID action) {
        var preview=approvals.preview(REVIEWER,id);
        return approvals.decide(REVIEWER,id,action,new ApprovalRequest(ApprovalRequest.Decision.APPROVE,(String)preview.get("reviewSnapshotHash"),"Mock review confirmed"));
    }

    @Test void t01NormalPaymentAndStartApprovalReplay() {
        UUID startAction=UUID.randomUUID(); var body=request(102);
        var created=workflows.start(customer(102),startAction,body);
        UUID id=(UUID)created.get("workflowId");
        var replay=workflows.start(customer(102),startAction,body);
        assertThat(replay.get("workflowId").toString()).isEqualTo(id.toString());
        assertThat(replay.get("replayed")).isEqualTo(true);
        drain(false);
        assertThat(row(id)).containsEntry("state","WAIT_APPROVAL").containsEntry("used_risk",35).containsEntry("reserved_risk",0);
        assertThat(count("mock_payment")).isZero();
        var preview=approvals.preview(REVIEWER,id);
        var approvalBody=new ApprovalRequest(ApprovalRequest.Decision.APPROVE,(String)preview.get("reviewSnapshotHash"),"Mock review confirmed");
        UUID action=UUID.randomUUID(); approvals.decide(REVIEWER,id,action,approvalBody);
        drain(false);
        assertThat(row(id)).containsEntry("state","PAID").containsEntry("used_risk",85).containsEntry("reserved_risk",0);
        assertThat(count("mock_payment")).isEqualTo(1);
        assertThat(count("loan_application")).isEqualTo(1);
        assertThat(approvals.decide(REVIEWER,id,action,approvalBody).get("replayed")).isEqualTo(true);
        assertThat(count("mock_payment")).isEqualTo(1);
        assertThat(db.number(db.required("select sum(points) n from risk_ledger where event_type in ('CHARGE','CONSUME')"),"n")).isEqualTo(85);
        assertThat(db.number(db.required("select count(*) n from audit_event where event_type='PAYMENT_COMMITTED'"),"n")).isEqualTo(1);
    }
    @Test void t02FalseVerifiedStopsBeforeAnyLoan() {
        UUID id=start(101); drain(false);
        assertThat(row(id)).containsEntry("state","BLOCKED").containsEntry("used_risk",10).containsEntry("last_reason_code","EVIDENCE_MISSING");
        assertThat(db.number(db.required("select count(*) n from agent_run where role='LOAN'"),"n")).isZero();
        assertThat(count("mock_payment")).isZero(); assertThat(count("approval")).isZero();
        assertThat(db.required("select scope,status from quarantine")).containsEntry("scope","RUN").containsEntry("status","ACTIVE");
    }
    @Test void t03OtherCustomerEvidenceCannotAuthorizeAndNormalCustomerStillWorks() {
        UUID attack=start(101),normal=start(102); drain(true);
        assertThat(row(attack)).containsEntry("state","BLOCKED").containsEntry("last_reason_code","EVIDENCE_INVALID");
        assertThat(row(normal)).containsEntry("state","WAIT_APPROVAL");
        approve(normal,UUID.randomUUID());drain(false);
        assertThat(row(normal)).containsEntry("state","PAID");assertThat(count("mock_payment")).isEqualTo(1);
    }
    @Test void t04RoleAndCustomerScopeNeverComeFromRequestBody() {
        assertThatThrownBy(()->workflows.start(customer(101),UUID.randomUUID(),request(102)))
                .isInstanceOfSatisfying(ApiException.class,e->assertThat(e.status()).isEqualTo(403));
        UUID id=start(102); drain(false);
        var fake=new Actor("kyc-service","KYC_SERVICE",Set.of("customer-102"));
        assertThatThrownBy(()->approvals.preview(fake,id)).isInstanceOfSatisfying(ApiException.class,e->assertThat(e.status()).isEqualTo(403));
        assertThat(count("approval")).isZero();assertThat(count("mock_payment")).isZero();
        assertThat(row(id)).containsEntry("state","WAIT_APPROVAL");
    }
    @Test void t05BudgetWaitIsNotAttackQuarantine() {
        UUID id=start(102);drain(false);
        assertThat(row(id)).containsEntry("state","WAIT_APPROVAL").containsEntry("used_risk",35).containsEntry("reserved_risk",0);
        assertThat(count("quarantine")).isZero();assertThat(count("mock_payment")).isZero();
        assertThat(jobs.claim()).isEmpty();
    }
    @Test void t06SelectiveIsolationPreservesIndependentWorkflow() {
        UUID attack=start(101),normal=start(102); drain(false);approve(normal,UUID.randomUUID());drain(false);
        assertThat(row(attack)).containsEntry("state","BLOCKED");assertThat(row(normal)).containsEntry("state","PAID");
        assertThat(db.number(db.required("select count(*) n from mock_payment where workflow_id=?",attack),"n")).isZero();
        assertThat(db.number(db.required("select count(*) n from mock_payment where workflow_id=?",normal),"n")).isEqualTo(1);
    }
    @Test void t11BusinessRejectionsAreNotAttackBlocks() {
        UUID overLimit=start(103),faceFail=start(104);drain(false);
        assertThat(row(overLimit)).containsEntry("state","REJECTED");
        assertThat(row(faceFail)).containsEntry("state","REJECTED").containsEntry("used_risk",10);
        assertThat(count("quarantine")).isZero();assertThat(count("mock_payment")).isZero();
    }
}
