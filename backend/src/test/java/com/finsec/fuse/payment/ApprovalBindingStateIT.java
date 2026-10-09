package com.finsec.fuse.payment;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.workflow.StartWorkflowRequest;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Authorization faults are security blocks; normal approval expiry remains a reapproval wait. */
class ApprovalBindingStateIT extends PaymentFixture {
    @ParameterizedTest
    @CsvSource({"AMOUNT,false","AMOUNT,true","ACCOUNT,false","ACCOUNT,true","LOAN_HASH,false","LOAN_HASH,true",
        "EVIDENCE_BUNDLE,false","EVIDENCE_BUNDLE,true","REVOKED,false","REVOKED,true","CUSTOMER,false","CUSTOMER,true"})
    void exactApprovalFaultsBlockWithoutAQuarantineOrPayment(String fault,boolean afterReserve) {
        UUID workflowId=ready102();var pay=approve(workflowId);
        if(afterReserve) {payments.reserve(pay.jobId(),pay.token());assertRisk(workflowId,35,50);}
        UUID approvalId=uuid(db.required("select * from workflow_job where id=?",pay.jobId()),"approval_id");
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflowId);
            switch(fault) {
                case "AMOUNT"->db.update("update approval set amount_krw=amount_krw+1 where id=?",approvalId);
                case "ACCOUNT"->db.update("update approval set payout_account_id=? where id=?",UUID.fromString("00000000-0000-4000-8000-000000000103"),approvalId);
                case "LOAN_HASH"->db.update("update approval set loan_result_hash=? where id=?","0".repeat(64),approvalId);
                case "EVIDENCE_BUNDLE"->db.update("update approval set evidence_bundle_hash=? where id=?","0".repeat(64),approvalId);
                case "REVOKED"->db.update("update approval set status='REVOKED' where id=?",approvalId);
                case "CUSTOMER"->db.update("update approval set customer_id='customer-103' where id=?",approvalId);
                default->throw new AssertionError(fault);
            }
        });
        var response=afterReserve?payments.commit(pay.jobId(),pay.token()):payments.reserve(pay.jobId(),pay.token());
        assertEquals("BLOCKED",response.get("state"));assertEquals("DENY",response.get("decision"));
        assertEquals(List.of(fault.equals("CUSTOMER")?"CONTEXT_MISMATCH":"APPROVAL_INVALID"),response.get("reasonCodes"));
        assertEquals("BLOCKED",str(workflow(workflowId),"state"));assertRisk(workflowId,35,0);
        assertEquals(0,count("mock_payment"));assertEquals(0,events("CONSUME"));assertEquals(afterReserve?1:0,events("RELEASE"));assertEquals(0,count("quarantine"));
        assertEquals("FAILED",str(db.required("select * from workflow_job where id=?",pay.jobId()),"state"));
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void ordinaryApprovalExpiryWaitsForANewApprovalWithoutSecurityClassification(boolean afterReserve) {
        UUID workflowId=ready102();var pay=approve(workflowId);if(afterReserve)payments.reserve(pay.jobId(),pay.token());
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflowId);db.update("update approval set expires_at=? where id=(select approval_id from workflow_job where id=?)",clock.now(),pay.jobId());});
        var response=afterReserve?payments.commit(pay.jobId(),pay.token()):payments.reserve(pay.jobId(),pay.token());
        assertEquals("WAIT_APPROVAL",response.get("state"));assertEquals("WAIT_APPROVAL",response.get("decision"));assertEquals(List.of("APPROVAL_REQUIRED"),response.get("reasonCodes"));
        assertRisk(workflowId,35,0);assertEquals(0,count("mock_payment"));assertEquals(0,count("quarantine"));assertEquals(afterReserve?1:0,events("RELEASE"));
    }
    @Test void foreignApprovalCannotPayOrRevokeTheIndependentWorkflow() {
        UUID workflowId=ready102();var pay=approve(workflowId);
        tx.executeWithoutResult(status->{db.gate();db.update("update application_registry set amount_krw=500000 where customer_id='customer-103'");});
        var other=workflows.start(new Actor("customer-103","CUSTOMER",Set.of("customer-103")),UUID.randomUUID(),new StartWorkflowRequest("APP-DEMO-103-001","customer-103",500000L,UUID.fromString("00000000-0000-4000-8000-000000000103")));
        UUID otherWorkflow=(UUID)other.get("workflowId");var prepared=prepareKyc();kyc.apply(prepared,verified(prepared));
        var loan=jobs.claim().orElseThrow();loans.execute(loan.jobId(),loan.token());var otherPay=approve(otherWorkflow);
        UUID foreignApproval=uuid(db.required("select * from workflow_job where id=?",otherPay.jobId()),"approval_id");
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflowId);db.update("update workflow_job set approval_id=? where id=?",foreignApproval,pay.jobId());});
        var denied=payments.reserve(pay.jobId(),pay.token());
        assertEquals("BLOCKED",denied.get("state"));assertEquals(List.of("APPROVAL_INVALID"),denied.get("reasonCodes"));assertRisk(workflowId,35,0);
        assertEquals("APPROVED",str(workflow(otherWorkflow),"state"));assertEquals("AVAILABLE",str(db.required("select * from approval where id=?",foreignApproval),"status"));
        assertEquals(0,count("mock_payment"));assertEquals(0,count("quarantine"));
        assertEquals("PAID",paymentAgent.execute(otherPay.jobId(),otherPay.token()).get("state"));assertRisk(otherWorkflow,85,0);
        assertEquals(0,((Number)db.required("select count(*) n from mock_payment where workflow_id=?",workflowId).get("n")).intValue());
        assertEquals(1,count("mock_payment"));
    }
}
