package com.finsec.fuse.quarantine;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.payment.PaymentFixture;
import java.util.*;
import org.junit.jupiter.api.Test;

class RecoveryGenerationIT extends PaymentFixture {
    @Test void releaseNeverResurrectsResultsAndResumeRetainsCostWithNewGeneration() {
        UUID workflowId=start("customer-101");var old=prepareKyc();kyc.apply(old,verified(old));
        assertEquals("BLOCKED",str(workflow(workflowId),"state"));assertRisk(workflowId,10,0);
        UUID incident=uuid(db.required("select * from quarantine where run_id=?",old.input().runId()),"id");
        var evidenceIds=issueEvidence101();
        quarantines.release(SECURITY,incident,UUID.randomUUID(),new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,evidenceIds,null,null,"Issued independent evidence and selected reviewed safe document")));
        assertEquals("BLOCKED",str(workflow(workflowId),"state"));assertEquals(0,count("mock_payment"));
        assertEquals("INVALIDATED",str(db.required("select * from agent_result where run_id=?",old.input().runId()),"status"));
        recovery.resume(REVIEWER,workflowId,UUID.randomUUID(),new ResumeRequest(1,"Remediation was independently checked"));
        assertEquals(2,integer(workflow(workflowId),"generation"));assertRisk(workflowId,10,0);
        var fresh=prepareKyc();assertEquals(2,fresh.input().generation());assertEquals(1,fresh.input().documents().getFirst().documentVersion());
        kyc.apply(old,verified(old));assertNull(workflow(workflowId).get("current_kyc_result_id"));
        kyc.apply(fresh,verified(fresh));var loan=jobs.claim().orElseThrow();loans.execute(loan.jobId(),loan.token());
        assertRisk(workflowId,35,0);assertEquals(2,integer(db.required("select * from workflow_stage where workflow_id=? and stage='KYC'",workflowId),"run_count"));
        var pay=approve(workflowId);paymentAgent.execute(pay.jobId(),pay.token());
        assertEquals("PAID",str(workflow(workflowId),"state"));assertRisk(workflowId,85,0);assertEquals(1,count("mock_payment"));
        assertEquals(2,events("CHARGE"));assertEquals(1,events("CONSUME"));
        var paidResume=assertThrows(ApiException.class,()->recovery.resume(REVIEWER,workflowId,UUID.randomUUID(),new ResumeRequest(2,"Not permitted")));
        assertEquals("INVALID_STATE",paidResume.reasonCode());
    }
    @Test void preExecutionSourceHoldCanBeReleasedWithoutInventingAnActualRun() {
        var incident=quarantines.apply(SECURITY,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.SOURCE_VERSION,null,null,null,DOCUMENT,2,null,null,QuarantineRequest.Reason.SOURCE_COMPROMISED,"Prevent first consumption"));
        UUID incidentId=(UUID)incident.get("quarantineId");UUID workflowId=start("customer-101");
        var blocked=jobs.claim().orElseThrow();assertTrue(kyc.prepare(blocked.jobId(),blocked.token()).isEmpty());
        assertEquals("BLOCKED",str(workflow(workflowId),"state"));assertEquals(0,count("agent_run"));assertEquals(0,count("run_source_use"));assertRisk(workflowId,0,0);
        var impact=quarantines.impact(SECURITY,incidentId);
        assertEquals(0,((Number)((Map<?,?>)impact.get("actual")).get("runCount")).intValue());
        assertTrue(((Collection<?>)impact.get("policyHeldWorkflowIds")).contains(workflowId));
        var ids=issueEvidence101();
        quarantines.release(SECURITY,incidentId,UUID.randomUUID(),new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,ids,null,null,"Safe source and fresh evidence for the held application")));
        assertEquals(DOCUMENT,uuid(workflow(workflowId),"recovery_document_id"));
        recovery.resume(REVIEWER,workflowId,UUID.randomUUID(),new ResumeRequest(1,"Resolve the policy hold"));
        var prepared=prepareKyc();assertEquals(2,prepared.input().generation());assertEquals(1,prepared.input().documents().getFirst().documentVersion());
        assertRisk(workflowId,10,0);assertEquals(1,count("agent_run"));
    }
    @Test void anUnreleasedAncestorStopsResumeAndTheThirdAutomaticKycNeedsManualReview() {
        UUID workflowId=start("customer-101");var old=prepareKyc();kyc.apply(old,verified(old));
        var ex=assertThrows(ApiException.class,()->recovery.resume(REVIEWER,workflowId,UUID.randomUUID(),new ResumeRequest(1,"Attempt without clearance")));
        assertEquals("QUARANTINED",ex.reasonCode());
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflowId);db.update("update quarantine set status='RELEASED' where run_id=?",old.input().runId());
            db.update("update workflow_stage set run_count=2 where workflow_id=? and stage='KYC'",workflowId);});
        var reply=recovery.resume(REVIEWER,workflowId,UUID.randomUUID(),new ResumeRequest(1,"Automatic limit test"));
        assertEquals("ON_HOLD",reply.get("state"));assertEquals(List.of("MANUAL_REVIEW_REQUIRED"),reply.get("reasonCodes"));
        assertEquals(1,integer(workflow(workflowId),"generation"));assertRisk(workflowId,10,0);assertEquals(1,count("agent_run"));
    }
    @Test void lateKycCompletionCannotReopenARunQuarantine() {
        UUID workflowId=start("customer-102");var prepared=prepareKyc();
        quarantines.automaticRun(prepared.input().runId(),"SECURITY_INVESTIGATION","Before response apply");
        kyc.apply(prepared,verified(prepared));
        assertEquals("BLOCKED",str(workflow(workflowId),"state"));assertEquals(1,count("agent_run"));assertEquals(0,count("agent_result"));assertEquals(0,count("mock_payment"));
        assertEquals(1,((Number)db.required("select count(*) n from audit_event where event_type='LATE_RESULT_DISCARDED'").get("n")).intValue());
    }
}
