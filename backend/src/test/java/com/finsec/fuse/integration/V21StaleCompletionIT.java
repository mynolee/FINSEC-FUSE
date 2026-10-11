package com.finsec.fuse.integration;

import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.workflow.KycContract;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Actual Service/PG single-boundary mutations; test clock is the application DB-TimeSource seam. */
class V21StaleCompletionIT extends PaymentFixture {
    private String currentRows(UUID workflow) {
        var snapshot=new LinkedHashMap<String,Object>();
        snapshot.put("workflow",workflow(workflow));
        for(String table:List.of("workflow_job","agent_run","agent_result","delegation_grant","approval","mock_payment","risk_ledger"))
            snapshot.put(table,db.query("SELECT * FROM "+table+" WHERE workflow_id=? ORDER BY id",workflow));
        return json.write(snapshot);
    }
    private long discarded(UUID workflow) {
        return ((Number)db.required("SELECT count(*) n FROM audit_event WHERE workflow_id=? AND event_type='LATE_RESULT_DISCARDED'",workflow).get("n")).longValue();
    }
    private void onlyDiscard(KycContract.Prepared prepared,KycContract.Response response) {
        UUID workflow=prepared.input().workflowId();String before=currentRows(workflow);long audit=discarded(workflow);
        kyc.apply(prepared,response);
        assertEquals(before,currentRows(workflow),"Late result must preserve every existing business row");
        assertEquals(audit+1,discarded(workflow));assertEquals(0,count("mock_payment"));
    }
    @Test void wrongLeaseOnlyDiscardsAndLegitimateLeaseCanStillComplete() {
        UUID workflow=start("customer-102");var prepared=prepareKyc();
        var wrong=new KycContract.Prepared(prepared.jobId(),UUID.randomUUID(),prepared.input());
        onlyDiscard(wrong,verified(prepared));
        kyc.apply(prepared,verified(prepared));
        assertEquals("KYC_VALIDATED",workflow(workflow).get("state"));assertEquals(1,count("agent_result"));assertRisk(workflow,10,0);
    }
    @ParameterizedTest @ValueSource(strings={"PENDING","SUCCEEDED","FAILED"})
    void nonRunningJobStateAloneDiscardsWithoutChangingCurrentRows(String state) {
        UUID workflow=start("customer-102");var prepared=prepareKyc();
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflow);db.update("UPDATE workflow_job SET state=? WHERE id=?",state,prepared.jobId());});
        onlyDiscard(prepared,verified(prepared));assertRisk(workflow,10,0);
    }
    @ParameterizedTest @ValueSource(ints={89,90,91})
    void leaseBoundaryIsCheckedAtApplyWithoutReaperChangingAnyOtherCondition(int seconds) {
        UUID workflow=start("customer-102");var prepared=prepareKyc();Instant started=clock.now();
        Instant lease=((Timestamp)db.required("SELECT lease_until FROM workflow_job WHERE id=?",prepared.jobId()).get("lease_until")).toInstant();
        assertEquals(started.plusSeconds(90),lease);
        clock.set(started.plusSeconds(seconds));
        if(seconds<90) {
            kyc.apply(prepared,verified(prepared));
            assertEquals("KYC_VALIDATED",workflow(workflow).get("state"));assertEquals(1,count("agent_result"));
            assertEquals(1,db.query("SELECT id FROM workflow_job WHERE workflow_id=? AND phase='LOAN'",workflow).size());
        } else onlyDiscard(prepared,verified(prepared));
        assertRisk(workflow,10,0);assertEquals(1,events("CHARGE"));
    }
    @ParameterizedTest @ValueSource(ints={60,75,89})
    void consumedStartGrantExpiryDoesNotInvalidateCurrentNormalKycLease(int seconds) {
        UUID workflow=start("customer-102");var prepared=prepareKyc();Instant started=clock.now();
        var grant=db.required("SELECT status,expires_at FROM delegation_grant WHERE target_run_id=?",prepared.input().runId());
        assertEquals("CONSUMED",grant.get("status"));assertEquals(started.plusSeconds(60),((Timestamp)grant.get("expires_at")).toInstant());
        clock.set(started.plusSeconds(seconds));kyc.apply(prepared,verified(prepared));
        assertEquals("KYC_VALIDATED",workflow(workflow).get("state"));assertEquals(1,count("agent_result"));
        assertEquals(1,events("CHARGE"));assertEquals(0,discarded(workflow));assertRisk(workflow,10,0);
    }
    @Test void responseSnapshotHashOnlyMismatchCannotProduceResultOrNextJob() {
        UUID workflow=start("customer-102");var prepared=prepareKyc();var good=verified(prepared);
        String hash=good.inputSnapshotHash().equals("0".repeat(64))?"1".repeat(64):"0".repeat(64);
        var wrong=new KycContract.Response(good.requestId(),good.workflowId(),good.generation(),good.runId(),hash,good.proposal(),good.modelMetadata());
        kyc.apply(prepared,wrong);
        assertEquals("ON_HOLD",workflow(workflow).get("state"));assertEquals("MODEL_OUTPUT_INVALID",workflow(workflow).get("last_reason_code"));
        assertEquals(0,count("agent_result"));assertEquals(1,count("workflow_job"));assertEquals(0,count("quarantine"));assertEquals(0,count("mock_payment"));assertRisk(workflow,10,0);
    }
    @Test void oldWorkflowGenerationAloneDiscardsWithoutOverwritingCurrentGeneration() {
        UUID workflow=start("customer-102");var prepared=prepareKyc();
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflow);db.update("UPDATE workflow SET generation=generation+1 WHERE id=?",workflow);});
        onlyDiscard(prepared,verified(prepared));assertEquals(2,((Number)workflow(workflow).get("generation")).intValue());
    }
    @Test void oldCompletionAfterCurrentValidResultPreservesAllCurrentRows() {
        UUID workflow=start("customer-102");var prepared=prepareKyc();kyc.apply(prepared,verified(prepared));
        UUID result=(UUID)workflow(workflow).get("current_kyc_result_id");assertNotNull(result);
        onlyDiscard(prepared,verified(prepared));assertEquals(result,workflow(workflow).get("current_kyc_result_id"));
    }
    @Test void quarantineBeforeFinalPaymentRevokesApprovalAndPreservesConsumedRisk() {
        UUID workflow=ready102();var payment=approve(workflow);payments.reserve(payment.jobId(),payment.token());
        UUID approval=(UUID)db.required("SELECT approval_id FROM workflow_job WHERE id=?",payment.jobId()).get("approval_id");
        quarantines.automaticRun(kycRun(workflow),"SECURITY_INVESTIGATION","Quarantine committed before final payment");
        assertEquals("BLOCKED",payments.commit(payment.jobId(),payment.token()).get("state"));
        assertEquals("REVOKED",db.required("SELECT status FROM approval WHERE id=?",approval).get("status"));
        assertEquals(0,count("mock_payment"));assertEquals(0,events("CONSUME"));assertEquals(1,events("RELEASE"));assertRisk(workflow,35,0);
    }
}
