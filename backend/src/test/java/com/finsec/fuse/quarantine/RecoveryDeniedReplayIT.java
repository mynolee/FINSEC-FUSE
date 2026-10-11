package com.finsec.fuse.quarantine;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.payment.PaymentFixture;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;

/** A persisted security DENY is distinct from an allowed reviewer business rejection. */
class RecoveryDeniedReplayIT extends PaymentFixture {
    @Autowired FusePolicy policy;

    @Test @Timeout(30)
    void exhaustedRecoveryReplaysTheSavedDenyWithoutChangingAnyDurableEffects() {
        UUID workflowId=start("customer-102");
        // Spend the real bounded run allowance through production prepare/reap/resume transactions.
        // Do not manufacture an exhausted stage counter or a prewritten denial receipt.
        for(int generation=1;generation<=policy.maxRunsPerStage();generation++) {
            var prepared=prepareKyc();
            assertEquals(generation,prepared.input().generation());
            var running=db.required("SELECT * FROM workflow_job WHERE id=?",prepared.jobId());
            clock.set(instant(running,"lease_until").plusMillis(1));
            jobs.reapNonPayment(prepared.jobId());
            assertEquals("ON_HOLD",str(workflow(workflowId),"state"));
            assertEquals("DEPENDENCY_UNAVAILABLE",str(workflow(workflowId),"last_reason_code"));
            assertRisk(workflowId,policy.kycRisk(),0);
            if(generation<policy.maxRunsPerStage()) {
                var resumed=recovery.resume(REVIEWER,workflowId,UUID.randomUUID(),
                    new ResumeRequest(generation,"Retry after the unavailable dependency recovers"));
                assertEquals("ALLOW",resumed.get("decision"));
                assertEquals("KYC_PENDING",resumed.get("state"));
            }
        }

        UUID actionId=UUID.randomUUID();
        var body=new ResumeRequest(policy.maxRunsPerStage(),"Request another automatic evaluation");
        var original=recovery.resume(REVIEWER,workflowId,actionId,body);
        assertEquals("ON_HOLD",original.get("state"));
        assertEquals("DENY",original.get("decision"));
        assertEquals(List.of("MANUAL_REVIEW_REQUIRED"),original.get("reasonCodes"));
        assertEquals(false,original.get("replayed"));
        assertEquals("DENY",str(workflow(workflowId),"last_decision"));
        assertEquals("MANUAL_REVIEW_REQUIRED",str(workflow(workflowId),"last_reason_code"));
        assertEquals(policy.maxRunsPerStage(),integer(workflow(workflowId),"generation"));
        assertEquals(policy.maxRunsPerStage(),integer(db.required(
            "SELECT * FROM workflow_stage WHERE workflow_id=? AND stage='KYC'",workflowId),"run_count"));
        assertEquals(policy.maxRunsPerStage(),count("agent_run"));
        assertEquals(policy.maxRunsPerStage(),count("delegation_grant"));
        assertEquals(1,events("CHARGE"));
        assertRisk(workflowId,policy.kycRisk(),0);
        assertEquals(0,count("approval"));
        assertEquals(0,count("payment_reservation"));
        assertEquals(0,count("mock_payment"));
        assertEquals(0,count("quarantine"));
        assertTrue(jobs.claim().isEmpty());

        var receipt=db.required("SELECT * FROM action_request WHERE action_id=?",actionId);
        assertEquals(REVIEWER.actorId(),str(receipt,"actor_id"));
        assertEquals("WORKFLOW_RESUME",str(receipt,"action_type"));
        assertEquals(workflowId,uuid(receipt,"workflow_id"));
        assertEquals("SUCCEEDED",str(receipt,"status"));
        assertEquals("DENY",str(receipt,"decision"));
        assertEquals(json.map(json.write(original)),json.map(str(receipt,"result_json")));
        assertEquals(1,db.query("SELECT id FROM audit_event WHERE action_id=? "
            +"AND event_type='MANUAL_REVIEW_REQUIRED' AND reason_code='MANUAL_REVIEW_REQUIRED'",actionId).size());

        var afterDeny=durableRows();
        // A different time makes accidental timestamp refreshes visible as well as duplicate rows.
        clock.set(clock.now().plusSeconds(3600));
        var expectedReplay=json.map(json.write(original));
        expectedReplay.put("replayed",true);
        for(int attempt=0;attempt<2;attempt++) {
            var replay=recovery.resume(REVIEWER,workflowId,actionId,body);
            assertEquals(expectedReplay,replay);
            assertEquals(afterDeny,durableRows(),"Saved DENY replay must not mutate rows or append audit events");
        }

        var conflict=assertThrows(ApiException.class,()->recovery.resume(REVIEWER,workflowId,actionId,
            new ResumeRequest(body.expectedGeneration(),"A changed body cannot reuse the denial receipt")));
        assertEquals(409,conflict.status());
        assertEquals("REPLAY_CONFLICT",conflict.reasonCode());
        assertEquals(afterDeny,durableRows());
    }

    private Map<String,List<String>> durableRows() {
        var rows=new LinkedHashMap<String,List<String>>();
        for(String table:List.of("execution_gate","loan_application","workflow","workflow_stage",
            "workflow_job","agent_run","agent_result","run_source_use","run_evidence_use","run_dependency",
            "action_request","approval","delegation_grant","payment_reservation","risk_ledger",
            "mock_payment","quarantine","quarantine_workflow_hold","audit_event")) {
            rows.put(table,db.query("SELECT to_jsonb(r)::text AS row_json FROM "+table+" r ORDER BY row_json")
                .stream().map(row->str(row,"row_json")).toList());
        }
        return rows;
    }
}
