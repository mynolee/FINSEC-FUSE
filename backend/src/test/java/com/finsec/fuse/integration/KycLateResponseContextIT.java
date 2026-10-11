package com.finsec.fuse.integration;

import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.quarantine.ResumeRequest;
import com.finsec.fuse.workflow.KycContract;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic service/real-PG probes: obsolete Prepared context is fenced before response validation. */
class KycLateResponseContextIT extends PaymentFixture {
    private static final List<String> DURABLE_TABLES=List.of(
        "execution_gate","agent_registry","mock_account","mock_profile","application_registry",
        "source_document_version","trusted_evidence","loan_application","workflow","workflow_stage",
        "workflow_job","agent_run","agent_result","run_source_use","run_evidence_use","run_dependency",
        "action_request","delegation_grant","approval","payment_reservation","risk_ledger","mock_payment",
        "quarantine","quarantine_workflow_hold","experiment","experiment_case_result","experiment_arm_binding");

    @ParameterizedTest
    @ValueSource(strings={"WRONG_RUN_ID","WRONG_HASH"})
    void activePreparedRejectsMalformedResponseWithoutAffectingIndependentWork(String mutation) {
        UUID currentId=start("customer-102");
        var current=prepareKyc();
        UUID independentId=start("customer-103");
        var independent=prepareKyc();
        assertEquals(currentId,current.input().workflowId());
        assertEquals(independentId,independent.input().workflowId());
        String independentBefore=workflowContext(independentId);
        var unchangedBefore=durableRows(Set.of("workflow","workflow_job","agent_run"));
        var auditBefore=auditRows();

        kyc.apply(current,response(current,mutation));

        assertEquals("ON_HOLD",workflow(currentId).get("state"));
        assertEquals("ERROR",workflow(currentId).get("last_decision"));
        assertEquals("MODEL_OUTPUT_INVALID",workflow(currentId).get("last_reason_code"));
        assertNull(workflow(currentId).get("current_kyc_result_id"));
        assertEquals("FAILED",db.required("SELECT status FROM agent_run WHERE id=?",current.input().runId()).get("status"));
        var job=db.required("SELECT state,last_error FROM workflow_job WHERE id=?",current.jobId());
        assertEquals("FAILED",job.get("state"));
        assertEquals("MODEL_OUTPUT_INVALID",job.get("last_error"));
        assertEquals(unchangedBefore,durableRows(Set.of("workflow","workflow_job","agent_run")));
        assertEquals(independentBefore,workflowContext(independentId));
        assertAuditAdditions(auditBefore,current,"SYSTEM_ERROR","MODEL_OUTPUT_INVALID");
        assertEquals(0,count("agent_result"));
        assertEquals(2,count("workflow_job"));
        assertEquals(2,count("agent_run"));
        assertNoPaymentOrQuarantine();
        assertRisk(currentId,10,0);

        // Valid independent work remains possible after the malformed active response is refused.
        String heldBefore=workflowContext(currentId);
        completeValidKyc(independent);
        assertEquals(heldBefore,workflowContext(currentId));
        assertEquals(1,count("agent_result"));
        assertEquals(2,events("CHARGE"));
    }

    @ParameterizedTest
    @ValueSource(strings={"UNCHANGED","WRONG_RUN_ID","WRONG_HASH"})
    void expiredOriginalPreparedOnlyAddsLateAuditBeforeReaping(String mutation) {
        UUID currentId=start("customer-102");
        var original=prepareKyc();
        expire(original);
        UUID independentId=start("customer-103");
        var independent=prepareKyc();
        assertEquals(independentId,independent.input().workflowId());

        onlyLateDiscard(original,response(original,mutation));

        assertEquals("KYC_PENDING",workflow(currentId).get("state"));
        assertEquals("RUNNING",db.required("SELECT state FROM workflow_job WHERE id=?",original.jobId()).get("state"));
        assertEquals(0,count("agent_result"));
        completeValidKyc(independent);
        assertRisk(currentId,10,0);
        assertEquals(2,events("CHARGE"));
    }

    @ParameterizedTest
    @CsvSource({"UNCHANGED,false","WRONG_RUN_ID,false","WRONG_HASH,false",
                "UNCHANGED,true","WRONG_RUN_ID,true","WRONG_HASH,true"})
    void genuinelyOldPreparedCannotOverwriteResumedGenerationOrIndependentWorkflow(
            String mutation,boolean currentAlreadyCompleted) {
        UUID currentId=start("customer-102");
        var original=prepareKyc();
        expire(original);
        jobs.reapNonPayment(original.jobId());
        assertEquals("ON_HOLD",workflow(currentId).get("state"));
        assertEquals("DEPENDENCY_UNAVAILABLE",workflow(currentId).get("last_reason_code"));
        assertEquals("FAILED",db.required("SELECT state FROM workflow_job WHERE id=?",original.jobId()).get("state"));
        assertEquals("FAILED",db.required("SELECT status FROM agent_run WHERE id=?",original.input().runId()).get("status"));
        recovery.resume(REVIEWER,currentId,UUID.randomUUID(),new ResumeRequest(1,"Synthetic lease recovery"));
        var current=prepareKyc();
        assertEquals(currentId,current.input().workflowId());
        assertEquals(1,original.input().generation());
        assertEquals(2,current.input().generation());
        assertNotEquals(original.jobId(),current.jobId());
        assertNotEquals(original.leaseToken(),current.leaseToken());
        assertNotEquals(original.input().runId(),current.input().runId());
        UUID independentId=start("customer-103");
        var independent=prepareKyc();
        assertEquals(independentId,independent.input().workflowId());
        if(currentAlreadyCompleted)completeValidKyc(current);

        // Keep the actual old Prepared intact. Mutate only its response, never its persisted context.
        onlyLateDiscard(original,response(original,mutation));

        assertEquals(2,((Number)workflow(currentId).get("generation")).intValue());
        assertEquals(currentAlreadyCompleted?"KYC_VALIDATED":"KYC_PENDING",workflow(currentId).get("state"));
        assertEquals(0,db.query("SELECT id FROM agent_result WHERE run_id=?",original.input().runId()).size());
        if(!currentAlreadyCompleted)completeValidKyc(current);
        String completedBefore=workflowContext(currentId);
        completeValidKyc(independent);
        assertEquals(completedBefore,workflowContext(currentId));
        assertEquals(2,count("agent_result"));
        assertEquals(5,count("workflow_job")); // Old KYC, new KYC + LOAN, independent KYC + LOAN.
        assertEquals(3,count("agent_run"));
        assertEquals(2,events("CHARGE")); // Resume retains the original workflow's first KYC charge.
        assertRisk(currentId,10,0);
        assertRisk(independentId,10,0);
        assertNoPaymentOrQuarantine();
    }

    private KycContract.Response response(KycContract.Prepared prepared,String mutation) {
        var good=verified(prepared);
        UUID wrongRun=new UUID(good.runId().getMostSignificantBits()^1L,good.runId().getLeastSignificantBits());
        String wrongHash=(good.inputSnapshotHash().charAt(0)=='0'?"1":"0")+good.inputSnapshotHash().substring(1);
        assertTrue(Set.of("UNCHANGED","WRONG_RUN_ID","WRONG_HASH").contains(mutation));
        var response=new KycContract.Response(good.requestId(),good.workflowId(),good.generation(),
            "WRONG_RUN_ID".equals(mutation)?wrongRun:good.runId(),
            "WRONG_HASH".equals(mutation)?wrongHash:good.inputSnapshotHash(),good.proposal(),good.modelMetadata());
        assertEquals("UNCHANGED".equals(mutation),response.boundTo(prepared.input()));
        return response;
    }

    private void expire(KycContract.Prepared prepared) {
        var lease=(Timestamp)db.required("SELECT lease_until FROM workflow_job WHERE id=?",prepared.jobId()).get("lease_until");
        clock.set(lease.toInstant()); // Equality is already expired; no sleep or forged generation.
        assertTrue(jobs.expired().stream().anyMatch(row->prepared.jobId().equals(row.get("id"))));
    }

    private void onlyLateDiscard(KycContract.Prepared original,KycContract.Response response) {
        var before=durableRows(Set.of());
        var audits=auditRows();
        kyc.apply(original,response);
        assertEquals(before,durableRows(Set.of()),"Late completion may not mutate or append any business row in either workflow");
        assertAuditAdditions(audits,original,"LATE_RESULT_DISCARDED","WORKFLOW_CHANGED");
        assertNoPaymentOrQuarantine();
    }

    private void completeValidKyc(KycContract.Prepared prepared) {
        kyc.apply(prepared,verified(prepared));
        UUID workflowId=prepared.input().workflowId();
        assertEquals("KYC_VALIDATED",workflow(workflowId).get("state"));
        var result=db.required("SELECT id,status,generation FROM agent_result WHERE run_id=?",prepared.input().runId());
        assertEquals("VALIDATED",result.get("status"));
        assertEquals(prepared.input().generation(),((Number)result.get("generation")).intValue());
        assertEquals(result.get("id"),workflow(workflowId).get("current_kyc_result_id"));
        assertEquals("SUCCEEDED",db.required("SELECT state FROM workflow_job WHERE id=?",prepared.jobId()).get("state"));
        assertEquals(1,db.query("SELECT id FROM workflow_job WHERE workflow_id=? AND generation=? AND phase='LOAN' AND state='PENDING'",
            workflowId,prepared.input().generation()).size());
        assertRisk(workflowId,10,0);
    }

    private void assertNoPaymentOrQuarantine() {
        for(String table:List.of("approval","payment_reservation","mock_payment","quarantine","quarantine_workflow_hold"))
            assertEquals(0,count(table),table);
    }

    private Map<String,List<Map<String,Object>>> durableRows(Set<String> excluded) {
        var rows=new LinkedHashMap<String,List<Map<String,Object>>>();
        // PostgreSQL renders bytea and composite-key rows consistently; sorting complete rows also detects inserts/deletes.
        for(String table:DURABLE_TABLES)if(!excluded.contains(table))
            rows.put(table,db.query("SELECT row_to_json(t)::text AS row FROM "+table+" t ORDER BY row_to_json(t)::text"));
        return rows;
    }

    private String workflowContext(UUID workflowId) {
        var rows=new LinkedHashMap<String,Object>();
        rows.put("workflow",db.query("SELECT row_to_json(t)::text AS row FROM workflow t WHERE id=?",workflowId));
        for(String table:List.of("workflow_job","agent_run","agent_result","workflow_stage","delegation_grant",
                "approval","payment_reservation","mock_payment","risk_ledger","run_dependency","action_request","audit_event"))
            rows.put(table,db.query("SELECT row_to_json(t)::text AS row FROM "+table+" t WHERE workflow_id=? ORDER BY row_to_json(t)::text",workflowId));
        for(String table:List.of("run_source_use","run_evidence_use"))
            rows.put(table,db.query("SELECT row_to_json(t)::text AS row FROM "+table+" t JOIN agent_run r ON r.id=t.run_id WHERE r.workflow_id=? ORDER BY row_to_json(t)::text",workflowId));
        return json.write(rows);
    }

    private Map<UUID,String> auditRows() {
        var rows=new LinkedHashMap<UUID,String>();
        for(var row:db.query("SELECT id,row_to_json(t)::text AS row FROM audit_event t ORDER BY id"))
            rows.put((UUID)row.get("id"),(String)row.get("row"));
        return rows;
    }

    private void assertAuditAdditions(Map<UUID,String> before,KycContract.Prepared prepared,String event,String reason) {
        var after=auditRows();
        boolean late="LATE_RESULT_DISCARDED".equals(event);
        int expected=late?1:2;
        assertEquals(before.size()+expected,after.size(),"Only the expected audit additions are allowed");
        before.forEach((id,row)->assertEquals(row,after.get(id),"Prior audit rows must remain identical"));
        var additions=new ArrayList<>(after.keySet());
        additions.removeAll(before.keySet());
        assertEquals(expected,additions.size());
        var added=additions.stream().map(id->db.required("SELECT * FROM audit_event WHERE id=?",id)).toList();
        var matching=added.stream().filter(row->event.equals(row.get("event_type"))).toList();
        assertEquals(1,matching.size());
        var audit=matching.getFirst();
        if(!late) {
            var changes=added.stream().filter(row->"WORKFLOW_STATE_CHANGED".equals(row.get("event_type"))).toList();
            assertEquals(1,changes.size());
            var change=changes.getFirst();
            assertEquals(prepared.input().workflowId(),change.get("workflow_id"));
            assertEquals("MODEL_OUTPUT_INVALID",change.get("reason_code"));
            assertEquals("fuse-worker",change.get("actor_id"));
            assertNull(change.get("run_id"));
            assertNull(change.get("action_id"));
            assertNull(change.get("quarantine_id"));
            assertEquals(true,db.required("SELECT details_json = ?::jsonb AS matches FROM audit_event WHERE id=?",
                "{\"from\":\"KYC_PENDING\",\"to\":\"ON_HOLD\"}",change.get("id")).get("matches"));
            assertEquals(true,db.required("SELECT details_json = ?::jsonb AS matches FROM audit_event WHERE id=?",
                "{\"state\":\"ON_HOLD\"}",audit.get("id")).get("matches"));
        }
        assertEquals(event,audit.get("event_type"));
        assertEquals(reason,audit.get("reason_code"));
        assertEquals(prepared.input().workflowId(),audit.get("workflow_id"));
        assertEquals(prepared.input().runId(),audit.get("run_id"));
        assertEquals(prepared.input().requestId(),audit.get("action_id"));
        assertEquals("fuse-worker",audit.get("actor_id"));
        assertNull(audit.get("quarantine_id"));
        if("LATE_RESULT_DISCARDED".equals(event))assertEquals("{}",audit.get("details_json").toString());
    }
}
