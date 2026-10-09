package com.finsec.fuse.integration;

import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.payment.PaymentSupport;
import com.finsec.fuse.persistence.ActionRequests;
import com.finsec.fuse.workflow.JobTransactions;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Real PostgreSQL recovery-state injection, not a process-crash test: commit() atomically
 * persists the payment and marks its job SUCCEEDED. After a genuine payment, the harness
 * resets only the job and optionally deletes its replay receipt to exercise the otherwise
 * untested defensive ledger-present reap branch. No payment ledger or authority is forged.
 */
class PaymentReapLedgerRestoreIT extends PaymentFixture {
    private static final String WORKER = "fuse-worker";
    private static final String ACTION = "EXECUTE_MOCK_PAYMENT";
    @Autowired ActionRequests actions;
    @Autowired PaymentSupport support;

    private record Paid(JobTransactions.Lease lease, UUID actionId, Map<String,Object> receipt,
                        Map<String,Object> body, Instant leaseUntil) {}

    private Paid paid() {
        UUID workflow = ready102();
        var lease = approve(workflow);
        payments.reserve(lease.jobId(), lease.token());
        assertEquals("PAID", payments.commit(lease.jobId(), lease.token()).get("state"));
        var job = job(lease.jobId());
        UUID actionId = (UUID) job.get("execution_action_id");
        var ledger = db.required("SELECT * FROM mock_payment WHERE action_id=?", actionId);
        assertEquals(1, count("mock_payment"));
        assertEquals(1, events("CONSUME"));
        assertRisk(workflow, 85, 0);
        return new Paid(lease, actionId, json.map(ledger.get("receipt_json").toString()),
            support.actionBody(workflow(workflow), job),
            ((Timestamp) job.get("lease_until")).toInstant());
    }

    private Map<String,Object> job(UUID id) {
        return db.required("SELECT * FROM workflow_job WHERE id=?", id);
    }

    private void injectRecoveryState(Paid paid, boolean removeReceipt) {
        tx.executeWithoutResult(status -> {
            db.gate();
            db.lockWorkflow(paid.lease().workflowId());
            db.update("UPDATE workflow_job SET state='RUNNING',completed_at=NULL WHERE id=?", paid.lease().jobId());
            if (removeReceipt) db.update("DELETE FROM action_request WHERE action_id=?", paid.actionId());
        });
    }

    /** Every durable business row that recovery must leave untouched, including all grants. */
    private String businessRows(UUID workflow) {
        var rows = new LinkedHashMap<String,Object>();
        rows.put("workflow", workflow(workflow));
        rows.put("stages", db.query("SELECT * FROM workflow_stage WHERE workflow_id=? ORDER BY stage", workflow));
        for (String table : List.of("agent_run", "agent_result", "approval", "payment_reservation",
                "mock_payment", "risk_ledger", "delegation_grant"))
            rows.put(table, db.query("SELECT * FROM " + table + " WHERE workflow_id=? ORDER BY id", workflow));
        return json.write(rows);
    }

    /** Include execution bookkeeping and recorded inputs, even when a row set is empty. */
    private String durableRows(UUID workflow) {
        var rows = new LinkedHashMap<String,Object>();
        rows.put("business", businessRows(workflow));
        for (String table : List.of("workflow_job", "audit_event"))
            rows.put(table, db.query("SELECT * FROM " + table + " WHERE workflow_id=? ORDER BY id", workflow));
        rows.put("actions", db.query("SELECT * FROM action_request WHERE workflow_id=? ORDER BY action_id", workflow));
        rows.put("dependencies", db.query("SELECT * FROM run_dependency WHERE workflow_id=? ORDER BY parent_run_id,child_run_id", workflow));
        rows.put("sources", db.query("SELECT u.* FROM run_source_use u JOIN agent_run r ON r.id=u.run_id WHERE r.workflow_id=? ORDER BY u.run_id,u.document_id,u.document_version", workflow));
        rows.put("evidence", db.query("SELECT u.* FROM run_evidence_use u JOIN agent_run r ON r.id=u.run_id WHERE r.workflow_id=? ORDER BY u.run_id,u.evidence_id", workflow));
        return json.write(rows);
    }

    private long restorations(Paid paid) {
        return ((Number) db.required("SELECT count(*) n FROM audit_event WHERE action_id=? AND event_type='PAYMENT_RECEIPT_RESTORED'",
            paid.actionId()).get("n")).longValue();
    }

    private void assertRestored(Paid paid, String before) {
        assertEquals(before, businessRows(paid.lease().workflowId()), "Recovery must not refresh authority, debit, or alter current state");
        var restored = db.required("SELECT * FROM action_request WHERE action_id=?", paid.actionId());
        assertEquals(WORKER, restored.get("actor_id"));
        assertEquals(ACTION, restored.get("action_type"));
        assertEquals(paid.lease().workflowId(), restored.get("workflow_id"));
        assertEquals("SUCCEEDED", restored.get("status"));
        assertEquals("ALLOW", restored.get("decision"));
        assertEquals(actions.fingerprint(WORKER, ACTION, paid.lease().workflowId(), paid.body()), restored.get("payload_hash"));
        assertEquals(paid.receipt(), json.map(restored.get("result_json").toString()));
        assertEquals("SUCCEEDED", job(paid.lease().jobId()).get("state"));
        assertNotNull(job(paid.lease().jobId()).get("completed_at"));
        assertEquals(1, count("mock_payment"));
        assertEquals(1, events("RESERVE"));
        assertEquals(1, events("CONSUME"));
        assertEquals(0, events("RELEASE"));
    }

    @ParameterizedTest @ValueSource(booleans={true, false})
    void restoresHistoricalSuccessWithOrWithoutExistingActionReceipt(boolean removeReceipt) {
        var paid = paid();
        injectRecoveryState(paid, removeReceipt);
        // All execution authority is expired; recovery must use the immutable original receipt.
        clock.set(paid.leaseUntil().plusSeconds(86_400));
        String before = businessRows(paid.lease().workflowId());
        String existing = removeReceipt ? null : json.write(db.required("SELECT * FROM action_request WHERE action_id=?", paid.actionId()));
        assertEquals("RUNNING", job(paid.lease().jobId()).get("state"));
        assertEquals(removeReceipt ? 0 : 1, db.query("SELECT action_id FROM action_request WHERE action_id=?", paid.actionId()).size());
        assertTrue(jobs.expired().stream().anyMatch(row -> paid.lease().jobId().equals(row.get("id"))));
        payments.reap(paid.lease().jobId());
        assertRestored(paid, before);
        assertEquals(1, restorations(paid));
        if (!removeReceipt) assertEquals(existing, json.write(db.required("SELECT * FROM action_request WHERE action_id=?", paid.actionId())));
        String completedJob = json.write(job(paid.lease().jobId()));
        String receipt = json.write(db.required("SELECT * FROM action_request WHERE action_id=?", paid.actionId()));
        clock.set(clock.now().plusSeconds(1));
        payments.reap(paid.lease().jobId());
        assertEquals(completedJob, json.write(job(paid.lease().jobId())));
        assertEquals(receipt, json.write(db.required("SELECT * FROM action_request WHERE action_id=?", paid.actionId())));
        assertEquals(1, restorations(paid));
        var replay = payments.commit(paid.lease().jobId(), paid.lease().token());
        var expected = new LinkedHashMap<>(paid.receipt());
        expected.put("replayed", true);
        assertEquals(expected, replay);
        assertRestored(paid, before);
    }

    @ParameterizedTest @ValueSource(ints={-1, 0, 1})
    void reapRequiresExpiredLeaseIncludingExactBoundary(int secondsFromExpiry) {
        var paid = paid();
        injectRecoveryState(paid, true);
        clock.set(paid.leaseUntil().plusSeconds(secondsFromExpiry));
        String before = businessRows(paid.lease().workflowId());
        String originalJob = json.write(job(paid.lease().jobId()));
        payments.reap(paid.lease().jobId());
        if (secondsFromExpiry < 0) {
            assertEquals(originalJob, json.write(job(paid.lease().jobId())));
            assertTrue(db.one("SELECT action_id FROM action_request WHERE action_id=?", paid.actionId()).isEmpty());
            assertEquals(0, restorations(paid));
            assertEquals(before, businessRows(paid.lease().workflowId()));
        } else {
            assertRestored(paid, before);
            assertEquals(1, restorations(paid));
        }
    }

    @ParameterizedTest @ValueSource(strings={"PENDING", "SUCCEEDED", "FAILED"})
    void nonRunningJobCannotRestoreEvenWhenLedgerAndExpiredLeaseExist(String state) {
        var paid = paid();
        injectRecoveryState(paid, true);
        tx.executeWithoutResult(status -> {
            db.gate(); db.lockWorkflow(paid.lease().workflowId());
            db.update("UPDATE workflow_job SET state=? WHERE id=?", state, paid.lease().jobId());
        });
        clock.set(paid.leaseUntil());
        String before = businessRows(paid.lease().workflowId());
        String originalJob = json.write(job(paid.lease().jobId()));
        payments.reap(paid.lease().jobId());
        assertEquals(originalJob, json.write(job(paid.lease().jobId())));
        assertEquals(before, businessRows(paid.lease().workflowId()));
        assertTrue(db.one("SELECT action_id FROM action_request WHERE action_id=?", paid.actionId()).isEmpty());
        assertEquals(0, restorations(paid));
    }

    @ParameterizedTest @ValueSource(strings={"TOKEN", "GENERATION"})
    void executionFencingIsIndependentOfLeaseExpiry(String mismatch) {
        var paid = paid();
        injectRecoveryState(paid, true);
        UUID token = mismatch.equals("TOKEN") ? UUID.randomUUID() : paid.lease().token();
        if (mismatch.equals("GENERATION")) tx.executeWithoutResult(status -> {
            db.gate(); db.lockWorkflow(paid.lease().workflowId());
            db.update("UPDATE workflow SET generation=generation+1 WHERE id=?", paid.lease().workflowId());
        });
        assertTrue(clock.now().isBefore(paid.leaseUntil()), "Only token or generation is invalid, not lease time");
        String before = businessRows(paid.lease().workflowId());
        String originalJob = json.write(job(paid.lease().jobId()));
        var denied = payments.commit(paid.lease().jobId(), token);
        assertEquals("DENY", denied.get("decision"));
        assertEquals(List.of("STALE_LEASE"), denied.get("reasonCodes"));
        assertEquals(originalJob, json.write(job(paid.lease().jobId())));
        assertEquals(before, businessRows(paid.lease().workflowId()));
        assertTrue(db.one("SELECT action_id FROM action_request WHERE action_id=?", paid.actionId()).isEmpty());
        assertEquals(0, restorations(paid));
    }

    @Test void staleExecutorCannotRestoreButReaperCanRecoverHistoricalSuccessWithoutTouchingNewGeneration() {
        var paid = paid();
        injectRecoveryState(paid, true);
        tx.executeWithoutResult(status -> {
            db.gate(); db.lockWorkflow(paid.lease().workflowId());
            db.update("UPDATE workflow SET generation=generation+1,state='ON_HOLD' WHERE id=?", paid.lease().workflowId());
        });
        clock.set(paid.leaseUntil());
        String before = businessRows(paid.lease().workflowId());
        for (UUID token : List.of(paid.lease().token(), UUID.randomUUID())) {
            var denied = payments.commit(paid.lease().jobId(), token);
            assertEquals("DENY", denied.get("decision"));
            assertEquals(List.of("STALE_LEASE"), denied.get("reasonCodes"));
            assertEquals(before, businessRows(paid.lease().workflowId()));
            assertTrue(db.one("SELECT action_id FROM action_request WHERE action_id=?", paid.actionId()).isEmpty());
            assertEquals("RUNNING", job(paid.lease().jobId()).get("state"));
        }
        payments.reap(paid.lease().jobId());
        assertRestored(paid, before);
        assertEquals(1, ((Number) paid.receipt().get("generation")).intValue());
        assertEquals(2, ((Number) workflow(paid.lease().workflowId()).get("generation")).intValue());
        assertEquals("ON_HOLD", workflow(paid.lease().workflowId()).get("state"));
    }

    @Test void recoveredReceiptRejectsChangedContextIncludingForeignJobWithoutTouchingIndependentLiveExecution() {
        var paid = paid();
        injectRecoveryState(paid, true);
        clock.set(paid.leaseUntil().plusSeconds(1));
        // Start the independent lease AFTER expiring the injected historical recovery state.
        // Local KYC preparation persists a real live run; no model/provider is executed.
        UUID independent = start("customer-103");
        var current = jobs.claim().orElseThrow();
        assertEquals(independent, current.workflowId());
        assertEquals("KYC", current.phase());
        assertNotEquals(paid.lease().workflowId(), independent);
        assertNotEquals(paid.lease().jobId(), current.jobId());
        var prepared = kyc.prepare(current.jobId(), current.token()).orElseThrow();
        var currentJob = job(current.jobId());
        var currentRun = db.required("SELECT * FROM agent_run WHERE id=?", prepared.input().runId());
        assertNotEquals(job(paid.lease().jobId()).get("run_id"), currentRun.get("id"));
        assertEquals(independent, currentJob.get("workflow_id"));
        assertEquals(independent, currentRun.get("workflow_id"));
        assertEquals(currentRun.get("id"), currentJob.get("run_id"));
        assertEquals(current.generation(), ((Number) workflow(independent).get("generation")).intValue());
        assertEquals(current.generation(), ((Number) currentJob.get("generation")).intValue());
        assertEquals(current.generation(), ((Number) currentRun.get("generation")).intValue());
        assertEquals(current.token(), currentJob.get("lease_token"));
        assertEquals("RUNNING", currentJob.get("state"));
        assertEquals("RUNNING", currentRun.get("status"));
        assertTrue(((Timestamp) currentJob.get("lease_until")).toInstant().isAfter(clock.now()));
        String independentBefore = durableRows(independent);
        // START_WORKFLOW receipts have no workflow_id, so include them explicitly in the oracle.
        String otherActionsBefore = json.write(db.query("SELECT * FROM action_request WHERE action_id<>? ORDER BY action_id", paid.actionId()));
        String before = businessRows(paid.lease().workflowId());
        payments.reap(paid.lease().jobId());
        assertRestored(paid, before);
        assertEquals(1, restorations(paid));
        assertEquals(independentBefore, durableRows(independent), "Reaping historical payment must preserve the independent live execution");
        assertEquals(otherActionsBefore, json.write(db.query("SELECT * FROM action_request WHERE action_id<>? ORDER BY action_id", paid.actionId())));
        assertEquals("RUNNING", job(current.jobId()).get("state"));
        assertEquals("RUNNING", db.required("SELECT * FROM agent_run WHERE id=?", prepared.input().runId()).get("status"));
        assertTrue(((Timestamp) job(current.jobId()).get("lease_until")).toInstant().isAfter(clock.now()));
        String paidBeforeReplay = durableRows(paid.lease().workflowId());
        String allActionsBeforeReplay = json.write(db.query("SELECT * FROM action_request ORDER BY action_id"));
        String receipt = json.write(db.required("SELECT * FROM action_request WHERE action_id=?", paid.actionId()));
        // Change ONLY canonical jobId; retain the original actor, workflow, action and terms.
        var changedJob = new LinkedHashMap<>(paid.body());
        assertEquals(paid.lease().jobId(), changedJob.put("jobId", current.jobId()));
        assertReplayDenied(paid, WORKER, paid.lease().workflowId(), changedJob, 409, "REPLAY_CONFLICT");
        assertEquals(allActionsBeforeReplay, json.write(db.query("SELECT * FROM action_request ORDER BY action_id")));
        assertEquals(paidBeforeReplay, durableRows(paid.lease().workflowId()));
        assertEquals(independentBefore, durableRows(independent), "Foreign job replay must preserve the independent live execution");
        assertReplayDenied(paid, "customer-102", paid.lease().workflowId(), paid.body(), 403, "FORBIDDEN");
        var changedGeneration = new LinkedHashMap<>(paid.body());
        changedGeneration.put("generation", paid.lease().generation()+1);
        assertReplayDenied(paid, WORKER, paid.lease().workflowId(), changedGeneration, 409, "REPLAY_CONFLICT");
        assertReplayDenied(paid, WORKER, UUID.randomUUID(), paid.body(), 409, "REPLAY_CONFLICT");
        assertEquals(receipt, json.write(db.required("SELECT * FROM action_request WHERE action_id=?", paid.actionId())));
        assertEquals(allActionsBeforeReplay, json.write(db.query("SELECT * FROM action_request ORDER BY action_id")));
        assertEquals(paidBeforeReplay, durableRows(paid.lease().workflowId()));
        assertEquals(independentBefore, durableRows(independent));
        assertEquals(1, restorations(paid));
        assertRestored(paid, before);
    }

    private void assertReplayDenied(Paid paid, String actor, UUID workflow, Map<String,Object> body,
                                    int status, String reason) {
        var denied = assertThrows(ApiException.class, () -> tx.execute(transaction -> {
            db.gate();
            return actions.replay(paid.actionId(), actor, ACTION, workflow, body);
        }));
        assertEquals(status, denied.status());
        assertEquals(reason, denied.reasonCode());
    }
}
