package com.finsec.fuse.integration;

import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.payment.PaymentSupport;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Real PostgreSQL worker-boundary test, not public HTTP admission or same-key replay.
 * The schema permits only one active job per workflow. Each distinct synthetic attempt
 * therefore admits its live job under the production gate and commits its rejection in
 * the same transaction. No constraint is removed and no payment grant is fabricated:
 * depth-three authority can only exist after genuine reviewer approval.
 */
class UnapprovedPaymentConcurrencyIT extends PaymentFixture {
    private static final int ATTEMPTS = 20;
    @Autowired PaymentSupport support;

    @Test
    void twentyDistinctConcurrentUnapprovedActionsCannotSpendRiskOrCreatePayment() throws Exception {
        UUID workflowId = ready102();
        var initialWorkflow = workflow(workflowId);
        assertRisk(workflowId, 35, 0);
        assertEquals("WAIT_APPROVAL", initialWorkflow.get("state"));
        assertNull(support.currentFailure(initialWorkflow, clock.now()),
            "The workflow must have valid evidence, account, results and policy before the attack");
        assertEquals(0, count("approval"));
        assertEquals(2, count("delegation_grant"));
        assertEquals(0, count("payment_reservation"));
        assertEquals(0, count("mock_payment"));
        var initialAuthority = authorityRows(workflowId);
        var initialJobs = db.query("SELECT * FROM workflow_job WHERE workflow_id=? ORDER BY id", workflowId);
        var initialAudits = db.query("SELECT * FROM audit_event WHERE workflow_id=? ORDER BY id", workflowId);
        long initialActions = count("action_request");
        int generation = integer(initialWorkflow, "generation");
        var attempts = new ArrayList<Attempt>();
        for (int i = 0; i < ATTEMPTS; i++)
            attempts.add(new Attempt(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID()));
        assertEquals(ATTEMPTS, new HashSet<>(attempts.stream().map(Attempt::actionId).toList()).size());
        assertEquals(ATTEMPTS, new HashSet<>(attempts.stream().map(Attempt::jobId).toList()).size());

        var ready = new CountDownLatch(ATTEMPTS);
        var start = new CountDownLatch(1);
        var pool = Executors.newFixedThreadPool(ATTEMPTS);
        List<Future<Map<String,Object>>> results = new ArrayList<>();
        try {
            for (var attempt : attempts) results.add(pool.submit(() -> {
                ready.countDown();
                assertTrue(start.await(20, TimeUnit.SECONDS), "Every contender must reach the start barrier");
                return tx.execute(status -> {
                    // Bound database waits too; a broken lock order must fail rather than hang CI.
                    db.jdbc().execute("SET LOCAL lock_timeout = '10s'");
                    db.jdbc().execute("SET LOCAL statement_timeout = '20s'");
                    db.gate();
                    db.lockWorkflow(workflowId);
                    db.update("""
                        INSERT INTO workflow_job(id,workflow_id,generation,phase,state,
                            execution_action_id,lease_token,lease_until,created_at,started_at)
                        VALUES(?,?,?,'PAY','RUNNING',?,?,?,?,?)
                        """, attempt.jobId(), workflowId, generation, attempt.actionId(), attempt.token(),
                        clock.now().plusSeconds(60), clock.now(), clock.now());
                    return paymentAgent.execute(attempt.jobId(), attempt.token());
                });
            }));
            assertTrue(ready.await(20, TimeUnit.SECONDS));
            start.countDown();
            for (int i = 0; i < ATTEMPTS; i++) {
                var response = results.get(i).get(30, TimeUnit.SECONDS);
                assertEquals(attempts.get(i).actionId(), response.get("requestId"));
                assertEquals(workflowId, response.get("workflowId"));
                assertEquals(generation, response.get("generation"));
                assertEquals("WAIT_APPROVAL", response.get("state"));
                assertEquals("WAIT_APPROVAL", response.get("decision"));
                assertEquals(List.of("APPROVAL_REQUIRED"), response.get("reasonCodes"));
                assertEquals(false, response.get("replayed"));
                assertFalse(response.containsKey("paymentId"));
                assertFalse(response.containsKey("reservationId"));
            }
        } finally {
            start.countDown();
            results.forEach(result -> result.cancel(true));
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "Payment contenders must terminate");
        }

        // Reads run after all futures/transactions complete, not against uncommitted worker state.
        assertEquals(initialAuthority, authorityRows(workflowId));
        assertEquals(initialActions, count("action_request"), "Approval waits do not create success/replay receipts");
        assertEquals(initialJobs.size() + ATTEMPTS, count("workflow_job"));
        assertEquals(initialAudits.size() + ATTEMPTS, count("audit_event"));
        for (var original : initialJobs)
            assertEquals(original, db.required("SELECT * FROM workflow_job WHERE id=?", original.get("id")));
        for (var original : initialAudits)
            assertEquals(original, db.required("SELECT * FROM audit_event WHERE id=?", original.get("id")));
        for (var attempt : attempts) assertRejectedJobAndAudit(workflowId, generation, attempt);
        var after = workflow(workflowId);
        assertEquals("WAIT_APPROVAL", after.get("state"));
        assertEquals("WAIT_APPROVAL", after.get("last_decision"));
        assertEquals("APPROVAL_REQUIRED", after.get("last_reason_code"));
        assertEquals(List.of("APPROVAL_REQUIRED"), json.map("{\"codes\":" + after.get("reason_codes") + "}").get("codes"));
        for (String field : List.of("id", "application_id", "generation", "root_authorization_id", "risk_ledger_id",
                "principal_id", "origin_intent", "policy_version", "current_kyc_result_id", "current_loan_result_id"))
            assertEquals(initialWorkflow.get(field), after.get(field), field);
        assertRisk(workflowId, 35, 0);
        assertEquals(0, events("RESERVE"));
        assertEquals(0, events("CONSUME"));
        assertEquals(0, events("RELEASE"));
        assertEquals(0, count("approval"));
        assertEquals(0, count("payment_reservation"));
        assertEquals(0, count("mock_payment"));

        // Positive control: the same workflow is still usable, but only with fresh real approval.
        var authorized = approve(workflowId);
        var receipt = paymentAgent.execute(authorized.jobId(), authorized.token());
        assertEquals("PAID", receipt.get("state"));
        assertEquals("ALLOW", receipt.get("decision"));
        assertEquals(List.of(), receipt.get("reasonCodes"));
        assertNotNull(receipt.get("paymentId"));
        assertEquals(1, count("mock_payment"));
        assertEquals(1, events("RESERVE"));
        assertEquals(1, events("CONSUME"));
        assertEquals(0, events("RELEASE"));
        assertRisk(workflowId, 85, 0);
        assertEquals("PAID", workflow(workflowId).get("state"));
        var payment = db.required("SELECT * FROM mock_payment WHERE workflow_id=?", workflowId);
        var reservation = db.required("SELECT * FROM payment_reservation WHERE id=?", payment.get("reservation_id"));
        assertEquals(authorized.jobId(), reservation.get("job_id"));
        assertEquals("COMMITTED", reservation.get("status"));
        assertEquals("CONSUMED", db.required("SELECT * FROM approval WHERE id=?", payment.get("approval_id")).get("status"));
        assertEquals("CONSUMED", db.required("SELECT * FROM delegation_grant WHERE id=?", reservation.get("grant_id")).get("status"));
        assertEquals("SUCCEEDED", db.required("SELECT * FROM workflow_job WHERE id=?", authorized.jobId()).get("state"));
        for (var attempt : attempts) {
            assertNotEquals(attempt.actionId(), payment.get("action_id"));
            assertRejectedJobAndAudit(workflowId, generation, attempt);
        }
    }

    private void assertRejectedJobAndAudit(UUID workflowId, int generation, Attempt attempt) {
        var job = db.required("SELECT * FROM workflow_job WHERE id=?", attempt.jobId());
        assertEquals(workflowId, job.get("workflow_id"));
        assertEquals(generation, job.get("generation"));
        assertEquals("PAY", job.get("phase"));
        assertEquals("FAILED", job.get("state"));
        assertEquals("APPROVAL_REQUIRED", job.get("last_error"));
        assertEquals(attempt.actionId(), job.get("execution_action_id"));
        assertEquals(attempt.token(), job.get("lease_token"));
        assertNull(job.get("approval_id"));
        assertNull(job.get("run_id"));
        assertNotNull(job.get("completed_at"));
        var audits = db.query("SELECT * FROM audit_event WHERE action_id=?", attempt.actionId());
        assertEquals(1, audits.size());
        var audit = audits.getFirst();
        assertEquals(workflowId, audit.get("workflow_id"));
        assertEquals("fuse-worker", audit.get("actor_id"));
        assertEquals("APPROVAL_WAITING", audit.get("event_type"));
        assertEquals("APPROVAL_REQUIRED", audit.get("reason_code"));
        assertNull(audit.get("run_id"));
        assertEquals(Map.of("jobId", attempt.jobId().toString()), json.map(str(audit, "details_json")));
        assertTrue(db.query("SELECT * FROM action_request WHERE action_id=?", attempt.actionId()).isEmpty());
    }

    private String authorityRows(UUID workflowId) {
        var rows = new LinkedHashMap<String,Object>();
        for (String table : List.of("agent_run", "agent_result", "delegation_grant", "approval",
                "payment_reservation", "mock_payment", "risk_ledger", "quarantine"))
            rows.put(table, db.query("SELECT * FROM " + table + " WHERE workflow_id=? ORDER BY id", workflowId));
        rows.put("stages", db.query("SELECT * FROM workflow_stage WHERE workflow_id=? ORDER BY stage", workflowId));
        rows.put("dependencies", db.query("SELECT * FROM run_dependency WHERE workflow_id=? ORDER BY parent_run_id,child_run_id", workflowId));
        return json.write(rows);
    }

    private record Attempt(UUID jobId, UUID actionId, UUID token) {}
}
