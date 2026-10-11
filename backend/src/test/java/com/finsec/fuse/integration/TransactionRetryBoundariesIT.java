package com.finsec.fuse.integration;

import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.testing.PostgresSupport;
import com.finsec.fuse.workflow.JobTransactions;
import com.finsec.fuse.workflow.TransactionRetries;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import static org.junit.jupiter.api.Assertions.*;

/**
 * SC-T18-B08: real PostgreSQL contention induced by a TEST-ONLY late audit trigger.
 * Production retry component and transactional service proxies are unmodified. This is
 * not a claim that the artificial fixture row/trigger exists in production, nor a test
 * of natural deadlocks, serialization failures, network loss, or the worker scheduler.
 * The inherited clock is fixed: retries never renew a lease or refresh authority.
 */
@Timeout(40)
class TransactionRetryBoundariesIT extends PaymentFixture {
    @Autowired TransactionRetries retries;

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void kycLateWritesRollBackThenSucceedWithinTwoRetries(int failuresBeforeRelease) throws Exception {
        UUID workflowId = start("customer-102");
        var lease = jobs.claim().orElseThrow();
        UUID action = action(lease);
        var now = clock.now();
        String before = snapshot(workflowId);
        var attempts = new AtomicInteger();
        var failures = new AtomicInteger();
        try (var contention = new AuditContention("DELEGATION_ALLOWED")) {
            var prepared = retries.run(() -> {
                attempts.incrementAndGet();
                assertIdentity(lease, action);
                try {
                    return kyc.prepare(lease.jobId(), lease.token()).orElseThrow();
                } catch (PessimisticLockingFailureException failure) {
                    assertActualLockRollback(failure);
                    assertEquals(before, snapshot(workflowId), "All late KYC writes must roll back before retry");
                    if (failures.incrementAndGet() == failuresBeforeRelease) contention.release();
                    throw failure;
                }
            });
            assertEquals(failuresBeforeRelease + 1, attempts.get());
            assertEquals(failuresBeforeRelease, failures.get());
            assertEquals(action, prepared.input().requestId());
            assertEquals(lease.token(), prepared.leaseToken());
            assertIdentity(lease, action);
            assertEquals(now, clock.now(), "No silent lease/authority refresh during retry waits");
            assertRisk(workflowId, 10, 0);
            assertEquals(1, count("agent_run"));
            assertEquals(1, count("delegation_grant"));
            assertEquals(1, events("CHARGE"));
            assertEquals(1, audit(action, "RISK_CHARGED"));
            assertEquals(1, audit(action, "DELEGATION_ALLOWED"));
            assertEquals(0, count("payment_reservation"));
            assertEquals(0, count("mock_payment"));
            String completed = snapshot(workflowId);
            assertTrue(kyc.prepare(lease.jobId(), lease.token()).isEmpty());
            assertEquals(completed, snapshot(workflowId), "Repeated prepare cannot duplicate charge/run/audit effects");
        }
    }

    @Test
    void permanentContentionStopsAfterInitialAttemptAndExactlyTwoRetries() throws Exception {
        UUID workflowId = start("customer-102");
        var lease = jobs.claim().orElseThrow();
        UUID action = action(lease);
        String before = snapshot(workflowId);
        var attempts = new AtomicInteger();
        var failures = new AtomicInteger();
        try (var contention = new AuditContention("DELEGATION_ALLOWED")) {
            assertThrows(PessimisticLockingFailureException.class, () -> retries.run(() -> {
                attempts.incrementAndGet();
                assertIdentity(lease, action);
                try {
                    return kyc.prepare(lease.jobId(), lease.token());
                } catch (PessimisticLockingFailureException failure) {
                    failures.incrementAndGet();
                    assertActualLockRollback(failure);
                    assertEquals(before, snapshot(workflowId));
                    throw failure;
                }
            }));
            assertEquals(3, attempts.get(), "Initial call plus at most two retries, never a fourth call");
            assertEquals(3, failures.get(), "Every attempt must actually fail on PostgreSQL contention");
            assertEquals(before, snapshot(workflowId));
            assertIdentity(lease, action);
            assertRisk(workflowId, 0, 0);
            assertEquals(0, count("agent_run"));
            assertEquals(0, count("risk_ledger"));
            assertEquals(0, count("payment_reservation"));
            assertEquals(0, count("mock_payment"));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"PAYMENT_RESERVED", "PAYMENT_COMMITTED"})
    void paymentRollbackBoundaryNeverDuplicatesReservationChargeReceiptOrAudit(String blockedEvent) throws Exception {
        UUID workflowId = ready102();
        var lease = approve(workflowId);
        UUID action = action(lease);
        String before = snapshot(workflowId);
        var now = clock.now();
        var reserved = new AtomicReference<String>();
        var reservationId = new AtomicReference<UUID>();
        var reservationVisits = new AtomicInteger();
        var attempts = new AtomicInteger();
        var failures = new AtomicInteger();
        // This hook executes only after the real reservation transaction has committed.
        hooks.onAfterReservation(() -> {
            reservationVisits.incrementAndGet();
            String current = snapshot(workflowId);
            UUID id = (UUID) db.required("SELECT id FROM payment_reservation WHERE execution_action_id=?", action).get("id");
            if (reserved.get() == null) {
                reserved.set(current);
                reservationId.set(id);
            } else {
                assertEquals(reserved.get(), current, "Retried execute must reuse the identical durable reservation");
                assertEquals(reservationId.get(), id);
            }
            assertRisk(workflowId, 35, 50);
            assertEquals(1, events("RESERVE"));
            assertEquals(0, events("CONSUME"));
        });
        try (var contention = new AuditContention(blockedEvent)) {
            var receipt = retries.run(() -> {
                attempts.incrementAndGet();
                assertIdentity(lease, action);
                try {
                    return paymentAgent.execute(lease.jobId(), lease.token());
                } catch (PessimisticLockingFailureException failure) {
                    assertActualLockRollback(failure);
                    if ("PAYMENT_COMMITTED".equals(blockedEvent)) {
                        assertNotNull(reserved.get(), "Commit contention must occur after a durable reservation");
                        assertEquals(reserved.get(), snapshot(workflowId), "Final commit writes must all roll back");
                        assertEquals(1, count("payment_reservation"));
                        assertEquals(1, events("RESERVE"));
                    } else {
                        assertNull(reserved.get(), "Failed reservation must never escape its transaction");
                        assertEquals(before, snapshot(workflowId));
                        assertEquals(0, count("payment_reservation"));
                        assertEquals(0, events("RESERVE"));
                    }
                    assertEquals(0, actionCount(action));
                    assertEquals(0, count("mock_payment"));
                    assertEquals(0, events("CONSUME"));
                    assertEquals(0, audit(action, "PAYMENT_COMMITTED"));
                    if (failures.incrementAndGet() == 2) contention.release();
                    throw failure;
                }
            });
            assertEquals(3, attempts.get());
            assertEquals(2, failures.get());
            assertEquals("PAYMENT_COMMITTED".equals(blockedEvent) ? 3 : 1, reservationVisits.get());
            assertEquals("PAID", receipt.get("state"));
            assertIdentity(lease, action);
            assertEquals(now, clock.now());
            assertRisk(workflowId, 85, 0);
            assertEquals(1, count("payment_reservation"));
            assertEquals(1, count("mock_payment"));
            assertEquals(1, actionCount(action));
            assertEquals(1, events("RESERVE"));
            assertEquals(1, events("CONSUME"));
            assertEquals(2, events("CHARGE"), "Exactly one original KYC and one original loan charge");
            assertEquals(0, events("RELEASE"));
            var stage = db.required("SELECT * FROM workflow_stage WHERE workflow_id=? AND stage='PAYMENT'", workflowId);
            assertEquals(1, ((Number) stage.get("run_count")).intValue());
            assertEquals(50, ((Number) stage.get("used_points")).intValue());
            assertEquals(0, ((Number) stage.get("reserved_points")).intValue());
            assertEquals(1, audit(action, "PAYMENT_RESERVED"));
            assertEquals(1, audit(action, "PAYMENT_COMMITTED"));
            assertEquals(1, ((Number) db.required("SELECT count(*) n FROM agent_run WHERE action_id=?", action).get("n")).intValue());
            assertEquals(reservationId.get(), db.required("SELECT reservation_id FROM mock_payment WHERE action_id=?", action).get("reservation_id"));
            String committed = snapshot(workflowId);
            hooks.reset();
            assertEquals("PAID", paymentAgent.execute(lease.jobId(), lease.token()).get("state"));
            assertEquals(committed, snapshot(workflowId), "Explicit identical replay must have no durable effect");
        } finally {
            hooks.reset();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void injectedUnknownCommitClassificationNeverRetriesEvenAfterRealPaymentCommit(boolean transactionException) {
        // Classification-only negative control, not a real lost JDBC acknowledgement.
        // PaymentCommitAcknowledgementIT separately covers JDBC post-commit fault injection.
        UUID workflowId = ready102();
        var lease = approve(workflowId);
        UUID action = action(lease);
        var attempts = new AtomicInteger();
        var committed = new AtomicReference<String>();
        RuntimeException unknown = transactionException
            ? new TransactionSystemException("Injected unknown commit outcome", new SQLException("Injected acknowledgement failure", "08006"))
            : new DataAccessResourceFailureException("Injected unknown commit outcome", new SQLException("Injected connection failure", "08006"));
        var thrown = assertThrows(RuntimeException.class, () -> retries.run((Runnable) () -> {
            attempts.incrementAndGet();
            assertEquals("PAID", paymentAgent.execute(lease.jobId(), lease.token()).get("state"));
            committed.set(snapshot(workflowId));
            throw unknown;
        }));
        assertSame(unknown, thrown);
        assertEquals(1, attempts.get(), "Unknown commit outcomes are explicitly nonretryable");
        assertNotNull(committed.get());
        assertEquals(committed.get(), snapshot(workflowId));
        assertIdentity(lease, action);
        assertEquals(1, actionCount(action));
        assertEquals(1, count("mock_payment"));
        assertEquals(1, count("payment_reservation"));
        assertEquals(1, events("RESERVE"));
        assertEquals(1, events("CONSUME"));
        assertEquals(1, audit(action, "PAYMENT_COMMITTED"));
        assertRisk(workflowId, 85, 0);
    }

    private UUID action(JobTransactions.Lease lease) {
        return (UUID) db.required("SELECT execution_action_id FROM workflow_job WHERE id=?", lease.jobId()).get("execution_action_id");
    }

    private void assertIdentity(JobTransactions.Lease lease, UUID action) {
        var job = db.required("SELECT * FROM workflow_job WHERE id=?", lease.jobId());
        assertEquals(action, job.get("execution_action_id"));
        assertEquals(lease.token(), job.get("lease_token"));
        assertEquals(lease.generation(), ((Number) job.get("generation")).intValue());
        assertTrue(clock.now().isBefore(com.finsec.fuse.persistence.Db.instant(job, "lease_until")));
    }

    private long actionCount(UUID action) {
        return ((Number) db.required("SELECT count(*) n FROM action_request WHERE action_id=?", action).get("n")).longValue();
    }

    private long audit(UUID action, String event) {
        return ((Number) db.required("SELECT count(*) n FROM audit_event WHERE action_id=? AND event_type=?", action, event).get("n")).longValue();
    }

    private void assertActualLockRollback(PessimisticLockingFailureException failure) {
        assertFalse(TransactionSynchronizationManager.isActualTransactionActive(), "Proxy must roll back before wrapper retries");
        Throwable cause = failure;
        while (cause != null && !(cause instanceof SQLException)) cause = cause.getCause();
        var sql = assertInstanceOf(SQLException.class, cause, "No synthetic Spring locking exceptions allowed");
        assertEquals("55P03", sql.getSQLState(), "Actual PostgreSQL lock_not_available must cause the retry");
        assertTrue(sql.getMessage().contains("lock timeout"));
        assertTrue(sql.getMessage().contains("retry_boundary_audit_gate"), "Failure must originate in the late audit fixture");
    }

    /** Fresh observer connection, never the application's aborted or thread-bound transaction. */
    private String snapshot(UUID workflowId) {
        Map<String, String> rows = new LinkedHashMap<>();
        try (var observer = DriverManager.getConnection(PostgresSupport.url(), "postgres", "")) {
            assertTrue(observer.getAutoCommit());
            try (var statement = observer.createStatement()) { statement.execute("SET statement_timeout='5s'"); }
            for (String table : List.of("workflow", "workflow_job", "workflow_stage", "agent_run", "agent_result",
                    "delegation_grant", "run_dependency", "approval", "payment_reservation", "mock_payment", "risk_ledger", "action_request", "audit_event")) {
                String key = "workflow".equals(table) ? "id" : "workflow_id";
                try (var query = observer.prepareStatement("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM " + table + " t WHERE " + key + "=?")) {
                    query.setObject(1, workflowId);
                    try (var result = query.executeQuery()) { assertTrue(result.next()); rows.put(table, result.getString(1)); }
                }
            }
            return rows.toString();
        } catch (SQLException failure) { throw new AssertionError("Independent rollback snapshot failed", failure); }
    }

    /** A second PostgreSQL backend owns a real row lock throughout each failed transaction. */
    private final class AuditContention implements AutoCloseable {
        private Connection blocker;

        AuditContention(String event) throws SQLException {
            assertTrue(List.of("DELEGATION_ALLOWED", "PAYMENT_RESERVED", "PAYMENT_COMMITTED").contains(event));
            assertEquals("2s", db.required("SHOW lock_timeout").get("lock_timeout"));
            assertEquals("5s", db.required("SHOW statement_timeout").get("statement_timeout"));
            try {
                db.jdbc().execute("CREATE TABLE retry_boundary_lock(id integer PRIMARY KEY)");
                db.jdbc().execute("INSERT INTO retry_boundary_lock VALUES(1)");
                db.jdbc().execute("""
                    CREATE FUNCTION retry_boundary_audit_gate() RETURNS trigger LANGUAGE plpgsql AS $$
                    BEGIN
                        PERFORM id FROM retry_boundary_lock WHERE id=1 FOR UPDATE;
                        RETURN NEW;
                    END $$
                    """);
                db.jdbc().execute("CREATE TRIGGER retry_boundary_audit AFTER INSERT ON audit_event FOR EACH ROW WHEN (NEW.event_type='" + event + "') EXECUTE FUNCTION retry_boundary_audit_gate()");
                blocker = DriverManager.getConnection(PostgresSupport.url(), "postgres", "");
                try (var statement = blocker.createStatement()) {
                    statement.execute("SET statement_timeout='5s'");
                    statement.execute("SET idle_in_transaction_session_timeout='30s'");
                }
                blocker.setAutoCommit(false);
                try (var statement = blocker.createStatement();
                     var row = statement.executeQuery("SELECT id FROM retry_boundary_lock WHERE id=1 FOR UPDATE")) {
                    assertTrue(row.next());
                }
                try (var statement = blocker.createStatement(); var row = statement.executeQuery("SELECT count(*) FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='transactionid' AND mode='ExclusiveLock' AND granted")) {
                    assertTrue(row.next());
                    assertEquals(1, row.getInt(1), "Positive control: real blocker transaction owns its row-lock transaction ID");
                }
            } catch (SQLException | RuntimeException | AssertionError failure) {
                try { close(); } catch (Exception cleanup) { failure.addSuppressed(cleanup); }
                throw failure;
            }
        }

        void release() {
            try { if (blocker != null) blocker.rollback(); }
            catch (SQLException failure) { throw new AssertionError("Could not release actual PostgreSQL blocker", failure); }
        }

        @Override public void close() throws SQLException {
            try {
                if (blocker != null) {
                    try { blocker.rollback(); } finally { blocker.close(); blocker = null; }
                }
            } finally {
                try { db.jdbc().execute("DROP TRIGGER IF EXISTS retry_boundary_audit ON audit_event"); }
                finally {
                    try { db.jdbc().execute("DROP FUNCTION IF EXISTS retry_boundary_audit_gate()"); }
                    finally { db.jdbc().execute("DROP TABLE IF EXISTS retry_boundary_lock"); }
                }
            }
        }
    }
}
