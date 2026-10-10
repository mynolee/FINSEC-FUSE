package com.finsec.fuse.integration;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.config.DemoSeed;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.persistence.DatabaseTimeSource;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.persistence.MutableTimeSource;
import com.finsec.fuse.persistence.TimeSource;
import com.finsec.fuse.testing.PostgresSupport;
import com.finsec.fuse.workflow.JobTransactions;
import com.finsec.fuse.workflow.StartWorkflowRequest;
import com.finsec.fuse.workflow.WorkflowService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Bounded SC-T24-B03 authority-clock calibration, complementary to synthetic lease boundaries.
 * Deliberately does not extend FuseIntegrationTest: its test profile excludes DatabaseTimeSource.
 * The demo profile retains normal service injection, transactions and production clock selection.
 * Raw JDBC probes use a separate connection to the same ephemeral PostgreSQL clock. They are
 * independent of TimeSource/Db code, NOT an independent wall-clock or NTP calibration oracle.
 * Fixed Java clocks below are counterfactuals, not an altered JVM/OS clock or injected authority.
 * Reaping covers a claimed, unprepared KYC job (no agent run), not active-run termination.
 * No equality-at-a-moving-clock assertion, provider call, real payment, or OS clock change.
 */
@SpringBootTest(classes=FuseApplication.class, webEnvironment=SpringBootTest.WebEnvironment.MOCK,
        properties={"fuse.demo-seed=true", "fuse.kyc-mode=replay", "fuse.worker-enabled=false"})
@ActiveProfiles("demo")
@Timeout(30)
class DatabaseAuthorityClockIT {
    @DynamicPropertySource
    static void postgres(DynamicPropertyRegistry registry) {
        PostgresSupport.properties(registry);
        registry.add("FUSE_SIGNING_KEY_PATH", () -> EphemeralKey.PATH.toString());
        registry.add("FUSE_VERIFY_KEYS", () -> "");
        registry.add("FUSE_SIGNING_KEY_ID", () -> "clock-it");
    }

    // Local throwaway mock signing material only; never publish, log or reuse a real credential.
    private static final class EphemeralKey {
        static final Path PATH = create();
        private static Path create() {
            try {
                Path path = Files.createTempFile("fuse-clock-it-", ".key",
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                path.toFile().deleteOnExit();
                byte[] bytes = new byte[32];
                new SecureRandom().nextBytes(bytes);
                Files.write(path, bytes);
                return path;
            } catch (java.io.IOException failure) {
                throw new ExceptionInInitializerError(failure);
            }
        }
    }

    @Autowired Db db;
    @Autowired DataSource dataSource;
    @Autowired TimeSource authority;
    @Autowired ApplicationContext context;
    @Autowired TransactionTemplate tx;
    @Autowired DemoSeed seed;
    @Autowired WorkflowService workflows;
    @Autowired JobTransactions jobs;
    @Autowired FusePolicy policy;

    @BeforeEach
    void resetOnlyEphemeralDatabaseAndVerifyProductionClock() throws Exception {
        try (var connection = dataSource.getConnection()) {
            assertEquals(PostgresSupport.url(), connection.getMetaData().getURL(),
                    "Refuse schema reset outside this harness's ephemeral PostgreSQL");
        }
        assertInstanceOf(DatabaseTimeSource.class, authority);
        assertEquals(1, context.getBeansOfType(TimeSource.class).size());
        assertTrue(context.getBeansOfType(MutableTimeSource.class).isEmpty());
        db.jdbc().execute("DROP SCHEMA public CASCADE");
        db.jdbc().execute("CREATE SCHEMA public");
        Flyway.configure().dataSource(dataSource).locations("classpath:db/migration").load().migrate();
        PostgresSupport.initializeAuth(dataSource, context.getEnvironment());
        seed.run(null);
    }

    @Test
    void authorityAdvancesInsideOneLockedTransactionWhileTransactionTimestampIsFrozen() {
        tx.executeWithoutResult(status -> {
            db.gate();
            long transactionId = db.jdbc().queryForObject("SELECT txid_current()", Long.class);
            Instant transactionTime = transactionTime();
            Instant first = bracketedAuthority();
            Instant later = first;
            // Bounded round trips allow database clock resolution to advance without fixed sleeps.
            // A transaction_timestamp()/now() regression remains frozen and fails this control.
            for (int attempt = 0; attempt < 1000 && !later.isAfter(first); attempt++) {
                later = bracketedAuthority();
            }
            assertTrue(later.isAfter(first), "Production authority must advance inside the transaction");
            assertEquals(transactionTime, transactionTime());
            assertEquals(transactionId, db.jdbc().queryForObject("SELECT txid_current()", Long.class));
            assertFalse(first.isBefore(transactionTime));
        });
    }

    @Test
    void productionClaimIssuesItsLeaseFromBracketedDatabaseTime() {
        UUID workflowId = start();
        Instant before = rawDatabaseNow();
        var lease = jobs.claim().orElseThrow();
        Instant after = rawDatabaseNow();
        assertEquals(workflowId, lease.workflowId());
        assertEquals("KYC", lease.phase());
        var row = db.required("SELECT * FROM workflow_job WHERE id=?", lease.jobId());
        Instant started = Db.instant(row, "started_at");
        assertBetween(started, before, after);
        assertEquals(started.plusSeconds(policy.leaseSeconds()), Db.instant(row, "lease_until"));
        assertEquals("RUNNING", row.get("state"));
        assertEquals(lease.token(), row.get("lease_token"));
        assertTrue(jobs.expired().stream().noneMatch(job -> lease.jobId().equals(job.get("id"))));
    }

    @ParameterizedTest(name="controlled lease is expired by database={0}")
    @ValueSource(booleans={false, true})
    void expiryAndReapingFollowDatabaseDespiteOppositeCounterfactualJavaClock(boolean expired) {
        UUID workflowId = start();
        var lease = jobs.claim().orElseThrow();
        Instant databaseAnchor = rawDatabaseNow();
        Instant deadline = databaseAnchor.plus(Duration.ofDays(expired ? -1 : 1));
        Clock counterfactualApplicationClock = Clock.fixed(
                databaseAnchor.plus(Duration.ofDays(expired ? -2 : 2)), ZoneOffset.UTC);
        // Controlled fixture deadline only; issuance from the real service is tested separately.
        tx.executeWithoutResult(status -> {
            db.gate();
            db.lockWorkflow(workflowId);
            assertEquals(1, db.update("UPDATE workflow_job SET lease_until=? WHERE id=?", deadline, lease.jobId()));
        });
        assertEquals(!expired, !counterfactualApplicationClock.instant().isBefore(deadline),
                "The Java-clock counterfactual must predict the opposite expiry result");
        assertEquals(expired, !rawDatabaseNow().isBefore(deadline));
        assertEquals(expired, jobs.expired().stream().anyMatch(job -> lease.jobId().equals(job.get("id"))));
        var beforeJob = db.required("SELECT * FROM workflow_job WHERE id=?", lease.jobId());
        assertNull(beforeJob.get("run_id"), "This proof covers the claimed, unprepared job");
        var beforeWorkflow = db.required("SELECT * FROM workflow WHERE id=?", workflowId);
        var beforeAudits = db.query("SELECT to_jsonb(a)::text AS row FROM audit_event a ORDER BY id");
        Instant before = rawDatabaseNow();
        jobs.reapNonPayment(lease.jobId());
        Instant after = rawDatabaseNow();
        var afterJob = db.required("SELECT * FROM workflow_job WHERE id=?", lease.jobId());
        var afterWorkflow = db.required("SELECT * FROM workflow WHERE id=?", workflowId);
        if (expired) {
            assertEquals("FAILED", afterJob.get("state"));
            assertEquals("DEPENDENCY_UNAVAILABLE", afterJob.get("last_error"));
            assertBetween(Db.instant(afterJob, "completed_at"), before, after);
            assertEquals("ON_HOLD", afterWorkflow.get("state"));
            assertEquals("ERROR", afterWorkflow.get("last_decision"));
            assertEquals("DEPENDENCY_UNAVAILABLE", afterWorkflow.get("last_reason_code"));
            Instant completed = Db.instant(afterJob, "completed_at");
            assertEquals(completed, Db.instant(afterWorkflow, "updated_at"));
            var afterAudits = db.query("SELECT to_jsonb(a)::text AS row FROM audit_event a ORDER BY id");
            assertEquals(beforeAudits.size() + 2, afterAudits.size());
            assertTrue(afterAudits.containsAll(beforeAudits), "Reaping must preserve old audit rows");
            var reapAudits = db.query("SELECT * FROM audit_event WHERE workflow_id=? AND event_type IN ('WORKFLOW_STATE_CHANGED','SYSTEM_ERROR')", workflowId);
            assertEquals(2, reapAudits.size());
            assertEquals(Set.of("WORKFLOW_STATE_CHANGED", "SYSTEM_ERROR"),
                    reapAudits.stream().map(row -> row.get("event_type")).collect(java.util.stream.Collectors.toSet()));
            for (var audit : reapAudits) {
                assertEquals("DEPENDENCY_UNAVAILABLE", audit.get("reason_code"));
                assertEquals(completed, Db.instant(audit, "created_at"));
            }
            assertTrue(jobs.expired().stream().noneMatch(job -> lease.jobId().equals(job.get("id"))));
        } else {
            assertEquals(beforeJob, afterJob, "A database-live lease cannot be reaped");
            assertEquals(beforeWorkflow, afterWorkflow);
            assertEquals(beforeAudits, db.query("SELECT to_jsonb(a)::text AS row FROM audit_event a ORDER BY id"),
                    "A database-live lease cannot append reaper audits");
        }
        assertEquals(expired, !rawDatabaseNow().isBefore(deadline), "Control remains far from moving boundary");
    }

    private UUID start() {
        return (UUID) workflows.start(new Actor("customer-102", "CUSTOMER", Set.of("customer-102")),
                UUID.randomUUID(), new StartWorkflowRequest("APP-DEMO-102-001", "customer-102", 1000000L,
                        UUID.fromString("00000000-0000-4000-8000-000000000102"))).get("workflowId");
    }

    private Instant transactionTime() {
        return db.jdbc().queryForObject("SELECT transaction_timestamp()", Timestamp.class).toInstant();
    }

    private Instant bracketedAuthority() {
        Instant before = rawDatabaseNow();
        Instant result = authority.now();
        Instant after = rawDatabaseNow();
        assertBetween(result, before, after);
        return result;
    }

    private Instant rawDatabaseNow() {
        // DataSource.getConnection, not DataSourceUtils/JdbcTemplate: no transaction-bound reuse.
        try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
            statement.setQueryTimeout(5);
            try (var result = statement.executeQuery("SELECT clock_timestamp()")) {
                assertTrue(result.next());
                return result.getTimestamp(1).toInstant();
            }
        } catch (SQLException failure) {
            throw new AssertionError("Independent JDBC clock probe failed", failure);
        }
    }

    private void assertBetween(Instant value, Instant before, Instant after) {
        assertNotNull(value);
        assertFalse(value.isBefore(before), "Timestamp precedes independent database lower bound");
        assertFalse(value.isAfter(after), "Timestamp exceeds independent database upper bound");
    }
}
