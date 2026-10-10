package com.finsec.fuse.integration;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.config.DemoSeed;
import com.finsec.fuse.persistence.DatabaseTimeSource;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.persistence.MutableTimeSource;
import com.finsec.fuse.persistence.TimeSource;
import com.finsec.fuse.testing.PostgresSupport;
import com.finsec.fuse.workflow.JobTransactions;
import com.finsec.fuse.workflow.KycContract;
import com.finsec.fuse.workflow.KycTransactions;
import com.finsec.fuse.workflow.StartWorkflowRequest;
import com.finsec.fuse.workflow.WorkflowService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SC-T24-B03: actual prepared KYC completion/reaping under the production DatabaseTimeSource.
 * Complements V21StaleCompletionIT's deterministic 89/90/91-second boundary proof. Controlled
 * lease deadlines are a full day away from the moving database clock; this is not an equality
 * boundary or independent wall-clock calibration. Raw JDBC brackets bypass TimeSource and Db.
 * Responses are valid bound synthetic proposals; no provider, transport fault, GPU, or OS/JVM
 * clock change is involved. The demo profile intentionally avoids the mutable test clock.
 */
@SpringBootTest(classes=FuseApplication.class, webEnvironment=SpringBootTest.WebEnvironment.MOCK,
        properties={"fuse.demo-seed=true", "fuse.kyc-mode=replay", "fuse.worker-enabled=false"})
@ActiveProfiles("demo")
@Timeout(30)
class DatabaseClockKycCompletionIT {
    @DynamicPropertySource
    static void postgres(DynamicPropertyRegistry registry) {
        PostgresSupport.properties(registry);
        registry.add("FUSE_SIGNING_KEY_PATH", () -> EphemeralKey.PATH.toString());
        registry.add("FUSE_VERIFY_KEYS", () -> "");
        registry.add("FUSE_SIGNING_KEY_ID", () -> "kyc-clock-it");
    }

    private static final class EphemeralKey {
        static final Path PATH = create();
        private static Path create() {
            try {
                Path path = Files.createTempFile("fuse-kyc-clock-it-", ".key",
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
    @Autowired KycTransactions kyc;

    @BeforeEach
    void resetEphemeralDatabaseWithProductionClock() throws Exception {
        try (var connection = dataSource.getConnection()) {
            assertEquals(PostgresSupport.url(), connection.getMetaData().getURL(),
                    "Refuse schema reset outside the harness's ephemeral PostgreSQL");
        }
        assertInstanceOf(DatabaseTimeSource.class, authority);
        assertSame(authority, context.getBean("databaseTimeSource"));
        assertEquals(1, context.getBeansOfType(TimeSource.class).size());
        assertTrue(context.getBeansOfType(MutableTimeSource.class).isEmpty());
        db.jdbc().execute("DROP SCHEMA public CASCADE");
        db.jdbc().execute("CREATE SCHEMA public");
        Flyway.configure().dataSource(dataSource).locations("classpath:db/migration").load().migrate();
        PostgresSupport.initializeAuth(dataSource, context.getEnvironment());
        seed.run(null);
    }

    @Test
    void liveActiveLeaseAcceptsExactlyOneResultAndSuccessorPreservingItsCharge() {
        var prepared = startAndPrepare("102");
        UUID independent = populateIndependentWorkflow();
        var independentBefore = workflowRows(independent);
        setDeadline(prepared, false);
        var liveBefore = allBusinessRows();
        var liveAuditsBefore = rows("audit_event");
        jobs.reapNonPayment(prepared.jobId());
        assertEquals(liveBefore, allBusinessRows(), "A live active run must not be reaped");
        assertEquals(liveAuditsBefore, rows("audit_event"));
        var riskBefore = rows("risk_ledger");
        var stageBefore = rows("workflow_stage");
        var auditsBefore = rows("audit_event");
        Instant before = rawDatabaseNow();
        kyc.apply(prepared, verified(prepared));
        Instant after = rawDatabaseNow();

        UUID workflowId = prepared.input().workflowId();
        var workflow = workflow(workflowId);
        var result = db.required("SELECT * FROM agent_result WHERE workflow_id=?", workflowId);
        var run = db.required("SELECT * FROM agent_run WHERE id=?", prepared.input().runId());
        var job = db.required("SELECT * FROM workflow_job WHERE id=?", prepared.jobId());
        var successor = db.required("SELECT * FROM workflow_job WHERE workflow_id=? AND phase='LOAN'", workflowId);
        assertEquals("KYC_VALIDATED", workflow.get("state"));
        assertEquals(result.get("id"), workflow.get("current_kyc_result_id"));
        assertEquals("VALIDATED", result.get("status"));
        assertEquals(prepared.input().runId(), result.get("run_id"));
        assertEquals("VALIDATED", run.get("status"));
        assertEquals("SUCCEEDED", job.get("state"));
        assertEquals("PENDING", successor.get("state"));
        assertEquals(2, db.query("SELECT id FROM workflow_job WHERE workflow_id=?", workflowId).size());
        Instant completed = Db.instant(job, "completed_at");
        assertBetween(completed, before, after);
        assertEquals(completed, Db.instant(run, "completed_at"));
        assertEquals(completed, Db.instant(result, "created_at"));
        assertEquals(completed, Db.instant(workflow, "updated_at"));
        assertEquals(completed, Db.instant(successor, "created_at"));
        var completionAudits = addedAudits(auditsBefore);
        assertEquals(3, completionAudits.size());
        assertEquals(Set.of("KYC_PROPOSED", "WORKFLOW_STATE_CHANGED", "EVIDENCE_VALIDATED"),
                completionAudits.stream().map(row -> row.get("event_type")).collect(java.util.stream.Collectors.toSet()));
        assertTrue(rows("mock_payment").isEmpty());
        for (var audit : completionAudits) assertBetween(auditTime(audit), before, after);
        assertEquals(riskBefore, rows("risk_ledger"));
        assertEquals(stageBefore, rows("workflow_stage"));
        assertChargedOnce(prepared);
        assertEquals(independentBefore, workflowRows(independent));
        // Includes an already populated current result pointer and successor in the snapshot.
        assertOnlyDiscard(prepared);
    }

    @Test
    void expiredActiveLeaseOnlyAppendsDiscardWithoutReapingOrOverwritingOtherCurrentResult() {
        var prepared = startAndPrepare("102");
        populateIndependentWorkflow();
        setDeadline(prepared, true);
        assertTrue(jobs.expired().stream().anyMatch(row -> prepared.jobId().equals(row.get("id"))));
        assertOnlyDiscard(prepared);
        assertEquals("RUNNING", db.required("SELECT status FROM agent_run WHERE id=?", prepared.input().runId()).get("status"));
        assertEquals("RUNNING", db.required("SELECT state FROM workflow_job WHERE id=?", prepared.jobId()).get("state"));
        assertEquals("KYC_PENDING", workflow(prepared.input().workflowId()).get("state"));
        assertChargedOnce(prepared);
    }

    @Test
    void reapingTerminatesActiveRunAndLaterCompletionOnlyAppendsDiscard() {
        var prepared = startAndPrepare("102");
        UUID independent = populateIndependentWorkflow();
        var independentBefore = workflowRows(independent);
        setDeadline(prepared, true);
        var riskBefore = rows("risk_ledger");
        var stageBefore = rows("workflow_stage");
        var resultsBefore = rows("agent_result");
        var grantsBefore = rows("delegation_grant");
        var auditsBefore = rows("audit_event");
        Instant before = rawDatabaseNow();
        jobs.reapNonPayment(prepared.jobId());
        Instant after = rawDatabaseNow();
        var job = db.required("SELECT * FROM workflow_job WHERE id=?", prepared.jobId());
        var run = db.required("SELECT * FROM agent_run WHERE id=?", prepared.input().runId());
        var workflow = workflow(prepared.input().workflowId());
        assertEquals("FAILED", job.get("state"));
        assertEquals("DEPENDENCY_UNAVAILABLE", job.get("last_error"));
        assertEquals("FAILED", run.get("status"));
        assertEquals("ON_HOLD", workflow.get("state"));
        assertEquals("ERROR", workflow.get("last_decision"));
        assertEquals("DEPENDENCY_UNAVAILABLE", workflow.get("last_reason_code"));
        assertNull(workflow.get("current_kyc_result_id"));
        assertEquals(1, db.query("SELECT id FROM workflow_job WHERE workflow_id=?", prepared.input().workflowId()).size());
        Instant completed = Db.instant(job, "completed_at");
        assertBetween(completed, before, after);
        assertEquals(completed, Db.instant(run, "completed_at"));
        assertEquals(completed, Db.instant(workflow, "updated_at"));
        var reapAudits = addedAudits(auditsBefore);
        assertEquals(2, reapAudits.size());
        assertEquals(Set.of("WORKFLOW_STATE_CHANGED", "SYSTEM_ERROR"),
                reapAudits.stream().map(row -> row.get("event_type")).collect(java.util.stream.Collectors.toSet()));
        for (var audit : reapAudits) assertEquals("DEPENDENCY_UNAVAILABLE", audit.get("reason_code"));
        for (var audit : reapAudits) assertBetween(auditTime(audit), before, after);
        assertEquals(riskBefore, rows("risk_ledger"));
        assertEquals(stageBefore, rows("workflow_stage"));
        assertEquals(resultsBefore, rows("agent_result"));
        assertEquals(grantsBefore, rows("delegation_grant"));
        assertEquals(independentBefore, workflowRows(independent));
        assertTrue(jobs.expired().stream().noneMatch(row -> prepared.jobId().equals(row.get("id"))));
        assertOnlyDiscard(prepared);
        assertChargedOnce(prepared);
    }

    private KycContract.Prepared startAndPrepare(String suffix) {
        String customer = "customer-" + suffix;
        UUID workflowId = (UUID) workflows.start(new Actor(customer, "CUSTOMER", Set.of(customer)),
                UUID.randomUUID(), new StartWorkflowRequest("APP-DEMO-" + suffix + "-001", customer,
                        1000000L, UUID.fromString("00000000-0000-4000-8000-000000000" + suffix))).get("workflowId");
        var lease = jobs.claim().orElseThrow();
        assertEquals(workflowId, lease.workflowId());
        assertEquals("KYC", lease.phase());
        var prepared = kyc.prepare(lease.jobId(), lease.token()).orElseThrow();
        assertEquals("RUNNING", db.required("SELECT status FROM agent_run WHERE id=?", prepared.input().runId()).get("status"));
        assertChargedOnce(prepared);
        return prepared;
    }

    private UUID populateIndependentWorkflow() {
        var prepared = startAndPrepare("103");
        kyc.apply(prepared, verified(prepared));
        var row = workflow(prepared.input().workflowId());
        assertEquals("KYC_VALIDATED", row.get("state"));
        assertNotNull(row.get("current_kyc_result_id"));
        assertEquals(1, db.query("SELECT id FROM agent_result WHERE workflow_id=?", prepared.input().workflowId()).size());
        return prepared.input().workflowId();
    }

    private KycContract.Response verified(KycContract.Prepared prepared) {
        var input = prepared.input();
        var response = new KycContract.Response(input.requestId(), input.workflowId(), input.generation(),
                input.runId(), input.inputSnapshotHash(), new KycContract.Proposal(KycContract.ProposalStatus.VERIFIED,
                input.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList(),
                "Synthetic database-clock completion fixture"), new KycContract.ModelMetadata("replay", "KYC-PROMPT-1"));
        assertTrue(response.boundTo(input));
        assertEquals(2, input.evidenceFacts().size());
        return response;
    }

    private void setDeadline(KycContract.Prepared prepared, boolean expired) {
        Instant deadline = rawDatabaseNow().plus(Duration.ofDays(expired ? -1 : 1));
        tx.executeWithoutResult(status -> {
            db.gate();
            db.lockWorkflow(prepared.input().workflowId());
            assertEquals(1, db.update("UPDATE workflow_job SET lease_until=? WHERE id=?", deadline, prepared.jobId()));
        });
        assertEquals(expired, !rawDatabaseNow().isBefore(deadline));
    }

    private void assertChargedOnce(KycContract.Prepared prepared) {
        UUID id = prepared.input().workflowId();
        var workflow = workflow(id);
        assertEquals(10, ((Number) workflow.get("used_risk")).intValue());
        assertEquals(0, ((Number) workflow.get("reserved_risk")).intValue());
        var charge = db.required("SELECT * FROM risk_ledger WHERE workflow_id=?", id);
        assertEquals("CHARGE", charge.get("event_type"));
        assertEquals("KYC", charge.get("stage"));
        assertEquals(10, ((Number) charge.get("points")).intValue());
        assertEquals(prepared.input().runId(), charge.get("run_id"));
    }

    private void assertOnlyDiscard(KycContract.Prepared prepared) {
        var beforeRows = allBusinessRows();
        var beforeAudits = rows("audit_event");
        Instant before = rawDatabaseNow();
        kyc.apply(prepared, verified(prepared));
        Instant after = rawDatabaseNow();
        assertEquals(beforeRows, allBusinessRows(), "Late completion must preserve all current and independent business rows");
        var added = addedAudits(beforeAudits);
        assertEquals(1, added.size(), "Exactly one discard audit and no other appended events");
        var audit = db.required("SELECT * FROM audit_event WHERE id=?", added.getFirst().get("id"));
        assertEquals("LATE_RESULT_DISCARDED", audit.get("event_type"));
        assertEquals("WORKFLOW_CHANGED", audit.get("reason_code"));
        assertEquals(prepared.input().workflowId(), audit.get("workflow_id"));
        assertEquals(prepared.input().runId(), audit.get("run_id"));
        assertEquals(prepared.input().requestId(), audit.get("action_id"));
        assertBetween(Db.instant(audit, "created_at"), before, after);
    }

    private Map<String, Object> allBusinessRows() {
        var snapshot = new LinkedHashMap<String, Object>();
        for (String table : List.of("execution_gate", "workflow", "workflow_stage", "workflow_job", "agent_run",
                "agent_result", "risk_ledger", "delegation_grant", "approval", "payment_reservation", "mock_payment",
                "quarantine", "quarantine_workflow_hold", "loan_application", "action_request", "run_source_use",
                "run_evidence_use", "run_dependency", "trusted_evidence", "source_document_version",
                "agent_registry", "mock_account", "mock_profile", "application_registry")) {
            snapshot.put(table, rows(table));
        }
        return snapshot;
    }

    private Map<String, Object> workflowRows(UUID id) {
        var snapshot = new LinkedHashMap<String, Object>();
        snapshot.put("workflow", workflow(id));
        for (String table : List.of("workflow_stage", "workflow_job", "agent_run", "agent_result", "risk_ledger",
                "delegation_grant", "approval", "payment_reservation", "mock_payment", "audit_event")) {
            snapshot.put(table, db.query("SELECT to_jsonb(t)::text AS row FROM " + table + " t WHERE workflow_id=? ORDER BY row", id));
        }
        return snapshot;
    }

    private Map<String, Object> workflow(UUID id) {
        return db.required("SELECT * FROM workflow WHERE id=?", id);
    }

    private List<Map<String, Object>> rows(String table) {
        return db.query("SELECT to_jsonb(t)::text AS row FROM " + table + " t ORDER BY row");
    }

    private List<Map<String, Object>> addedAudits(List<Map<String, Object>> before) {
        var after = rows("audit_event");
        assertTrue(after.containsAll(before), "Existing append-only audit rows must remain unchanged");
        return db.query("SELECT id,event_type,reason_code,to_jsonb(t)::text AS row FROM audit_event t ORDER BY id").stream()
                .filter(row -> !before.contains(Map.of("row", row.get("row")))).toList();
    }

    private Instant auditTime(Map<String, Object> audit) {
        return Db.instant(db.required("SELECT created_at FROM audit_event WHERE id=?", audit.get("id")), "created_at");
    }

    private Instant rawDatabaseNow() {
        try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
            statement.setQueryTimeout(5);
            try (var result = statement.executeQuery("SELECT clock_timestamp()")) {
                assertTrue(result.next());
                return result.getTimestamp(1).toInstant();
            }
        } catch (SQLException failure) {
            throw new AssertionError("Independent JDBC database-clock probe failed", failure);
        }
    }

    private void assertBetween(Instant value, Instant before, Instant after) {
        assertNotNull(value);
        assertFalse(value.isBefore(before), "Timestamp precedes raw database lower bound");
        assertFalse(value.isAfter(after), "Timestamp exceeds raw database upper bound");
    }
}
