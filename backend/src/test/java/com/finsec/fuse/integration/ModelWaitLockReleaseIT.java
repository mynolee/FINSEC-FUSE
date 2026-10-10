package com.finsec.fuse.integration;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.testing.FuseIntegrationTest;
import com.finsec.fuse.testing.PostgresSupport;
import com.finsec.fuse.workflow.JobWorker;
import com.finsec.fuse.workflow.KycContract;
import com.finsec.fuse.workflow.StartWorkflowRequest;
import com.finsec.fuse.workflow.WorkflowService;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import static org.junit.jupiter.api.Assertions.*;

/** Real worker, HTTP transport and PostgreSQL 16; no mocked transaction or model gateway. */
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class ModelWaitLockReleaseIT extends FuseIntegrationTest {
    private static final String APPLICATION_NAME = "fuse-model-wait-lock-test";
    private static final StalledModel MODEL = StalledModel.start();

    @Autowired WorkflowService workflows;
    @Autowired JobWorker worker;

    @DynamicPropertySource
    static void localModel(DynamicPropertyRegistry registry) {
        registry.add("fuse.kyc-base-url", MODEL::url);
        registry.add("fuse.kyc-mode", () -> "replay");
        registry.add("spring.datasource.hikari.data-source-properties.ApplicationName", () -> APPLICATION_NAME);
        // Keep idle connections, but avoid background pool filling during the lock snapshot.
        registry.add("spring.datasource.hikari.minimum-idle", () -> "1");
    }

    @AfterAll
    static void stopModel() throws InterruptedException {
        MODEL.close();
    }

    @Test
    @Timeout(45)
    void stalledModelHttpReleasesTransactionsAndLocksWhileAnotherCustomerCompletes() throws Exception {
        MODEL.json = json;
        assertEquals(APPLICATION_NAME, db.required("SHOW application_name").get("application_name"));
        // Production deadlines remain unchanged: DB lock 2s, statement 5s; model HTTP 30s.
        assertEquals("2s", db.required("SHOW lock_timeout").get("lock_timeout"));
        assertEquals("5s", db.required("SHOW statement_timeout").get("statement_timeout"));
        UUID waitingWorkflow = start(102);
        var before = db.required("SELECT * FROM workflow_job WHERE workflow_id=?", waitingWorkflow);
        UUID jobId = (UUID) before.get("id");
        UUID actionId = (UUID) before.get("execution_action_id");
        var runners = Executors.newFixedThreadPool(2);
        Future<Boolean> waiting = runners.submit(worker::runOne);
        try (var observer = DriverManager.getConnection(PostgresSupport.url(), "postgres", "")) {
            // This connection is outside the application's pool and never invokes its transaction manager.
            try (var statement = observer.createStatement()) {
                statement.execute("SET statement_timeout = '3s'");
                statement.execute("SET lock_timeout = '1s'");
            }
            var input = MODEL.waitingRequest.get(10, TimeUnit.SECONDS);
            assertEquals(waitingWorkflow, input.workflowId());
            assertEquals(actionId, input.requestId());
            assertHttpStillWaiting(waiting);

            var claimed = db.required("SELECT * FROM workflow_job WHERE id=?", jobId);
            UUID leaseToken = (UUID) claimed.get("lease_token");
            assertNotNull(leaseToken);
            assertEquals("RUNNING", claimed.get("state"));
            assertEquals(input.runId(), claimed.get("run_id"));
            assertEquals("RUNNING", db.required("SELECT status FROM agent_run WHERE id=?", input.runId()).get("status"));
            assertEquals(10, ((Number) db.required("SELECT used_risk FROM workflow WHERE id=?", waitingWorkflow).get("used_risk")).intValue());
            assertEquals(0, count("agent_result", waitingWorkflow));

            assertApplicationHasNoTransactionOrLocks(observer);
            assertSameRowsCanBeLockedNow(observer, waitingWorkflow, jobId);
            assertHttpStillWaiting(waiting);

            // Both admission and another actual worker KYC round trip must finish before release.
            // Customer 104 has seeded failed evidence and is correctly rejected without quarantine.
            Future<UUID> independent = runners.submit(() -> {
                UUID workflow = start(104);
                assertTrue(worker.runOne());
                return workflow;
            });
            UUID independentWorkflow = independent.get(8, TimeUnit.SECONDS);
            assertEquals("REJECTED", db.required("SELECT state FROM workflow WHERE id=?", independentWorkflow).get("state"));
            assertEquals(1, count("agent_result", independentWorkflow));
            assertEquals(0, count("mock_payment", independentWorkflow));
            assertHttpStillWaiting(waiting);
            assertApplicationHasNoTransactionOrLocks(observer);
            assertSameRowsCanBeLockedNow(observer, waitingWorkflow, jobId);

            var stillClaimed = db.required("SELECT * FROM workflow_job WHERE id=?", jobId);
            assertEquals("RUNNING", stillClaimed.get("state"));
            assertEquals(leaseToken, stillClaimed.get("lease_token"));
            assertEquals(actionId, stillClaimed.get("execution_action_id"));
            assertEquals(input.runId(), stillClaimed.get("run_id"));
            assertEquals(0, count("agent_result", waitingWorkflow));

            MODEL.release.countDown();
            assertTrue(waiting.get(8, TimeUnit.SECONDS));
            assertNull(MODEL.failure.get(), "The local HTTP fixture must not fail silently");
            assertEquals(2, MODEL.requests.get(), "Exactly two synthetic HTTP requests, without retry/provider calls");
            assertEquals("KYC_VALIDATED", db.required("SELECT state FROM workflow WHERE id=?", waitingWorkflow).get("state"));
            var completed = db.required("SELECT * FROM workflow_job WHERE id=?", jobId);
            assertEquals("SUCCEEDED", completed.get("state"));
            assertEquals(actionId, completed.get("execution_action_id"));
            assertEquals(1, count("agent_run", waitingWorkflow));
            assertEquals(1, count("agent_result", waitingWorkflow));
            assertEquals(1, count("risk_ledger", waitingWorkflow));
            assertEquals(0, count("mock_payment", waitingWorkflow));
            assertApplicationHasNoTransactionOrLocks(observer);
            assertSameRowsCanBeLockedNow(observer, waitingWorkflow, jobId);
        } finally {
            // Release before interrupting: even failed assertions cannot leave a blocked HTTP handler/worker.
            MODEL.release.countDown();
            if (!waiting.isDone()) waiting.cancel(true);
            runners.shutdownNow();
            assertTrue(runners.awaitTermination(10, TimeUnit.SECONDS), "Worker test threads must terminate before database reset");
        }
    }

    private UUID start(int customer) {
        String principal = "customer-" + customer;
        return (UUID) workflows.start(new Actor(principal, "CUSTOMER", Set.of(principal)), UUID.randomUUID(),
            new StartWorkflowRequest("APP-DEMO-" + customer + "-001", principal, 1_000_000L,
                UUID.fromString("00000000-0000-4000-8000-000000000" + customer))).get("workflowId");
    }

    private long count(String table, UUID workflow) {
        return ((Number) db.required("SELECT count(*) n FROM " + table + " WHERE workflow_id=?", workflow).get("n")).longValue();
    }

    private void assertHttpStillWaiting(Future<Boolean> waiting) {
        assertEquals(1, MODEL.release.getCount(), "Observation must precede releasing the HTTP response");
        assertFalse(waiting.isDone(), "The real worker must still be waiting for model HTTP");
        assertNull(MODEL.failure.get(), "Stall must be controlled by the barrier, not a fixture error");
    }

    private void assertApplicationHasNoTransactionOrLocks(Connection observer) throws Exception {
        int sessions = 0;
        try (var query = observer.prepareStatement("""
                SELECT pid,state,xact_start,backend_xid
                FROM pg_stat_activity
                WHERE datname=current_database() AND application_name=? AND pid<>pg_backend_pid()
                ORDER BY pid
                """)) {
            query.setString(1, APPLICATION_NAME);
            try (var rows = query.executeQuery()) {
                while (rows.next()) {
                    sessions++;
                    String label = "Application backend " + rows.getInt("pid");
                    assertEquals("idle", rows.getString("state"), label + " must not be idle in transaction");
                    assertNull(rows.getObject("xact_start"), label + " must not own even a read-only transaction");
                    assertNull(rows.getObject("backend_xid"), label + " must not own a transaction ID");
                }
            }
        }
        // Existing idle/read-capable pool sessions are not transaction/row-lock ownership.
        assertTrue(sessions > 0, "A lock snapshot without application sessions would be vacuous");
        try (var query = observer.prepareStatement("""
                SELECT l.pid,l.locktype,l.mode,l.granted
                FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
                WHERE a.datname=current_database() AND a.application_name=? AND a.pid<>pg_backend_pid()
                """)) {
            query.setString(1, APPLICATION_NAME);
            try (var locks = query.executeQuery()) {
                assertFalse(locks.next(), "Application sessions must hold no PostgreSQL locks while awaiting HTTP");
            }
        }
    }

    private void assertSameRowsCanBeLockedNow(Connection observer, UUID workflow, UUID job) throws Exception {
        observer.setAutoCommit(false);
        try {
            // Follow production gate → workflow → job order; NOWAIT fails immediately on a held row lock.
            try (var gate = observer.createStatement();
                 var row = gate.executeQuery("SELECT id FROM execution_gate WHERE id=1 FOR UPDATE NOWAIT")) {
                assertTrue(row.next());
            }
            lockRow(observer, "SELECT id FROM workflow WHERE id=? FOR UPDATE NOWAIT", workflow);
            lockRow(observer, "SELECT id FROM workflow_job WHERE id=? FOR UPDATE NOWAIT", job);
            // Positive control: pg_locks really sees this competing transaction's write/row-lock ownership.
            try (var query = observer.createStatement(); var rows = query.executeQuery("""
                    SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid()
                        AND locktype='transactionid' AND mode='ExclusiveLock' AND granted) AS owns_transaction,
                        EXISTS(SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid()
                        AND relation='execution_gate'::regclass AND mode='RowShareLock' AND granted) AS owns_gate
                    """)) {
                assertTrue(rows.next());
                assertTrue(rows.getBoolean("owns_transaction"));
                assertTrue(rows.getBoolean("owns_gate"));
            }
        } finally {
            observer.rollback();
            observer.setAutoCommit(true);
        }
    }

    private void lockRow(Connection observer, String sql, UUID id) throws Exception {
        try (var query = observer.prepareStatement(sql)) {
            query.setObject(1, id);
            try (var row = query.executeQuery()) { assertTrue(row.next()); }
        }
    }

    private static final class StalledModel {
        private final HttpServer server;
        private final ExecutorService handlers = Executors.newFixedThreadPool(2);
        final CountDownLatch release = new CountDownLatch(1);
        final CompletableFuture<KycContract.Input> waitingRequest = new CompletableFuture<>();
        final AtomicInteger requests = new AtomicInteger();
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        volatile Json json;

        private StalledModel() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setExecutor(handlers);
            server.createContext("/internal/v1/kyc/evaluations", exchange -> {
                try {
                    assertEquals("POST", exchange.getRequestMethod());
                    var input = json.read(exchange.getRequestBody().readAllBytes(), KycContract.Input.class);
                    requests.incrementAndGet();
                    if ("customer-102".equals(input.customerId())) {
                        waitingRequest.complete(input);
                        // Fixture watchdog is shorter than the unchanged 30s production HTTP deadline.
                        if (!release.await(20, TimeUnit.SECONDS)) throw new IOException("Model barrier was not released");
                    }
                    var status = input.evidenceFacts().stream().anyMatch(fact -> "FAIL".equals(fact.result()))
                        ? KycContract.ProposalStatus.NOT_VERIFIED : KycContract.ProposalStatus.VERIFIED;
                    var response = new KycContract.Response(input.requestId(), input.workflowId(), input.generation(),
                        input.runId(), input.inputSnapshotHash(), new KycContract.Proposal(status,
                            input.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList(),
                            "Synthetic local lock-release fixture"), new KycContract.ModelMetadata("replay", "KYC-PROMPT-1"));
                    byte[] bytes = json.bytes(response);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, bytes.length);
                    exchange.getResponseBody().write(bytes);
                } catch (Exception | AssertionError error) {
                    failure.compareAndSet(null, error);
                    waitingRequest.completeExceptionally(error);
                } finally {
                    exchange.close();
                }
            });
            server.start();
        }

        static StalledModel start() {
            try { return new StalledModel(); }
            catch (IOException failure) { throw new ExceptionInInitializerError(failure); }
        }

        String url() { return "http://127.0.0.1:" + server.getAddress().getPort(); }

        void close() throws InterruptedException {
            release.countDown();
            server.stop(0);
            handlers.shutdownNow();
            assertTrue(handlers.awaitTermination(5, TimeUnit.SECONDS), "Local HTTP fixture must terminate");
        }
    }
}
