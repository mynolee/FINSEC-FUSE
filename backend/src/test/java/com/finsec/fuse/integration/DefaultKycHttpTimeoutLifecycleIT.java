package com.finsec.fuse.integration;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.testing.FuseIntegrationTest;
import com.finsec.fuse.workflow.JobTransactions;
import com.finsec.fuse.workflow.JobWorker;
import com.finsec.fuse.workflow.KycClient;
import com.finsec.fuse.workflow.KycContract;
import com.finsec.fuse.workflow.KycGateway;
import com.finsec.fuse.workflow.KycTransactions;
import com.finsec.fuse.workflow.StartWorkflowRequest;
import com.finsec.fuse.workflow.WorkflowService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.sql.Timestamp;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
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

/**
 * Real worker, default KycClient HTTP deadline and ephemeral PostgreSQL lifecycle.
 * The 29–40s acceptance window is deliberately tolerant, not an exact 30s measurement:
 * 1s lower tolerance covers observation skew; 10s upper tolerance covers scheduling/DB work.
 * The frozen authority clock proves only lease configuration, not 90s real lease survival.
 * runOne bypasses scheduler permits, so later success is not worker-pool capacity evidence.
 */
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class DefaultKycHttpTimeoutLifecycleIT extends FuseIntegrationTest {
    private static final DeadlineModel MODEL = DeadlineModel.start();

    @Autowired WorkflowService workflows;
    @Autowired JobWorker worker;
    @Autowired KycTransactions kyc;
    @Autowired KycGateway gateway;
    @Autowired FusePolicy policy;

    @DynamicPropertySource
    static void localModel(DynamicPropertyRegistry registry) {
        // Only redirect the dependency; no HTTP timeout, policy or production constructor override.
        registry.add("fuse.kyc-base-url", MODEL::url);
        registry.add("fuse.kyc-mode", () -> "replay");
    }

    @AfterAll
    static void stopModel() throws InterruptedException {
        MODEL.close();
    }

    @Test
    @Timeout(60)
    void defaultHttpDeadlineFailsOnceThenAllowsAnIndependentBoundResponse() throws Exception {
        MODEL.json = json;
        assertInstanceOf(KycClient.class, gateway);
        assertEquals(30, policy.kycTimeoutSeconds());
        assertEquals(90, policy.leaseSeconds());
        var authorityStart = clock.now();
        UUID workflow = start(102);
        var pending = db.required("SELECT * FROM workflow_job WHERE workflow_id=?", workflow);
        UUID jobId = (UUID) pending.get("id");
        UUID actionId = (UUID) pending.get("execution_action_id");
        var runners = Executors.newSingleThreadExecutor();
        long workerStart = System.nanoTime();
        var waiting = runners.submit(() -> {
            assertTrue(worker.runOne());
            return System.nanoTime();
        });
        try {
            var input = MODEL.waitingRequest.get(8, TimeUnit.SECONDS);
            assertEquals(workflow, input.workflowId());
            assertEquals(actionId, input.requestId());
            var claimed = db.required("SELECT * FROM workflow_job WHERE id=?", jobId);
            UUID token = (UUID) claimed.get("lease_token");
            assertNotNull(token);
            assertEquals("RUNNING", claimed.get("state"));
            assertEquals(input.runId(), claimed.get("run_id"));
            assertEquals(authorityStart.plusSeconds(90), ((Timestamp) claimed.get("lease_until")).toInstant(),
                "Frozen-clock T0+90 configuration only; this test does not wait for lease expiry");
            assertEquals("RUNNING", db.required("SELECT status FROM agent_run WHERE id=?", input.runId()).get("status"));
            assertFalse(waiting.isDone());
            long remaining = TimeUnit.SECONDS.toNanos(40) - (System.nanoTime() - workerStart);
            assertTrue(remaining > 0);
            long workerEnd = waiting.get(remaining, TimeUnit.NANOSECONDS);
            long elapsed = workerEnd - workerStart;
            long httpElapsed = workerEnd - MODEL.handlerEnteredNanos;
            assertTrue(elapsed <= TimeUnit.SECONDS.toNanos(40), "Worker completion must stay within the tolerant 40s ceiling");
            assertTrue(httpElapsed >= TimeUnit.SECONDS.toNanos(29), "Failure must follow sustained HTTP waiting, not immediate rejection");
            assertEquals(1, MODEL.release.getCount(), "The fixture must not cause completion by releasing a response");
            assertEquals(1, MODEL.waitingHandlerDone.getCount());
            assertFalse(MODEL.watchdogFired.get(), "The 45s fixture watchdog must never cause the accepted failure");
            assertNull(MODEL.failure.get());
            assertEquals(authorityStart, clock.now(), "Real timeout evidence uses nanoTime, not an advanced fixture clock");
            assertEquals(1, MODEL.requests.get());
            assertFailed(workflow, jobId, input.runId(), actionId);
            assertEquals(0, eventCount(workflow, "LATE_RESULT_DISCARDED"));
            var failedState = snapshot(workflow);
            long failedAudit = count("audit_event", workflow);

            // A real late network response may be accepted by the kernel or meet a closed client socket.
            // In either case join its handler before starting the independent workflow.
            MODEL.release.countDown();
            assertTrue(MODEL.waitingHandlerDone.await(5, TimeUnit.SECONDS));
            assertFalse(MODEL.watchdogFired.get());
            assertNull(MODEL.failure.get());
            assertEquals(failedState, snapshot(workflow));
            assertEquals(failedAudit, count("audit_event", workflow));

            UUID independent = start(104);
            var succeeding = runners.submit(worker::runOne);
            assertTrue(succeeding.get(8, TimeUnit.SECONDS));
            var normal = MODEL.normalRequest.get(1, TimeUnit.SECONDS);
            assertEquals(independent, normal.workflowId());
            assertTrue(normal.evidenceFacts().stream().anyMatch(fact -> "FAIL".equals(fact.result())));
            var normalJob = db.required("SELECT * FROM workflow_job WHERE workflow_id=?", independent);
            assertEquals(normal.requestId(), normalJob.get("execution_action_id"));
            assertEquals(normal.runId(), normalJob.get("run_id"));
            assertEquals("SUCCEEDED", normalJob.get("state"));
            assertEquals("REJECTED", db.required("SELECT state FROM workflow WHERE id=?", independent).get("state"));
            assertEquals(1, count("agent_result", independent));
            var result = db.required("SELECT run_id,body_json->>'status' proposal FROM agent_result WHERE workflow_id=?", independent);
            assertEquals(normal.runId(), result.get("run_id"));
            assertEquals("NOT_VERIFIED", result.get("proposal"));
            assertNoDownstream(independent);
            assertEquals(2, MODEL.requests.get(), "One timed-out request and one subsequent request; no retry");
            assertNull(MODEL.failure.get());
            assertEquals(failedState, snapshot(workflow));
            assertEquals(failedAudit, count("audit_event", workflow));
            var independentState = snapshot(independent);
            long independentAudit = count("audit_event", independent);

            // prepare() ignores the already failed lease without HTTP or audit; apply() emits one late audit.
            worker.execute(new JobTransactions.Lease(jobId, workflow, token, "KYC", input.generation()));
            assertEquals(failedState, snapshot(workflow));
            assertEquals(failedAudit, count("audit_event", workflow));
            kyc.apply(new KycContract.Prepared(jobId, token, input), DeadlineModel.response(input));
            assertFailed(workflow, jobId, input.runId(), actionId);
            assertEquals(failedState, snapshot(workflow));
            assertEquals(failedAudit + 1, count("audit_event", workflow));
            assertEquals(1, eventCount(workflow, "LATE_RESULT_DISCARDED"));
            var late = db.required("SELECT * FROM audit_event WHERE workflow_id=? AND event_type='LATE_RESULT_DISCARDED'", workflow);
            assertEquals("WORKFLOW_CHANGED", late.get("reason_code"));
            assertEquals(input.runId(), late.get("run_id"));
            assertEquals(actionId, late.get("action_id"));
            assertEquals(independentState, snapshot(independent));
            assertEquals(independentAudit, count("audit_event", independent));
            assertEquals(2, MODEL.requests.get());
        } finally {
            MODEL.release.countDown();
            if (!waiting.isDone()) waiting.cancel(true);
            runners.shutdownNow();
            // Clear a test-timeout interrupt long enough to perform bounded joins; restore it afterwards.
            boolean interrupted = Thread.interrupted();
            try {
                try {
                    assertTrue(runners.awaitTermination(5, TimeUnit.SECONDS), "Worker must terminate before database reset");
                } finally {
                    MODEL.close();
                }
            } finally {
                if (interrupted) Thread.currentThread().interrupt();
            }
        }
    }

    private void assertFailed(UUID workflow, UUID job, UUID run, UUID action) {
        var row = db.required("SELECT * FROM workflow WHERE id=?", workflow);
        assertEquals("ON_HOLD", row.get("state"));
        assertEquals("ERROR", row.get("last_decision"));
        assertEquals("DEPENDENCY_UNAVAILABLE", row.get("last_reason_code"));
        assertEquals(10, ((Number) row.get("used_risk")).intValue());
        assertEquals(0, ((Number) row.get("reserved_risk")).intValue());
        var stage = db.required("SELECT * FROM workflow_stage WHERE workflow_id=? AND stage='KYC'", workflow);
        assertEquals(1, ((Number) stage.get("run_count")).intValue());
        assertEquals(10, ((Number) stage.get("used_points")).intValue());
        var failed = db.required("SELECT * FROM workflow_job WHERE id=?", job);
        assertEquals("FAILED", failed.get("state"));
        assertEquals("DEPENDENCY_UNAVAILABLE", failed.get("last_error"));
        assertEquals(action, failed.get("execution_action_id"));
        assertEquals(run, failed.get("run_id"));
        assertEquals("FAILED", db.required("SELECT status FROM agent_run WHERE id=?", run).get("status"));
        assertEquals(1, count("agent_run", workflow));
        assertEquals(0, count("agent_result", workflow));
        assertEquals(1, count("risk_ledger", workflow));
        var charge = db.required("SELECT * FROM risk_ledger WHERE workflow_id=?", workflow);
        assertEquals("CHARGE", charge.get("event_type"));
        assertEquals("KYC", charge.get("stage"));
        assertEquals(10, ((Number) charge.get("points")).intValue());
        assertEquals(action, charge.get("action_id"));
        assertEquals(run, charge.get("run_id"));
        assertEquals(1, eventCount(workflow, "SYSTEM_ERROR"));
        assertNoDownstream(workflow);
    }

    private void assertNoDownstream(UUID workflow) {
        assertEquals(1, count("workflow_job", workflow));
        assertEquals(0, ((Number) db.required("SELECT count(*) n FROM workflow_job WHERE workflow_id=? AND phase IN ('LOAN','PAY')", workflow).get("n")).longValue());
        assertEquals(0, count("mock_payment", workflow));
        assertEquals(0, count("payment_reservation", workflow));
        assertEquals(0, ((Number) db.required("SELECT count(*) n FROM quarantine").get("n")).longValue());
        assertEquals(0, ((Number) db.required("SELECT count(*) n FROM quarantine_workflow_hold").get("n")).longValue());
    }

    private Map<String, List<Map<String, Object>>> snapshot(UUID workflow) {
        var state = new LinkedHashMap<String, List<Map<String, Object>>>();
        state.put("workflow", db.query("SELECT to_jsonb(t)::text AS snapshot_json FROM workflow t WHERE id=?", workflow));
        for (String table : List.of("workflow_stage", "workflow_job", "agent_run", "agent_result", "risk_ledger", "mock_payment", "payment_reservation")) {
            state.put(table, db.query("SELECT to_jsonb(t)::text AS snapshot_json FROM " + table + " t WHERE workflow_id=? ORDER BY to_jsonb(t)::text", workflow));
        }
        return state;
    }

    private long eventCount(UUID workflow, String event) {
        return ((Number) db.required("SELECT count(*) n FROM audit_event WHERE workflow_id=? AND event_type=?", workflow, event).get("n")).longValue();
    }

    private long count(String table, UUID workflow) {
        return ((Number) db.required("SELECT count(*) n FROM " + table + " WHERE workflow_id=?", workflow).get("n")).longValue();
    }

    private UUID start(int customer) {
        String principal = "customer-" + customer;
        return (UUID) workflows.start(new Actor(principal, "CUSTOMER", Set.of(principal)), UUID.randomUUID(),
            new StartWorkflowRequest("APP-DEMO-" + customer + "-001", principal, 1_000_000L,
                UUID.fromString("00000000-0000-4000-8000-000000000" + customer))).get("workflowId");
    }

    private static final class DeadlineModel {
        private final HttpServer server;
        private final ExecutorService handlers = Executors.newFixedThreadPool(2);
        final CountDownLatch release = new CountDownLatch(1);
        final CountDownLatch waitingHandlerDone = new CountDownLatch(1);
        final CompletableFuture<KycContract.Input> waitingRequest = new CompletableFuture<>();
        final CompletableFuture<KycContract.Input> normalRequest = new CompletableFuture<>();
        final AtomicInteger requests = new AtomicInteger();
        final AtomicBoolean watchdogFired = new AtomicBoolean();
        final AtomicBoolean closed = new AtomicBoolean();
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        volatile long handlerEnteredNanos;
        volatile Json json;

        private DeadlineModel() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setExecutor(handlers);
            server.createContext("/internal/v1/kyc/evaluations", this::handle);
            server.start();
        }

        private void handle(HttpExchange exchange) {
            boolean stalled = false;
            try {
                assertEquals("POST", exchange.getRequestMethod());
                var input = json.read(exchange.getRequestBody().readAllBytes(), KycContract.Input.class);
                requests.incrementAndGet();
                stalled = "customer-102".equals(input.customerId());
                if (stalled) {
                    handlerEnteredNanos = System.nanoTime();
                    waitingRequest.complete(input);
                    if (!release.await(45, TimeUnit.SECONDS)) {
                        watchdogFired.set(true);
                        throw new IOException("Fixture watchdog fired before response release");
                    }
                } else {
                    assertEquals("customer-104", input.customerId());
                    normalRequest.complete(input);
                }
                var bound = response(input);
                assertTrue(bound.boundTo(input));
                byte[] bytes = json.bytes(bound);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                try {
                    exchange.sendResponseHeaders(200, bytes.length);
                    exchange.getResponseBody().write(bytes);
                } catch (IOException disconnected) {
                    // Only a released, intentionally late write may meet the cancelled client's socket.
                    if (!stalled || release.getCount() != 0) throw disconnected;
                }
            } catch (Exception | AssertionError error) {
                failure.compareAndSet(null, error);
                waitingRequest.completeExceptionally(error);
                normalRequest.completeExceptionally(error);
            } finally {
                exchange.close();
                if (stalled) waitingHandlerDone.countDown();
            }
        }

        static KycContract.Response response(KycContract.Input input) {
            var status = input.evidenceFacts().stream().anyMatch(fact -> "FAIL".equals(fact.result()))
                ? KycContract.ProposalStatus.NOT_VERIFIED : KycContract.ProposalStatus.VERIFIED;
            return new KycContract.Response(input.requestId(), input.workflowId(), input.generation(), input.runId(),
                input.inputSnapshotHash(), new KycContract.Proposal(status,
                    input.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList(),
                    "Synthetic local deadline fixture"), new KycContract.ModelMetadata("replay", "KYC-PROMPT-1"));
        }

        static DeadlineModel start() {
            try { return new DeadlineModel(); }
            catch (IOException failure) { throw new ExceptionInInitializerError(failure); }
        }

        String url() { return "http://127.0.0.1:" + server.getAddress().getPort(); }

        void close() throws InterruptedException {
            if (!closed.compareAndSet(false, true)) return;
            release.countDown();
            server.stop(0);
            handlers.shutdownNow();
            assertTrue(handlers.awaitTermination(5, TimeUnit.SECONDS), "All HTTP handlers must join before database reset");
        }
    }
}
