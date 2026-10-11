package com.finsec.fuse.integration;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.DemoSeed;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.config.FuseReadinessHealthIndicator;
import com.finsec.fuse.payment.PaymentAgentService;
import com.finsec.fuse.testing.FuseIntegrationTest;
import com.finsec.fuse.workflow.JobTransactions;
import com.finsec.fuse.workflow.JobWorker;
import com.finsec.fuse.workflow.KycClient;
import com.finsec.fuse.workflow.KycContract;
import com.finsec.fuse.workflow.KycGateway;
import com.finsec.fuse.workflow.KycTransactions;
import com.finsec.fuse.workflow.LoanTransactions;
import com.finsec.fuse.workflow.StartWorkflowRequest;
import com.finsec.fuse.workflow.TransactionRetries;
import com.finsec.fuse.workflow.WorkflowService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import static org.junit.jupiter.api.Assertions.*;

/** Test-owned scheduling drives real poll/permit/HTTP/DB behavior after fixture setup.
 * Does not establish Spring scheduling wiring, a 30s timeout, 90s lease survival,
 * wall-clock authority behavior, or HTTP connection-pool reuse. */
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class ScheduledKycCapacityLifecycleIT extends FuseIntegrationTest {
    private static final BarrierModel MODEL = BarrierModel.start();
    @Autowired WorkflowService workflows;
    @Autowired JobTransactions jobs;
    @Autowired KycTransactions kyc;
    @Autowired KycGateway gateway;
    @Autowired LoanTransactions loans;
    @Autowired PaymentAgentService payments;
    @Autowired TransactionRetries retries;
    @Autowired FusePolicy policy;
    @Autowired FuseReadinessHealthIndicator readiness;

    @DynamicPropertySource
    static void localModel(DynamicPropertyRegistry registry) {
        registry.add("fuse.kyc-base-url", MODEL::url);
        registry.add("fuse.kyc-mode", () -> "replay");
    }
    @AfterAll static void stopModel() throws InterruptedException { MODEL.close(); }

    @Test
    @Timeout(45)
    void scheduledPollEnforcesFourSlotsAndReusesReleasedFailureCapacity() throws Exception {
        MODEL.json = json;
        assertInstanceOf(KycClient.class, gateway);
        assertEquals(4, policy.maxKycConcurrency());
        assertEquals(30, policy.kycTimeoutSeconds());
        assertEquals(90, policy.leaseSeconds());
        assertFalse(environment.getProperty("fuse.worker-enabled", Boolean.class, true));
        List<UUID> workflowsStarted = seedAndStartFive();
        var worker = new JobWorker(jobs, kyc, gateway, loans, payments, retries, db, policy, readiness, true);
        // Cleanup-only observation: no production seam and no permit manipulation.
        var executor = (ExecutorService) ReflectionTestUtils.getField(worker, "executor");
        assertNotNull(executor);
        var scheduler = Executors.newSingleThreadScheduledExecutor();
        var polls = new AtomicInteger();
        var pollFailure = new AtomicReference<Throwable>();
        try {
            scheduler.scheduleWithFixedDelay(() -> {
                try { worker.poll(); }
                catch (Throwable failure) { pollFailure.compareAndSet(null, failure); }
                finally { polls.incrementAndGet(); }
            }, 0, policy.workerPollMs(), TimeUnit.MILLISECONDS);
            await(() -> MODEL.requests.size() == 4, 8);
            assertEquals(4, MODEL.waitingResponses.get());
            var held = List.copyOf(MODEL.requests.keySet());
            assertEquals(4, Set.copyOf(held).size());
            UUID fifth = workflowsStarted.stream().filter(id -> !held.contains(id)).findFirst().orElseThrow();
            int saturatedAt = polls.get();
            for (int round = 1; round <= 3; round++) {
                int expectedPolls = saturatedAt + round;
                await(() -> polls.get() >= expectedPolls, 3);
                assertNull(pollFailure.get());
                assertNull(MODEL.failure.get());
                assertEquals(4, MODEL.requests.size());
                assertEquals(4, MODEL.waitingResponses.get());
                assertEquals(4, MODEL.maxWaitingResponses.get());
                for (UUID id : held) assertRunning(id);
                assertPendingUncharged(fifth);
            }
            UUID affected = held.getFirst();
            var failedInput = MODEL.requests.get(affected).input;
            MODEL.requests.get(affected).status = 503;
            MODEL.requests.get(affected).release.countDown();
            await(() -> "FAILED".equals(job(affected).get("state")), 5);
            assertFailed(affected, failedInput);
            await(() -> MODEL.requests.containsKey(fifth), 5);
            assertEquals(5, MODEL.calls.get());
            assertEquals(4, MODEL.waitingResponses.get(), "Three original calls plus newly admitted fifth");
            assertEquals(4, MODEL.maxWaitingResponses.get());
            assertRunning(fifth);
            for (UUID id : held) if (!id.equals(affected)) assertRunning(id);
            var failedSnapshot = snapshot(affected);
            for (var request : MODEL.requests.values()) request.release.countDown();
            await(() -> workflowsStarted.stream().allMatch(id ->
                Set.of("FAILED", "SUCCEEDED").contains(job(id).get("state"))), 8);
            int completedAt = polls.get();
            await(() -> polls.get() >= completedAt + 3, 4);
            assertEquals(failedSnapshot, snapshot(affected));
            assertFailed(affected, failedInput);
            assertEquals(5, MODEL.calls.get(), "Exactly one HTTP call per workflow; no automatic retry");
            assertEquals(0, MODEL.waitingResponses.get());
            assertEquals(4, MODEL.maxWaitingResponses.get());
            assertNull(MODEL.failure.get());
            assertNull(pollFailure.get());
            assertFalse(MODEL.watchdogFired.get());
            for (UUID id : workflowsStarted) {
                assertNoDownstream(id);
                if (id.equals(affected)) continue;
                var input = MODEL.requests.get(id).input;
                assertEquals("SUCCEEDED", job(id).get("state"));
                assertEquals("REJECTED", db.required("SELECT state FROM workflow WHERE id=?", id).get("state"));
                assertEquals(1, count("agent_run", id));
                assertEquals(1, count("agent_result", id));
                var result = db.required("SELECT run_id,body_json->>'status' proposal FROM agent_result WHERE workflow_id=?", id);
                assertEquals(input.runId(), result.get("run_id"));
                assertEquals("NOT_VERIFIED", result.get("proposal"));
                assertCharge(id, input);
            }
        } finally {
            boolean interrupted = Thread.interrupted();
            try {
                scheduler.shutdownNow();
                try {
                    assertTrue(scheduler.awaitTermination(5, TimeUnit.SECONDS), "Stop and join poll invocations before worker shutdown");
                } finally {
                    MODEL.requests.values().forEach(request -> request.release.countDown());
                    worker.stop();
                    try {
                        assertTrue(executor.awaitTermination(8, TimeUnit.SECONDS), "Join every worker before database reset");
                    } finally { MODEL.close(); }
                }
            } finally { if (interrupted) Thread.currentThread().interrupt(); }
        }
    }

    private List<UUID> seedAndStartFive() {
        var customers = new ArrayList<DemoSeed.Customer>();
        for (int index = 0; index < 5; index++) {
            String customer = "capacity-fixture-" + index;
            customers.add(new DemoSeed.Customer(customer, UUID.randomUUID(), 3_000_000L, 2_000_000L,
                1_000_000L, "CAPACITY-FIXTURE-" + index, 1, List.of(
                    new DemoSeed.Evidence(UUID.randomUUID(), "ID_DOC", "mock-id-issuer", "PASS"),
                    new DemoSeed.Evidence(UUID.randomUUID(), "FACE_MATCH", "mock-face-issuer", "FAIL"))));
        }
        tx.executeWithoutResult(status -> seed.seed(new DemoSeed.Fixture("scheduled-capacity-v1", "LOAN-MOCK-1",
            UUID.fromString("00000000-0000-4000-8000-000000000201"), List.of(), customers)));
        var ids = new ArrayList<UUID>();
        for (var customer : customers) ids.add((UUID) workflows.start(
            new Actor(customer.customerId(), "CUSTOMER", Set.of(customer.customerId())), UUID.randomUUID(),
            new StartWorkflowRequest(customer.businessReference(), customer.customerId(), customer.amountKrw(), customer.accountId())).get("workflowId"));
        assertEquals(5, Set.copyOf(ids).size());
        return ids;
    }

    private void assertPendingUncharged(UUID id) {
        var job = job(id);
        assertEquals("PENDING", job.get("state"));
        assertNull(job.get("run_id"));
        assertNull(job.get("lease_token"));
        assertEquals(0, count("agent_run", id));
        assertEquals(0, count("agent_result", id));
        assertEquals(0, count("risk_ledger", id));
        assertEquals(0, ((Number) db.required("SELECT used_risk FROM workflow WHERE id=?", id).get("used_risk")).intValue());
        assertNoDownstream(id);
    }
    private void assertRunning(UUID id) {
        var input = MODEL.requests.get(id).input;
        assertEquals(id, input.workflowId());
        assertEquals(db.required("SELECT a.customer_id FROM workflow w JOIN loan_application a ON a.id=w.application_id WHERE w.id=?", id).get("customer_id"), input.customerId());
        assertEquals("RUNNING", job(id).get("state"));
        assertNotNull(job(id).get("lease_token"));
        assertEquals(input.runId(), job(id).get("run_id"));
        assertEquals(input.requestId(), job(id).get("execution_action_id"));
        assertEquals("RUNNING", db.required("SELECT status FROM agent_run WHERE id=?", input.runId()).get("status"));
        assertEquals(1, count("agent_run", id));
        assertEquals(0, count("agent_result", id));
        assertCharge(id, input);
    }
    private void assertFailed(UUID id, KycContract.Input input) {
        var workflow = db.required("SELECT * FROM workflow WHERE id=?", id);
        assertEquals("ON_HOLD", workflow.get("state"));
        assertEquals("ERROR", workflow.get("last_decision"));
        assertEquals("DEPENDENCY_UNAVAILABLE", workflow.get("last_reason_code"));
        assertEquals(10, ((Number) workflow.get("used_risk")).intValue());
        assertEquals(0, ((Number) workflow.get("reserved_risk")).intValue());
        assertEquals("FAILED", job(id).get("state"));
        assertEquals("DEPENDENCY_UNAVAILABLE", job(id).get("last_error"));
        assertEquals(input.requestId(), job(id).get("execution_action_id"));
        assertEquals(input.runId(), job(id).get("run_id"));
        assertEquals("FAILED", db.required("SELECT status FROM agent_run WHERE id=?", input.runId()).get("status"));
        assertEquals(1, count("agent_run", id));
        assertEquals(0, count("agent_result", id));
        assertEquals(1, ((Number) db.required("SELECT count(*) n FROM audit_event WHERE workflow_id=? AND event_type='SYSTEM_ERROR'", id).get("n")).longValue());
        assertCharge(id, input);
        assertNoDownstream(id);
    }
    private void assertCharge(UUID id, KycContract.Input input) {
        assertEquals(1, count("risk_ledger", id));
        var charge = db.required("SELECT * FROM risk_ledger WHERE workflow_id=?", id);
        assertEquals("CHARGE", charge.get("event_type"));
        assertEquals("KYC", charge.get("stage"));
        assertEquals(10, ((Number) charge.get("points")).intValue());
        assertEquals(input.requestId(), charge.get("action_id"));
        assertEquals(input.runId(), charge.get("run_id"));
    }
    private void assertNoDownstream(UUID id) {
        assertEquals(1, count("workflow_job", id));
        assertEquals("KYC", job(id).get("phase"));
        assertEquals(0, count("mock_payment", id));
        assertEquals(0, count("payment_reservation", id));
        assertEquals(0, ((Number) db.required("SELECT count(*) n FROM quarantine").get("n")).longValue());
        assertEquals(0, ((Number) db.required("SELECT count(*) n FROM quarantine_workflow_hold").get("n")).longValue());
    }
    private Map<String, Object> job(UUID id) { return db.required("SELECT * FROM workflow_job WHERE workflow_id=?", id); }
    private long count(String table, UUID id) { return ((Number) db.required("SELECT count(*) n FROM " + table + " WHERE workflow_id=?", id).get("n")).longValue(); }
    private List<List<Map<String, Object>>> snapshot(UUID id) {
        return List.of("workflow", "workflow_job", "workflow_stage", "agent_run", "agent_result", "risk_ledger", "audit_event")
            .stream().map(table -> db.query("SELECT to_jsonb(t)::text snapshot FROM " + table + " t WHERE "
                + (table.equals("workflow") ? "id" : "workflow_id") + "=? ORDER BY to_jsonb(t)::text", id)).toList();
    }
    private static void await(BooleanSupplier condition, int seconds) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(20);
        assertTrue(condition.getAsBoolean(), "Bounded capacity lifecycle observation did not complete");
    }

    private static final class Request {
        final KycContract.Input input;
        final CountDownLatch release = new CountDownLatch(1);
        volatile int status = 200;
        Request(KycContract.Input input) { this.input = input; }
    }
    private static final class BarrierModel {
        final HttpServer server;
        // Six handlers ensure the fixture cannot itself impose the four-call bound.
        final ExecutorService handlers = Executors.newFixedThreadPool(6);
        final Map<UUID, Request> requests = new ConcurrentHashMap<>();
        final AtomicInteger calls = new AtomicInteger();
        final AtomicInteger waitingResponses = new AtomicInteger();
        final AtomicInteger maxWaitingResponses = new AtomicInteger();
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final AtomicBoolean watchdogFired = new AtomicBoolean();
        final AtomicBoolean closed = new AtomicBoolean();
        volatile Json json;
        BarrierModel() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setExecutor(handlers);
            server.createContext("/internal/v1/kyc/evaluations", this::handle);
            server.start();
        }
        void handle(HttpExchange exchange) {
            int concurrency = waitingResponses.incrementAndGet();
            maxWaitingResponses.accumulateAndGet(concurrency, Math::max);
            boolean waiting = true;
            try {
                assertEquals("POST", exchange.getRequestMethod());
                var input = json.read(exchange.getRequestBody().readAllBytes(), KycContract.Input.class);
                calls.incrementAndGet();
                assertTrue(input.evidenceFacts().stream().anyMatch(fact -> "FAIL".equals(fact.result())));
                var request = new Request(input);
                assertNull(requests.putIfAbsent(input.workflowId(), request), "No duplicate HTTP request");
                if (!request.release.await(20, TimeUnit.SECONDS)) {
                    watchdogFired.set(true);
                    throw new IOException("Short barrier watchdog fired");
                }
                byte[] response;
                if (request.status == 503) response = json.bytes(Map.of("reasonCode", "DEPENDENCY_UNAVAILABLE"));
                else {
                    var bound = new KycContract.Response(input.requestId(), input.workflowId(), input.generation(), input.runId(),
                        input.inputSnapshotHash(), new KycContract.Proposal(KycContract.ProposalStatus.NOT_VERIFIED,
                        input.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList(), "Synthetic capacity fixture"),
                        new KycContract.ModelMetadata("replay", "KYC-PROMPT-1"));
                    assertTrue(bound.boundTo(input));
                    response = json.bytes(bound);
                }
                // End dependency waiting before making a response visible to the client.
                // Physical socket-close callbacks can overlap a subsequent admitted call.
                waitingResponses.decrementAndGet();
                waiting = false;
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(request.status, response.length);
                exchange.getResponseBody().write(response);
            } catch (Exception | AssertionError error) { failure.compareAndSet(null, error); }
            finally { exchange.close(); if (waiting) waitingResponses.decrementAndGet(); }
        }
        String url() { return "http://127.0.0.1:" + server.getAddress().getPort(); }
        static BarrierModel start() {
            try { return new BarrierModel(); }
            catch (IOException failure) { throw new ExceptionInInitializerError(failure); }
        }
        void close() throws InterruptedException {
            if (!closed.compareAndSet(false, true)) return;
            requests.values().forEach(request -> request.release.countDown());
            server.stop(0);
            handlers.shutdownNow();
            assertTrue(handlers.awaitTermination(5, TimeUnit.SECONDS), "Join HTTP handlers before database reset");
        }
    }
}
