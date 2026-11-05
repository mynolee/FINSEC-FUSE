package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.application.VirtualHttpApplication;
import com.finsec.fuse.reimplementation.application.VirtualLoopbackListener;
import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;
import static org.junit.jupiter.api.Assertions.*;

/** Source-only configured application acceptance fixtures; no listener or real thread is started. */
final class VirtualConfiguredDeliveryAssemblyTest {
    static final class ManualQueue implements Executor {
        final Deque<Runnable> tasks = new ArrayDeque<>(); boolean reject;
        public void execute(Runnable task) {
            if (reject) throw new RejectedExecutionException("synthetic queue unavailable");
            tasks.addLast(task);
        }
        void drainOne() { assertFalse(tasks.isEmpty()); tasks.removeFirst().run(); }
    }
    static final class Fixture {
        final SimulationFixture seed = new SimulationFixture();
        final AtomicInteger providerCalls = new AtomicInteger(), pairCalls = new AtomicInteger();
        final HttpLimits limits = new HttpLimits(4096, 8192, 16);
        final VirtualHttpApplication.Config config = new VirtualHttpApplication.Config("127.0.0.1", 18080,
                "/internal/synthetic-ready", limits, 1000, 2);
        final VirtualProductAssembly.Inputs inputs;
        final VirtualProductAssembly.DeliveryInputs delivery;
        final VirtualHttpApplication application;
        final VirtualProductAssembly product;
        Fixture(Executor executor, boolean configured) {
            var terms = new SimulationSpec.RiskTerms("SYNTHETIC-POLICY-1", 1, 2, 3, 20, 5, 2, Duration.ofMinutes(5));
            var fixtures = List.of(new VirtualExperimentService.FixtureSet("synthetic-delivery-suite",
                    List.of(new VirtualExperimentService.Case("synthetic-delivery-case", SimulationSpec.KycStatus.VERIFIED,
                            List.of(ID_FACT, FACE_FACT)))));
            inputs = new VirtualProductAssembly.Inputs(seed.store, seed.catalog, terms,
                    (actor, operation, workflow, customer) -> seed.permitted.get(),
                    (actor, target, remediation) -> seed.remediationVerified.get(), fixtures,
                    new VirtualExperimentService.PairEvaluator() {
                        public String mode() { return VirtualTransactionalStore.MODE; }
                        public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                                String caseId, int repeat, Map<String, Object> proposal) {
                            pairCalls.incrementAndGet();
                            assertEquals("synthetic-delivery-case", caseId);
                            assertEquals(List.of(ID_FACT.toString(), FACE_FACT.toString()), proposal.get("evidenceIds"));
                            return new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.WAIT_APPROVAL,
                                    VirtualExperimentService.Reason.SYNTHETIC_REVIEW);
                        }
                    }, seed.clock, seed::id,
                    (request, operation, workflow, customer) -> {
                        if (!seed.permitted.get()) throw new WorkflowHttpController.Rejection(WorkflowHttpController.Denial.FORBIDDEN);
                        return ACTOR;
                    }, (request, operation, workflow) -> {
                        if (!seed.permitted.get()) throw SimulationFailure.forbidden(); return ACTOR;
                    }, limits);
            delivery = new VirtualProductAssembly.DeliveryInputs(executor, ACTOR, new VirtualKycJobAdapter.ProviderPort() {
                public String mode() { return VirtualTransactionalStore.MODE; }
                public Map<String, Object> evaluate(VirtualKycJobAdapter.Delivery d, Map<String, Object> input) {
                    providerCalls.incrementAndGet();
                    assertNotNull(d.expectedJobId()); assertEquals(d.expectedGeneration(), input.get("generation"));
                    return object("requestId", input.get("requestId"), "workflowId", input.get("workflowId"),
                            "generation", input.get("generation"), "runId", input.get("runId"), "inputSnapshotHash", input.get("inputSnapshotHash"),
                            "proposal", object("status", "VERIFIED", "evidenceIds", List.of(ID_FACT.toString(), FACE_FACT.toString()), "explanation", "synthetic check"),
                            "modelMetadata", object("model", "synthetic-model", "promptVersion", "KYC-PROMPT-1"));
                }
            }, seed::id, 2);
            application = configured
                    ? new VirtualHttpApplication(config, inputs, delivery, request -> VirtualHttpApplication.Access.ALLOW, () -> true)
                    : new VirtualHttpApplication(config, inputs, request -> VirtualHttpApplication.Access.ALLOW, () -> true);
            product = application.product();
            assertSame(seed.store, product.store()); assertTrue(seed.store.snapshot().isEmpty());
            assertEquals(0, providerCalls.get()); assertEquals(0, pairCalls.get());
        }
        MockHttpServletRequest request(UUID action) {
            var request = new MockHttpServletRequest(); request.addHeader("Idempotency-Key", action.toString()); return request;
        }
        Map<String, Object> start(UUID action) {
            var response = product.http().workflowController().start(request(action), object("businessReference", seed.app.businessReference(),
                    "customerId", seed.app.customerId(), "amountKrw", seed.app.amountKrw(), "payoutAccountId", seed.app.payoutAccountId().toString()));
            assertEquals(200, response.getStatusCode().value()); return Objects.requireNonNull(response.getBody());
        }
        UUID workflow(Map<String, Object> receipt) { return UUID.fromString((String) receipt.get("workflowId")); }
        Map<String, Object> view(UUID workflow) { return product.workflows().get(ACTOR, workflow); }
        @SuppressWarnings("unchecked")
        UUID activeJob(UUID workflow) { return UUID.fromString((String)((Map<String, Object>)view(workflow).get("activeJob")).get("jobId")); }
        @SuppressWarnings("unchecked")
        Map<String, Object> approve(UUID workflow) {
            var previewResponse = product.http().apiController().preview(request(seed.id()), workflow.toString());
            assertEquals(200, previewResponse.getStatusCode().value());
            var preview = (Map<String, Object>) previewResponse.getBody(); assertNotNull(preview);
            var response = product.http().apiController().approval(request(seed.id()), workflow.toString(),
                    object("decision", "APPROVE", "reviewSnapshotHash", preview.get("reviewSnapshotHash"), "comment", "synthetic review"));
            assertEquals(200, response.getStatusCode().value()); return (Map<String, Object>) response.getBody();
        }
    }

    @Test void configuredHttpGraphConsumesCommittedNotificationsThroughKycThenApprovalAndPayment() {
        var queue = new ManualQueue(); var f = new Fixture(queue, true); var request = f.seed.id();
        var created = f.start(request); UUID workflow = f.workflow(created);
        assertEquals("KYC_PENDING", created.get("state")); assertEquals(1, queue.tasks.size());
        assertEquals(0, f.providerCalls.get()); assertEquals(1, f.product.deliveries().status().queued());
        var replay = f.start(request); assertEquals(true, replay.get("replayed")); assertEquals(1, queue.tasks.size());
        queue.drainOne(); assertEquals(1, f.providerCalls.get()); assertEquals("WAIT_APPROVAL", f.view(workflow).get("state"));
        assertEquals(0, f.product.deliveries().status().unknown());
        var approved = f.approve(workflow); assertEquals("APPROVED", approved.get("state")); assertEquals(1, queue.tasks.size());
        assertTrue(f.seed.store.snapshot().getOrDefault("virtual_payments", Map.of()).isEmpty());
        queue.drainOne(); assertEquals("PAID", f.view(workflow).get("state"));
        assertEquals(1, f.seed.store.snapshot().get("virtual_payments").size());
        assertEquals(0, f.view(workflow).get("reservedRisk")); assertEquals(1, f.providerCalls.get());
        assertTrue(queue.tasks.isEmpty()); assertEquals(0, f.product.deliveries().status().running());
    }

    @Test void registeredReplayCreateIsDrivenByOneQueuedTaskAndKeepsItsOriginalPendingReceipt() {
        var queue = new ManualQueue(); var f = new Fixture(queue, true);
        var response = f.product.http().apiController().experiment(f.request(f.seed.id()), object("fixtureSetId", "synthetic-delivery-suite",
                "caseIds", List.of("synthetic-delivery-case"), "mode", "PAIRED", "modelMode", "REPLAY", "repeatCount", 2));
        assertEquals(200, response.getStatusCode().value());
        var accepted = (Map<?, ?>) response.getBody(); assertNotNull(accepted);
        assertEquals("PENDING", accepted.get("status")); UUID experiment = UUID.fromString((String) accepted.get("experimentId"));
        assertEquals(1, queue.tasks.size()); assertEquals(0, f.pairCalls.get());
        queue.drainOne(); var completed = f.product.experiments().get(ACTOR, experiment);
        assertEquals("COMPLETED", completed.get("status")); assertEquals(2, completed.get("completedPairs"));
        assertEquals(4, f.pairCalls.get()); assertTrue(queue.tasks.isEmpty());
        assertEquals("PENDING", accepted.get("status")); assertEquals(0, f.providerCalls.get());
    }

    @Test void rejectedDispatchDoesNotRewriteKnownCommittedStartAndHostCanExplicitlyEnqueuePendingJob() {
        var queue = new ManualQueue(); queue.reject = true; var f = new Fixture(queue, true); UUID request = f.seed.id();
        var accepted = f.start(request); UUID workflow = f.workflow(accepted);
        assertEquals("ALLOW", accepted.get("decision")); assertEquals("KYC_PENDING", accepted.get("state"));
        assertEquals(1L, f.product.deliveries().status().rejected()); assertEquals(0, f.providerCalls.get());
        assertTrue(queue.tasks.isEmpty()); assertNotNull(f.view(workflow).get("activeJob"));
        var globalBefore = f.seed.store.snapshot().get(ActionJournal.TABLE).get(request.toString());
        queue.reject = false;
        assertEquals(VirtualDeliveryCoordinator.Submission.ACCEPTED, f.product.deliveries().enqueueKyc(workflow, 1));
        assertEquals(globalBefore, f.seed.store.snapshot().get(ActionJournal.TABLE).get(request.toString()));
        queue.drainOne(); assertEquals("WAIT_APPROVAL", f.view(workflow).get("state"));
        assertEquals("KYC_PENDING", accepted.get("state")); assertEquals(1, f.providerCalls.get());
    }

    @Test void inlineExecutorCannotRunProviderOnCommittedRequestStack() {
        var f = new Fixture(Runnable::run, true); var accepted = f.start(f.seed.id());
        assertEquals("ALLOW", accepted.get("decision")); assertEquals("KYC_PENDING", accepted.get("state"));
        assertEquals(0, f.providerCalls.get()); assertEquals(1L, f.product.deliveries().status().rejected());
        assertEquals("KYC_PENDING", f.view(f.workflow(accepted)).get("state"));
    }

    @Test void oldQueuedGenerationCannotPrepareOrReserveReplacementJobAndOldRequestReplayDoesNotEnqueueIt() {
        var queue = new ManualQueue(); var f = new Fixture(queue, true); UUID request = f.seed.id();
        var created = f.start(request); UUID workflow = f.workflow(created), oldJob = f.activeJob(workflow);
        var q = f.product.quarantines().create(ACTOR, f.seed.id(), new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.WORKFLOW,
                object("workflowId", workflow.toString())), "SYNTHETIC_CONTAINMENT", "");
        f.product.quarantines().release(ACTOR, f.seed.id(), UUID.fromString((String) q.get("quarantineId")),
                new VirtualQuarantineService.Remediation(DOCUMENT, 2, List.of(ID_FACT), "synthetic remediation", null, null));
        var resumed = f.product.http().workflowController().resume(f.request(f.seed.id()), workflow.toString(),
                object("expectedGeneration", 1, "reason", "synthetic independent recovery"));
        assertEquals(200, resumed.getStatusCode().value()); assertEquals(2, f.view(workflow).get("generation"));
        UUID replacement = f.activeJob(workflow); assertNotEquals(oldJob, replacement); assertEquals(2, queue.tasks.size());
        var before = f.seed.store.snapshot();
        assertEquals(400, assertThrows(SimulationFailure.class,
                () -> f.product.workflows().prepareKyc(ACTOR, f.seed.id(), workflow, oldJob, 1)).status());
        assertEquals(400, assertThrows(SimulationFailure.class,
                () -> f.product.workflows().reservePayment(ACTOR, f.seed.id(), workflow, oldJob, 1)).status());
        assertEquals(before, f.seed.store.snapshot()); assertEquals(0, f.providerCalls.get());
        var oldReplay = f.start(request); assertEquals(1, oldReplay.get("generation")); assertEquals(2, queue.tasks.size());
        queue.drainOne(); assertEquals(0, f.providerCalls.get()); assertEquals(replacement, f.activeJob(workflow));
        queue.drainOne(); assertEquals(1, f.providerCalls.get()); assertEquals("WAIT_APPROVAL", f.view(workflow).get("state"));
        assertEquals(2, f.view(workflow).get("generation")); assertTrue(queue.tasks.isEmpty());
    }

    @Test void defaultApplicationStillHasNoDeliveryAndExplicitListenerPreparationStartsNothing() {
        var queue = new ManualQueue(); var f = new Fixture(queue, false); var accepted = f.start(f.seed.id());
        assertEquals("KYC_PENDING", accepted.get("state")); assertTrue(queue.tasks.isEmpty()); assertEquals(0, f.providerCalls.get());
        assertThrows(IllegalStateException.class, () -> f.product.deliveries());
        var clean = new Fixture(new ManualQueue(), true); var base = Path.of("/synthetic-delivery-fixture");
        var settings = new VirtualLoopbackListener.Settings(clean.config, base, base.resolve("doc"), base.resolve("work"),
                123, 2, 2, 1, 2, 0, 2, 1000, 2, 1000);
        var prepared = VirtualLoopbackListener.prepare(settings, clean.inputs, clean.delivery,
                request -> VirtualHttpApplication.Access.ALLOW, () -> true);
        assertEquals(VirtualLoopbackListener.State.PREPARED, prepared.state());
        assertTrue(clean.seed.store.snapshot().isEmpty()); assertEquals(0, clean.providerCalls.get()); assertEquals(0, clean.pairCalls.get());
    }
}
