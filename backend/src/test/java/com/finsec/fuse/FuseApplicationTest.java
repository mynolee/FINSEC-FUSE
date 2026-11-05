package com.finsec.fuse;

import com.finsec.fuse.reimplementation.application.*;
import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.*;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.FuseApplication.*;
import static com.finsec.fuse.reimplementation.application.ConfiguredVirtualApplicationHost.*;
import static com.finsec.fuse.reimplementation.application.VirtualLoopbackListener.StartResult.*;

/** Injected ports only: never invokes standard main, ServiceLoader, JVM hooks or a native listener. */
class FuseApplicationTest {
    private static final String CANARY = "synthetic-hidden-startup-path-and-cause";
    private PreparedVirtualApplicationFactory.Prepared prepared() {
        var limits = new HttpLimits(4096, 8192, 16);
        var inputs = new VirtualProductAssembly.Inputs(new VirtualTransactionalStore(),
            new SimulationSpec.Catalog(List.of(), List.of()),
            new SimulationSpec.RiskTerms("SYNTHETIC-ONLY", 1, 2, 3, 10, 2, 1, Duration.ofMinutes(1)),
            (actor, operation, workflow, customer) -> false, (actor, target, remediation) -> false,
            List.of(), new VirtualExperimentService.PairEvaluator() {
                public String mode() { return VirtualTransactionalStore.MODE; }
                public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                        String caseId, int repeat, Map<String,Object> shared) { throw new AssertionError("No evaluation"); }
            }, Clock.fixed(Instant.parse("2000-01-01T00:00:00Z"), ZoneOffset.UTC),
            () -> { throw new AssertionError("No IDs"); },
            (request, operation, workflow, customer) -> null, (request, operation, workflow) -> null, limits);
        var base = Path.of("/synthetic-unopened-entrypoint");
        var settings = new VirtualLoopbackListener.Settings(new VirtualHttpApplication.Config("127.0.0.1", 18080,
            "/internal/v1/ready", limits, 1000, 1), base, base.resolve("doc"), base.resolve("work"),
            0, 2, 1, 1, 1, 0, 1, 1000, 2, 1000);
        var delivery = new VirtualProductAssembly.DeliveryInputs(task -> { throw new AssertionError("No execution"); },
            new ActorRef("synthetic-startup-actor"), new VirtualKycJobAdapter.ProviderPort() {
                public String mode() { return VirtualTransactionalStore.MODE; }
                public Map<String,Object> evaluate(VirtualKycJobAdapter.Delivery delivery, Map<String,Object> input) {
                    throw new AssertionError("No provider");
                }
            }, () -> { throw new AssertionError("No delivery IDs"); }, 1);
        return new PreparedVirtualApplicationFactory.Prepared(settings, inputs, delivery,
            request -> { throw new AssertionError("No readiness request"); },
            () -> { throw new AssertionError("No dependency probe"); }, new BorrowedDelivery());
    }
    private static final class FakeHost implements Host {
        int starts, stops; Runnable duringStart; boolean failStart, failStop;
        VirtualLoopbackListener.StartResult answer = STARTED;
        final List<String> events;
        final StopReport stopped = new StopReport(StopStatus.EXTERNAL_DELIVERY_UNCONFIRMED, true, false, true);
        FakeHost(List<String> events) { this.events = events; }
        public VirtualLoopbackListener.StartResult start() {
            starts++; events.add("start"); if (duringStart != null) duringStart.run();
            if (failStart) throw new IllegalStateException(CANARY); return answer;
        }
        public StopReport stop() {
            stops++; events.add("stop"); if (failStop) throw new IllegalStateException(CANARY); return stopped;
        }
    }
    private FactoryResolver one(PreparedVirtualApplicationFactory.Prepared supplied, AtomicInteger instances) {
        return () -> List.of(() -> { instances.incrementAndGet(); return () -> supplied; });
    }
    private static void noAuthority(LaunchResult result) {
        assertFalse(result.executionAuthorityGranted()); assertFalse(result.productionReady());
        assertFalse(result.toString().contains(CANARY));
    }
    @Test void zeroAndAmbiguousDescriptorsNeverInstantiateOrPrepare() {
        var instances = new AtomicInteger(); var preparations = new AtomicInteger();
        Supplier<PreparedVirtualApplicationFactory> descriptor = () -> { instances.incrementAndGet();
            throw new AssertionError("Must count descriptors first"); };
        for (var descriptors : List.of(List.<Supplier<PreparedVirtualApplicationFactory>>of(), List.of(descriptor, descriptor))) {
            var result = launch(new String[0], () -> descriptors,
                stop -> { throw new AssertionError("No hook"); }, supplied -> { preparations.incrementAndGet(); return null; });
            assertEquals(Status.CONFIGURATION_REQUIRED, result.status());
            assertFalse(result.factoryInstantiationAttempted()); assertFalse(result.hostPreparationAttempted());
            assertFalse(result.startAttempted()); assertEquals(CleanupKnowledge.NO_FACTORY_ATTEMPT, result.cleanupKnowledge());
            noAuthority(result);
        }
        assertEquals(0, instances.get()); assertEquals(0, preparations.get());
    }
    @Test void invalidArgumentsAndMalformedDescriptorsNeverBecomeDefaultStartup() {
        var calls = new AtomicInteger();
        FactoryResolver resolver = () -> { calls.incrementAndGet(); return List.of(); };
        for (String[] args : new String[][] {null, {CANARY}}) {
            var result = launch(args, resolver, stop -> fail("No hook"), supplied -> { fail("No host"); return null; });
            assertEquals(Status.CONFIGURATION_REQUIRED, result.status()); noAuthority(result);
        }
        assertEquals(0, calls.get());
        var malformed = launch(new String[0], () -> null, stop -> fail("No hook"), supplied -> null);
        assertEquals(Status.CONFIGURATION_REQUIRED, malformed.status());
        assertFalse(malformed.factoryInstantiationAttempted()); noAuthority(malformed);
    }
    @Test void failedPreparedAdmissionRetainsUnknownWithoutInventingAHostHandle() {
        var instances = new AtomicInteger(); var hostCalls = new AtomicInteger();
        FactoryResolver resolver = () -> List.of(() -> { instances.incrementAndGet();
            return () -> new PreparedVirtualApplicationFactory.Prepared(null, null, null, null, null, null); });
        var result = launch(new String[0], resolver, stop -> fail("No hook"), supplied -> { hostCalls.incrementAndGet(); return null; });
        assertEquals(Status.CONFIGURATION_REQUIRED, result.status()); assertTrue(result.factoryInstantiationAttempted());
        assertFalse(result.hostPreparationAttempted()); assertFalse(result.startAttempted());
        assertEquals(CleanupKnowledge.UNCONFIRMED_WITHOUT_HANDLE, result.cleanupKnowledge());
        assertNull(result.stopReport()); assertEquals(1, instances.get()); assertEquals(0, hostCalls.get()); noAuthority(result);
    }
    @Test void exactPreparedObjectFlowsToOneHostAndHookPrecedesOneStart() {
        var supplied = prepared(); var events = new ArrayList<String>(); var host = new FakeHost(events);
        var instances = new AtomicInteger(); Runnable[] hook = new Runnable[1];
        var result = launch(new String[0], one(supplied, instances), stop -> { events.add("hook"); hook[0] = stop; },
            actual -> { assertSame(supplied, actual); events.add("prepare"); return host; });
        assertEquals(List.of("prepare", "hook", "start"), events); assertEquals(1, instances.get());
        assertEquals(Status.STARTED, result.status()); assertEquals(HookStatus.REGISTERED, result.hookStatus());
        assertTrue(result.startAttempted()); assertEquals(CleanupKnowledge.NOT_REQUESTED, result.cleanupKnowledge());
        assertNull(result.stopReport()); assertEquals(0, host.stops); noAuthority(result);
        hook[0].run(); hook[0].run(); assertEquals(1, host.starts); assertEquals(1, host.stops);
    }
    @Test void partiallyRegisteredDeniedHookStopsOnceAndCachesUncertainty() {
        var host = new FakeHost(new ArrayList<>()); host.failStop = true; Runnable[] captured = new Runnable[1];
        var result = launch(new String[0], one(prepared(), new AtomicInteger()), stop -> {
            captured[0] = stop; throw new IllegalStateException(CANARY);
        }, supplied -> host);
        assertEquals(Status.HOOK_REGISTRATION_FAILED, result.status()); assertEquals(HookStatus.UNCONFIRMED, result.hookStatus());
        assertFalse(result.startAttempted()); assertEquals(0, host.starts); assertEquals(1, host.stops);
        assertEquals(StopStatus.UNCONFIRMED, result.stopReport().status()); assertTrue(result.stopReport().deliveryExternallyOwned());
        assertFalse(result.stopReport().listenerAcknowledged()); assertFalse(result.stopReport().providerResourcesClosed());
        captured[0].run(); assertEquals(1, host.stops); noAuthority(result);
    }
    @Test void nonSuccessfulOrThrowingStartCleansOnlySameHostWithoutRetry() {
        for (int mode = 0; mode < 4; mode++) {
            var host = new FakeHost(new ArrayList<>()); Runnable[] hook = new Runnable[1];
            host.answer = mode == 0 ? START_FAILED_CLEANUP_ACKNOWLEDGED
                : mode == 1 ? START_FAILED_RESIDUAL_UNCONFIRMED : null;
            host.failStart = mode == 3;
            var result = launch(new String[0], one(prepared(), new AtomicInteger()), stop -> hook[0] = stop, supplied -> host);
            assertEquals(mode == 0 ? Status.START_FAILED : Status.START_UNCONFIRMED, result.status());
            assertEquals(1, host.starts); assertEquals(1, host.stops); assertSame(host.stopped, result.stopReport());
            assertEquals(CleanupKnowledge.STOP_REPORT_AVAILABLE, result.cleanupKnowledge());
            assertEquals(StopStatus.EXTERNAL_DELIVERY_UNCONFIRMED, result.stopReport().status());
            hook[0].run(); assertEquals(1, host.stops); noAuthority(result);
        }
    }
    @Test void inlineStopBeforeStartPreventsStartAndDoesNotPretendRunning() {
        var host = new FakeHost(new ArrayList<>());
        var result = launch(new String[0], one(prepared(), new AtomicInteger()), Runnable::run, supplied -> host);
        assertEquals(Status.STOPPED_BEFORE_START, result.status()); assertFalse(result.startAttempted());
        assertEquals(0, host.starts); assertEquals(1, host.stops); assertSame(host.stopped, result.stopReport()); noAuthority(result);
    }
    @Test void finiteReentrantStopDuringStartDoesNotReportAnActiveHost() {
        var host = new FakeHost(new ArrayList<>()); Runnable[] hook = new Runnable[1];
        host.duringStart = () -> hook[0].run();
        var result = launch(new String[0], one(prepared(), new AtomicInteger()), stop -> hook[0] = stop, supplied -> host);
        assertEquals(Status.STOPPED_DURING_START, result.status()); assertTrue(result.startAttempted());
        assertEquals(1, host.starts); assertEquals(1, host.stops); assertSame(host.stopped, result.stopReport());
        hook[0].run(); assertEquals(1, host.stops); noAuthority(result);
    }
    /** No threads, queued tasks or native resources: only explicit ownership call observations. */
    private static final class FakeOwnedExecutor extends java.util.concurrent.AbstractExecutorService {
        int shutdowns, awaits, shutdownNows, executions;
        long waitedMillis;
        int awaitMode;
        public void shutdown() { shutdowns++; }
        public List<Runnable> shutdownNow() { shutdownNows++; throw new AssertionError("No forced task interruption"); }
        public boolean isShutdown() { return shutdowns != 0; }
        public boolean isTerminated() { return shutdowns != 0 && awaitMode == 0; }
        public boolean awaitTermination(long timeout, java.util.concurrent.TimeUnit unit) throws InterruptedException {
            awaits++; waitedMillis = unit.toMillis(timeout);
            if (awaitMode == 2) throw new IllegalStateException(CANARY);
            if (awaitMode == 3) throw new InterruptedException(CANARY);
            return awaitMode == 0;
        }
        public void execute(Runnable task) { executions++; throw new AssertionError("No executor task"); }
    }
    private PreparedVirtualApplicationFactory.Prepared preparedWith(FakeOwnedExecutor executor, boolean owned) {
        var original = prepared();
        var delivery = original.delivery();
        var matching = new VirtualProductAssembly.DeliveryInputs(executor, delivery.workflowActor(), delivery.provider(),
            delivery.actionIds(), delivery.maximumInFlight());
        return new PreparedVirtualApplicationFactory.Prepared(original.settings(), original.inputs(), matching,
            original.authorization(), original.dependenciesAvailable(),
            owned ? new OwnedExecutor(executor, 37) : new BorrowedDelivery());
    }
    private LaunchResult failBeforeHost(PreparedVirtualApplicationFactory.Prepared supplied, boolean nullHost) {
        var instances = new AtomicInteger(); var hostCalls = new AtomicInteger();
        var result = launch(new String[0], one(supplied, instances), stop -> fail("No hook before Host"), actual -> {
            hostCalls.incrementAndGet(); assertSame(supplied, actual);
            if (nullHost) return null;
            throw new IllegalStateException(CANARY);
        });
        assertEquals(1, instances.get()); assertEquals(1, hostCalls.get());
        assertEquals(Status.CONFIGURATION_REQUIRED, result.status());
        assertTrue(result.factoryInstantiationAttempted()); assertTrue(result.hostPreparationAttempted());
        assertFalse(result.startAttempted()); assertEquals(HookStatus.NOT_ATTEMPTED, result.hookStatus());
        assertEquals(CleanupKnowledge.UNCONFIRMED_WITHOUT_HANDLE, result.cleanupKnowledge());
        assertNull(result.stopReport()); noAuthority(result);
        return result;
    }
    @Test void ownedPreparedHostThrowOrNullClosesOnlyExactExecutorOnceWithoutAggregateAcknowledgement() {
        for (boolean nullHost : new boolean[] {false, true}) {
            var executor = new FakeOwnedExecutor();
            var supplied = preparedWith(executor, true);
            failBeforeHost(supplied, nullHost);
            assertSame(executor, supplied.delivery().executor());
            assertEquals(1, executor.shutdowns); assertEquals(1, executor.awaits);
            assertEquals(37, executor.waitedMillis);
            assertEquals(0, executor.shutdownNows); assertEquals(0, executor.executions);
        }
    }
    @Test void borrowedPreparedHostFailureDoesNotShutdownOrAwaitBorrowedExecutor() {
        for (boolean nullHost : new boolean[] {false, true}) {
            var executor = new FakeOwnedExecutor();
            failBeforeHost(preparedWith(executor, false), nullHost);
            assertEquals(0, executor.shutdowns); assertEquals(0, executor.awaits);
            assertEquals(0, executor.shutdownNows); assertEquals(0, executor.executions);
        }
    }
    @Test void ownedAwaitFalseOrOrdinaryFailureNeverBecomesOverallCleanupSuccess() {
        for (int mode : new int[] {1, 2}) {
            for (boolean nullHost : new boolean[] {false, true}) {
                var executor = new FakeOwnedExecutor(); executor.awaitMode = mode;
                failBeforeHost(preparedWith(executor, true), nullHost);
                assertEquals(1, executor.shutdowns); assertEquals(1, executor.awaits);
                assertEquals(37, executor.waitedMillis); assertEquals(0, executor.shutdownNows);
                assertEquals(0, executor.executions);
            }
        }
    }
    @Test void ownedAwaitInterruptIsRestoredWithoutRetryOrFalseStopReport() {
        boolean priorInterrupt = Thread.currentThread().isInterrupted();
        try {
            // No thread is started; isolate and restore only this test thread's interrupt bit.
            Thread.interrupted();
            var executor = new FakeOwnedExecutor(); executor.awaitMode = 3;
            failBeforeHost(preparedWith(executor, true), false);
            assertTrue(Thread.currentThread().isInterrupted());
            assertEquals(1, executor.shutdowns); assertEquals(1, executor.awaits);
            assertEquals(37, executor.waitedMillis); assertEquals(0, executor.shutdownNows);
            assertEquals(0, executor.executions);
        } finally {
            Thread.interrupted();
            if (priorInterrupt) Thread.currentThread().interrupt();
        }
    }

}
