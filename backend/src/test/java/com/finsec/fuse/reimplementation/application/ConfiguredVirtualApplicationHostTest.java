package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.*;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.application.ConfiguredVirtualApplicationHost.*;

/** Prepared-only lifecycle tests; no listener start, filesystem preparation or real executor. */
class ConfiguredVirtualApplicationHostTest {
    private final HttpLimits limits = new HttpLimits(4096, 8192, 16);
    private VirtualProductAssembly.Inputs inputs() {
        return new VirtualProductAssembly.Inputs(new VirtualTransactionalStore(),
            new SimulationSpec.Catalog(List.of(), List.of()),
            new SimulationSpec.RiskTerms("SYNTHETIC-ONLY", 1, 2, 3, 10, 2, 1, Duration.ofMinutes(1)),
            (actor, operation, workflow, customer) -> false, (actor, target, remediation) -> false,
            List.of(), new VirtualExperimentService.PairEvaluator() {
                public String mode() { return VirtualTransactionalStore.MODE; }
                public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                        String caseId, int repeat, Map<String,Object> shared) { throw new AssertionError("No evaluation"); }
            }, Clock.fixed(Instant.parse("2000-01-01T00:00:00Z"), ZoneOffset.UTC),
            () -> { throw new AssertionError("No identifiers"); },
            (request, operation, workflow, customer) -> null, (request, operation, workflow) -> null, limits);
    }
    private VirtualLoopbackListener.Settings settings(HttpLimits supplied) {
        Path base = Path.of("/synthetic-configured-host-unused");
        return new VirtualLoopbackListener.Settings(new VirtualHttpApplication.Config("127.0.0.1", 18080,
            "/internal/v1/ready", supplied, 1000, 1), base, base.resolve("doc"), base.resolve("work"),
            0, 2, 1, 1, 1, 0, 1, 1000, 2, 1000);
    }
    private VirtualProductAssembly.DeliveryInputs delivery(FakeExecutor executor) {
        return new VirtualProductAssembly.DeliveryInputs(executor, new ActorRef("synthetic-host-actor"),
            new VirtualKycJobAdapter.ProviderPort() {
                public String mode() { return VirtualTransactionalStore.MODE; }
                public Map<String,Object> evaluate(VirtualKycJobAdapter.Delivery delivery, Map<String,Object> input) {
                    throw new AssertionError("No provider");
                }
            }, () -> { throw new AssertionError("No action identifiers"); }, 1);
    }
    private ConfiguredVirtualApplicationHost host(FakeExecutor executor, DeliveryOwnership ownership) {
        return ConfiguredVirtualApplicationHost.prepare(settings(limits), inputs(), delivery(executor),
            request -> { throw new AssertionError("No readiness request"); },
            () -> { throw new AssertionError("No readiness probe"); }, ownership);
    }
    @Test void prepareRetainsOneConfiguredListenerWithoutSubmittingOrStarting() {
        var executor = new FakeExecutor(); var ownership = new OwnedExecutor(executor, 7);
        var host = host(executor, ownership);
        assertSame(host.listener(), host.listener()); assertSame(ownership, host.deliveryOwnership());
        assertEquals(State.PREPARED, host.state());
        assertEquals(VirtualLoopbackListener.State.PREPARED, host.listener().state());
        assertEquals(0, executor.submissions); assertEquals(0, executor.shutdowns); assertEquals(0, executor.awaits);
        host.close();
    }
    @Test void exactExecutorIdentityAndMatchingLimitsAreRequiredBeforePreparation() {
        var executor = new FakeExecutor();
        assertThrows(IllegalArgumentException.class, () -> host(executor, new OwnedExecutor(new FakeExecutor(), 7)));
        assertThrows(IllegalArgumentException.class, () -> ConfiguredVirtualApplicationHost.prepare(
            settings(new HttpLimits(4097, 8192, 16)), inputs(), delivery(executor), request -> null,
            () -> true, new BorrowedDelivery()));
        assertThrows(IllegalArgumentException.class, () -> new OwnedExecutor(executor, 0));
        assertEquals(0, executor.submissions); assertEquals(0, executor.shutdowns);
    }
    @Test void borrowedExecutorIsNeverShutDownAndProviderClosureIsNotClaimed() {
        var executor = new FakeExecutor(); var host = host(executor, new BorrowedDelivery());
        var report = host.stop();
        assertEquals(StopStatus.EXTERNAL_DELIVERY_UNCONFIRMED, report.status());
        assertTrue(report.listenerAcknowledged()); assertTrue(report.deliveryExternallyOwned());
        assertFalse(report.ownedExecutorTerminated()); assertFalse(report.providerResourcesClosed());
        assertFalse(report.executionAuthorityGranted()); assertEquals(0, executor.shutdowns);
        assertEquals(0, executor.awaits); assertEquals(0, executor.forced);
        assertEquals(State.EXTERNAL_DELIVERY_UNCONFIRMED, host.state());
    }
    @Test void ownedAcknowledgementRequiresTerminationAndUsesExplicitFiniteWait() {
        var executor = new FakeExecutor(); executor.terminate = true;
        var host = host(executor, new OwnedExecutor(executor, 7)); var report = host.stop();
        assertEquals(StopStatus.OWNED_RESOURCES_ACKNOWLEDGED, report.status());
        assertTrue(report.listenerAcknowledged()); assertTrue(report.ownedExecutorTerminated());
        assertFalse(report.deliveryExternallyOwned()); assertFalse(report.providerResourcesClosed());
        assertEquals(1, executor.shutdowns); assertEquals(1, executor.awaits);
        assertEquals(7, executor.wait); assertEquals(TimeUnit.MILLISECONDS, executor.unit);
        assertEquals(0, executor.forced); assertEquals(State.STOPPED_OWNED_RESOURCES, host.state());
    }
    @Test void incompleteOrThrowingTerminationStaysUnknownAndFirstReportIsRetained() {
        for (boolean failure : new boolean[] {false, true}) {
            var executor = new FakeExecutor(); executor.fail = failure;
            var host = host(executor, new OwnedExecutor(executor, 7)); var first = host.stop();
            assertEquals(StopStatus.UNCONFIRMED, first.status()); assertFalse(first.ownedExecutorTerminated());
            assertEquals(State.RESIDUAL_UNCONFIRMED, host.state()); executor.terminate = true;
            assertSame(first, host.stop()); host.close();
            assertEquals(1, executor.shutdowns); assertEquals(1, executor.awaits); assertEquals(0, executor.forced);
        }
    }
    @Test void interruptedWaitRestoresCallingFlagWithoutForcedShutdownOrRetry() {
        boolean prior = Thread.currentThread().isInterrupted();
        try {
            Thread.interrupted();
            var executor = new FakeExecutor(); executor.interrupt = true;
            var host = host(executor, new OwnedExecutor(executor, 7)); var report = host.stop();
            assertTrue(Thread.currentThread().isInterrupted());
            assertEquals(StopStatus.UNCONFIRMED, report.status()); assertFalse(report.ownedExecutorTerminated());
            assertSame(report, host.stop()); assertEquals(1, executor.awaits); assertEquals(0, executor.forced);
        } finally {
            Thread.interrupted(); if (prior) Thread.currentThread().interrupt();
        }
    }
    private static final class FakeExecutor extends AbstractExecutorService {
        int submissions, shutdowns, awaits, forced; long wait; TimeUnit unit;
        boolean terminate, fail, interrupt;
        public void execute(Runnable command) { submissions++; throw new AssertionError("No submission"); }
        public void shutdown() { shutdowns++; }
        public List<Runnable> shutdownNow() { forced++; throw new AssertionError("No forced cleanup"); }
        public boolean isShutdown() { return shutdowns > 0; }
        public boolean isTerminated() { return terminate; }
        public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
            awaits++; wait = timeout; this.unit = unit;
            if (interrupt) throw new InterruptedException("synthetic");
            if (fail) throw new IllegalStateException("synthetic");
            return terminate;
        }
    }
}
