package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.*;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit prepared data and finite fake resources only; no native start or external provider. */
class DataConfiguredVirtualApplicationFactoryTest {
    private static UUID id(long value) { return new UUID(0, value); }
    private static final class Executor extends AbstractExecutorService {
        int shutdowns, awaits, forced, submissions; boolean terminated, fail, interrupt;
        long wait; TimeUnit unit;
        public void execute(Runnable task) { submissions++; throw new AssertionError("No task submission"); }
        public void shutdown() { shutdowns++; }
        public List<Runnable> shutdownNow() { forced++; throw new AssertionError("No forced stop"); }
        public boolean isShutdown() { return shutdowns != 0; }
        public boolean isTerminated() { return terminated; }
        public boolean awaitTermination(long value, TimeUnit unit) throws InterruptedException {
            awaits++; wait = value; this.unit = unit;
            if (interrupt) throw new InterruptedException("synthetic");
            if (fail) throw new IllegalStateException("synthetic"); return terminated;
        }
    }
    private static final class Fixture {
        final HttpLimits limits = new HttpLimits(4096, 8192, 16);
        final SimulationSpec.Catalog catalog = new SimulationSpec.Catalog(List.of(), List.of());
        final SimulationSpec.RiskTerms terms = new SimulationSpec.RiskTerms("SYNTHETIC-ONLY", 1, 2, 3, 10, 2, 1, Duration.ofMinutes(1));
        final Executor executor = new Executor();
        final PreparedSyntheticProviders providers = new PreparedSyntheticProviders(List.of(), List.of(), 1, 1);
        final PreparedSecurityBindings security = new PreparedSecurityBindings(
            (actor, operation, workflow, customer) -> { throw new AssertionError("No authority query during prepare"); },
            (actor, target, remediation) -> { throw new AssertionError("No remediation query"); },
            (request, operation, workflow, customer) -> { throw new AssertionError("No actor query"); },
            (request, operation, workflow) -> { throw new AssertionError("No other actor query"); },
            request -> { throw new AssertionError("No readiness query"); },
            () -> { throw new AssertionError("No availability query"); });
        final PreparedVirtualConfiguration config;
        Fixture() {
            Path base = Path.of("/synthetic-unopened-data-factory");
            var settings = new VirtualLoopbackListener.Settings(new VirtualHttpApplication.Config("127.0.0.1", 18080,
                "/internal/v1/ready", limits, 1000, 1), base, base.resolve("doc"), base.resolve("work"),
                0, 2, 1, 1, 1, 0, 1, 1000, 2, 1000);
            config = new PreparedVirtualConfiguration(settings, catalog, terms, List.of(), 1,
                Clock.fixed(Instant.parse("2000-01-01T00:00:00Z"), ZoneOffset.UTC),
                () -> { throw new AssertionError("No generated identities"); }, new ActorRef("synthetic-data-actor"), 1);
        }
        DataConfiguredVirtualApplicationFactory factory(PreparedResourceLease lease) {
            return new DataConfiguredVirtualApplicationFactory(config, security, providers, lease);
        }
    }
    @Test void actualPrepareRetainsExplicitReferencesAndTransfersExactExecutorWithoutCallbacks() {
        var f = new Fixture(); var lease = PreparedResourceLease.owned(f.executor, 9); var factory = f.factory(lease);
        var prepared = factory.prepare(); var input = prepared.inputs();
        assertSame(f.config.listener(), prepared.settings()); assertSame(f.catalog, input.catalog());
        assertSame(f.terms, input.riskTerms()); assertSame(f.limits, input.httpLimits());
        assertSame(f.security.authority(), input.authority()); assertSame(f.security.startResumeActors(), input.startResumeActors());
        assertSame(f.security.otherActors(), input.otherActors()); assertSame(f.security.remediationVerifier(), input.remediationVerifier());
        assertSame(f.security.readiness(), prepared.authorization()); assertSame(f.security.dependenciesAvailable(), prepared.dependenciesAvailable());
        assertSame(f.config.actionIds(), input.ids()); assertSame(input.ids(), prepared.delivery().actionIds());
        assertSame(f.executor, prepared.delivery().executor()); assertSame(f.config.deliveryActor(), prepared.delivery().workflowActor());
        assertEquals(f.config.maximumInFlight(), prepared.delivery().maximumInFlight());
        assertSame(f.executor, ((ConfiguredVirtualApplicationHost.OwnedExecutor) prepared.ownership()).executor());
        assertNotNull(input.store()); assertSame(input.store(), prepared.inputs().store());
        assertEquals(PreparedResourceLease.State.TRANSFERRED, lease.state());
        assertEquals(PreparedResourceLease.Cleanup.TRANSFERRED_TO_PREPARED, lease.cleanup());
        assertThrows(IllegalStateException.class, factory::prepare);
        lease.close(); assertEquals(0, f.executor.shutdowns); assertEquals(0, f.executor.submissions);
        // Consume the returned actual Prepared through the public host, without native start.
        f.executor.terminated = true;
        var host = ConfiguredVirtualApplicationHost.prepare(prepared.settings(), prepared.inputs(), prepared.delivery(),
            prepared.authorization(), prepared.dependenciesAvailable(), prepared.ownership());
        assertEquals(ConfiguredVirtualApplicationHost.StopStatus.OWNED_RESOURCES_ACKNOWLEDGED, host.stop().status());
        assertEquals(1, f.executor.shutdowns); assertEquals(1, f.executor.awaits); assertEquals(0, f.executor.forced);
        lease.close(); assertEquals(1, f.executor.shutdowns);
    }
    @Test void separateFactoriesCreateDistinctEmptyStoresRatherThanReusingAnAmbientStore() {
        var f = new Fixture();
        var a = f.factory(PreparedResourceLease.borrowed(f.executor)).prepare();
        var b = f.factory(PreparedResourceLease.borrowed(f.executor)).prepare();
        assertNotSame(a.inputs().store(), b.inputs().store());
        assertEquals(VirtualTransactionalStore.MODE, a.inputs().pairEvaluator().mode());
        assertEquals(VirtualTransactionalStore.MODE, a.delivery().provider().mode());
        assertEquals(0, f.executor.submissions); assertEquals(0, f.executor.shutdowns);
    }
    @Test void missingTrustedBindingsRejectBeforeClaimAndNeverSupplyDefaultAuthority() {
        var f = new Fixture(); var lease = PreparedResourceLease.owned(f.executor, 9); var s = f.security;
        assertThrows(NullPointerException.class, () -> new PreparedSecurityBindings(null, s.remediationVerifier(), s.startResumeActors(), s.otherActors(), s.readiness(), s.dependenciesAvailable()));
        assertThrows(NullPointerException.class, () -> new PreparedSecurityBindings(s.authority(), null, s.startResumeActors(), s.otherActors(), s.readiness(), s.dependenciesAvailable()));
        assertThrows(NullPointerException.class, () -> new PreparedSecurityBindings(s.authority(), s.remediationVerifier(), null, s.otherActors(), s.readiness(), s.dependenciesAvailable()));
        assertThrows(NullPointerException.class, () -> new PreparedSecurityBindings(s.authority(), s.remediationVerifier(), s.startResumeActors(), null, s.readiness(), s.dependenciesAvailable()));
        assertThrows(NullPointerException.class, () -> new PreparedSecurityBindings(s.authority(), s.remediationVerifier(), s.startResumeActors(), s.otherActors(), null, s.dependenciesAvailable()));
        assertThrows(NullPointerException.class, () -> new PreparedSecurityBindings(s.authority(), s.remediationVerifier(), s.startResumeActors(), s.otherActors(), s.readiness(), null));
        assertThrows(NullPointerException.class, () -> new DataConfiguredVirtualApplicationFactory(f.config, null, f.providers, lease));
        assertEquals(PreparedResourceLease.State.AVAILABLE, lease.state()); assertEquals(0, f.executor.shutdowns);
        lease.close(); assertEquals(1, f.executor.shutdowns);
    }
    @Test void configurationCapturesFixtureMembershipAndRejectsBoundOrDuplicateChanges() {
        var f = new Fixture(); var fixture = new VirtualExperimentService.FixtureSet("synthetic-fixture",
            List.of(new VirtualExperimentService.Case("synthetic-case", SimulationSpec.KycStatus.NEEDS_REVIEW, List.of())));
        var supplied = new ArrayList<>(List.of(fixture)); var c = f.config;
        var captured = new PreparedVirtualConfiguration(c.listener(), c.catalog(), c.riskTerms(), supplied, 1,
            c.clock(), c.actionIds(), c.deliveryActor(), c.maximumInFlight());
        supplied.clear(); assertEquals(List.of(fixture), captured.fixtureSets());
        assertThrows(UnsupportedOperationException.class, () -> captured.fixtureSets().clear());
        assertThrows(IllegalArgumentException.class, () -> new PreparedVirtualConfiguration(c.listener(), c.catalog(), c.riskTerms(),
            List.of(fixture, fixture), 2, c.clock(), c.actionIds(), c.deliveryActor(), c.maximumInFlight()));
        assertThrows(IllegalArgumentException.class, () -> new PreparedVirtualConfiguration(c.listener(), c.catalog(), c.riskTerms(),
            List.of(fixture), 0, c.clock(), c.actionIds(), c.deliveryActor(), c.maximumInFlight()));
    }
    @Test void exactKycDeliveryAndOrderedInputAreRequiredAndNestedResponseIsDefensivelyCopied() {
        var delivery = new VirtualKycJobAdapter.Delivery(id(1), id(2), id(3), id(4), 1);
        var input = new LinkedHashMap<String,Object>(); input.put("first", 1); input.put("second", 2);
        var nested = new LinkedHashMap<String,Object>(); nested.put("marker", "synthetic-mapped-response");
        var response = new LinkedHashMap<String,Object>(); response.put("nested", nested);
        var entry = new PreparedSyntheticProviders.KycEntry(delivery, CanonicalJson.orderedSha256(input), response);
        var entries = new ArrayList<>(List.of(entry));
        var providers = new PreparedSyntheticProviders(entries, List.of(), 1, 1); entries.clear(); nested.put("marker", "changed");
        var actual = providers.kyc().evaluate(delivery, input);
        assertEquals(Map.of("nested", Map.of("marker", "synthetic-mapped-response")), actual);
        assertThrows(UnsupportedOperationException.class, () -> actual.put("other", true));
        assertThrows(UnsupportedOperationException.class, () -> ((Map<?,?>) actual.get("nested")).clear());
        var reversed = new LinkedHashMap<String,Object>(); reversed.put("second", 2); reversed.put("first", 1);
        assertEquals("SYNTHETIC_RESPONSE_UNAVAILABLE", assertThrows(IllegalStateException.class,
            () -> providers.kyc().evaluate(delivery, reversed)).getMessage());
        assertThrows(IllegalStateException.class, () -> providers.kyc().evaluate(
            new VirtualKycJobAdapter.Delivery(id(1), id(2), id(3), id(5), 1), input));
        assertFalse(entry.toString().contains("synthetic-mapped-response"));
    }
    @Test void exactPairCoordinatesAndProposalAreRequiredWithNoFabricatedAllowOnMissingMapping() {
        var expected = new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.WAIT_APPROVAL,
            VirtualExperimentService.Reason.SYNTHETIC_REVIEW);
        var proposal = Map.<String,Object>of("synthetic", "known");
        var entry = new PreparedSyntheticProviders.PairEntry(VirtualExperimentService.Environment.FUSE,
            "synthetic-case", 1, CanonicalJson.sha256(proposal), expected);
        var providers = new PreparedSyntheticProviders(List.of(), List.of(entry), 1, 1);
        assertSame(expected, providers.pairs().evaluate(VirtualExperimentService.Environment.FUSE, "synthetic-case", 1, proposal));
        assertThrows(IllegalStateException.class, () -> providers.pairs().evaluate(VirtualExperimentService.Environment.BASELINE, "synthetic-case", 1, proposal));
        assertThrows(IllegalStateException.class, () -> providers.pairs().evaluate(VirtualExperimentService.Environment.FUSE, "synthetic-other", 1, proposal));
        assertThrows(IllegalStateException.class, () -> providers.pairs().evaluate(VirtualExperimentService.Environment.FUSE, "synthetic-case", 2, proposal));
        assertThrows(IllegalStateException.class, () -> providers.pairs().evaluate(VirtualExperimentService.Environment.FUSE, "synthetic-case", 1, Map.of("synthetic", "different")));
        assertThrows(IllegalArgumentException.class, () -> new PreparedSyntheticProviders(List.of(), List.of(entry, entry), 1, 2));
        assertThrows(IllegalStateException.class, () -> new PreparedSyntheticProviders(List.of(), List.of(), 1, 1).pairs()
            .evaluate(VirtualExperimentService.Environment.FUSE, "synthetic-case", 1, proposal));
    }
    @Test void ownedClaimedLeaseCleanupPreservesFalseOrThrowingTerminationWithoutRetry() {
        for (boolean failure : new boolean[] {false, true}) {
            var executor = new Executor(); executor.fail = failure;
            var lease = PreparedResourceLease.owned(executor, 9); lease.claim();
            assertEquals(PreparedResourceLease.State.CLAIMED, lease.state());
            lease.close(); assertEquals(PreparedResourceLease.State.CLOSED, lease.state());
            assertEquals(PreparedResourceLease.Cleanup.UNCONFIRMED, lease.cleanup());
            executor.terminated = true; lease.close();
            assertEquals(PreparedResourceLease.Cleanup.UNCONFIRMED, lease.cleanup());
            assertEquals(1, executor.shutdowns); assertEquals(1, executor.awaits);
            assertEquals(9, executor.wait); assertEquals(TimeUnit.MILLISECONDS, executor.unit); assertEquals(0, executor.forced);
            assertThrows(IllegalStateException.class, lease::claim);
        }
    }
    @Test void borrowedUnclaimedOrClaimedLeaseNeverShutsDownExternalExecutor() {
        for (boolean claim : new boolean[] {false, true}) {
            var executor = new Executor(); var lease = PreparedResourceLease.borrowed(executor);
            if (claim) lease.claim(); lease.close(); lease.close();
            assertEquals(PreparedResourceLease.Cleanup.BORROWED_NOT_CLOSED, lease.cleanup());
            assertEquals(PreparedResourceLease.State.CLOSED, lease.state());
            assertEquals(0, executor.shutdowns); assertEquals(0, executor.awaits); assertEquals(0, executor.forced);
        }
    }
    @Test void interruptedOwnedCleanupRestoresFlagAndCachesUnconfirmedState() {
        boolean previous = Thread.currentThread().isInterrupted();
        try {
            Thread.interrupted(); var executor = new Executor(); executor.interrupt = true;
            var lease = PreparedResourceLease.owned(executor, 9); lease.close();
            assertTrue(Thread.currentThread().isInterrupted()); assertEquals(PreparedResourceLease.Cleanup.UNCONFIRMED, lease.cleanup());
            lease.close(); assertEquals(1, executor.awaits); assertEquals(0, executor.forced);
        } finally { Thread.interrupted(); if (previous) Thread.currentThread().interrupt(); }
    }
}
