package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.persistence.*;
import java.util.*;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;

/** Public-read failure boundaries with real typed history and scoped read-only faults. */
class VirtualTypedWorkflowReadProjectionBoundaryTest {
    private static final String WORKFLOWS = "virtual_workflows", HEADS = "virtual_grant_profile_current_heads";
    private static final String LANES = "virtual_workflow_lanes", TARGETS = "virtual_grant_profile_target_bindings";
    private static UUID id(long n) { return VirtualGrantContinuationFixture.id(n); }
    private record Fault(String table, String key, String field, Object replacement, boolean missing) { }
    private static final class ReadFaultStore implements TransactionalStore {
        final VirtualTransactionalStore delegate = new VirtualTransactionalStore();
        Fault fault; int faultHits, publications, writes;
        public String mode() { return delegate.mode(); }
        public Map<String, Map<String, Map<String, Object>>> snapshot() { return delegate.snapshot(); }
        private Map<String, Object> row(String table, String key, Map<String, Object> original) {
            if (fault == null || original == null || !fault.table().equals(table) || !fault.key().equals(key)) return original;
            faultHits++;
            if (fault.missing()) return null;
            var changed = new LinkedHashMap<>(original); changed.put(fault.field(), fault.replacement());
            return Collections.unmodifiableMap(changed);
        }
        public <R> R transaction(Function<Tx, R> work) {
            R result = delegate.transaction(tx -> work.apply(new Tx() {
                public Map<String, Object> get(String table, String key) { return row(table, key, tx.get(table, key)); }
                public Map<String, Map<String, Object>> rows(String table) {
                    var actual = tx.rows(table);
                    if (fault == null || !fault.table().equals(table) || !actual.containsKey(fault.key())) return actual;
                    var copy = new LinkedHashMap<>(actual);
                    var changed = row(table, fault.key(), actual.get(fault.key()));
                    if (changed == null) copy.remove(fault.key()); else copy.put(fault.key(), changed);
                    return Collections.unmodifiableMap(copy);
                }
                public void put(String table, String key, Map<String, Object> value) { writes++; tx.put(table, key, value); }
            }));
            publications++; return result;
        }
    }
    private static final class Fixture {
        final ReadFaultStore store = new ReadFaultStore();
        final VirtualGrantContinuationFixture typed = new VirtualGrantContinuationFixture(store);
        final VirtualWorkflowService reads;
        final UUID workflowId, targetId, oldResultId, resultId;
        Fixture() { this(false); }
        Fixture(boolean firstChargeInGenerationTwo) {
            if (!firstChargeInGenerationTwo) {
                var first = typed.prepareCurrent(); assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, first.status());
                var old = typed.consume(1, first.receipt().inputSnapshotHash(), 82001);
                assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, old.status()); oldResultId = old.receipt().result().resultId();
            } else oldResultId = null;
            typed.blockAndRelease(); var next = typed.firstCommand();
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, typed.advance(next).status());
            var second = typed.prepareCurrent(); assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, second.status());
            var current = typed.consume(2, second.receipt().inputSnapshotHash(), 82002);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, current.status()); resultId = current.receipt().result().resultId();
            workflowId = next.identity().workflowId(); targetId = next.identity().targetRunId();
            reads = new VirtualWorkflowService(store, typed.seed.f.catalog, typed.terms, typed.seed.f.access,
                    typed.seed.f.clock, typed.seed.f::id);
            baseline();
        }
        void baseline() {
            assertNull(store.fault);
            var one = reads.get(SimulationFixture.ACTOR, workflowId);
            assertEquals(workflowId.toString(), one.get("workflowId")); assertEquals(2, one.get("generation"));
            var page = reads.list(SimulationFixture.ACTOR, 0, 10);
            assertInstanceOf(List.class, page.get("items"));
            var items = (List<?>) page.get("items"); assertEquals(1, items.size());
            assertEquals(one, items.get(0));
        }
        void failsClosed(Fault fault) {
            var before = store.snapshot(); int writes = store.writes, publications = store.publications;
            store.fault = fault;
            try {
                store.faultHits = 0;
                var getFailure = assertThrows(SimulationFailure.class, () -> reads.get(SimulationFixture.ACTOR, workflowId));
                dependency(getFailure); assertTrue(store.faultHits > 0, "GET did not reach the selected read fault");
                assertSame(before, store.snapshot()); assertEquals(writes, store.writes); assertEquals(publications, store.publications);
                store.faultHits = 0;
                var listFailure = assertThrows(SimulationFailure.class, () -> reads.list(SimulationFixture.ACTOR, 0, 10));
                dependency(listFailure); assertTrue(store.faultHits > 0, "list did not reach the selected read fault");
                assertSame(before, store.snapshot()); assertEquals(writes, store.writes); assertEquals(publications, store.publications);
            } finally { store.fault = null; }
            baseline();
        }
    }
    private static void dependency(SimulationFailure failure) {
        assertEquals(503, failure.status()); assertEquals("DEPENDENCY_UNAVAILABLE", failure.code());
        assertEquals("DEPENDENCY_UNAVAILABLE", failure.getMessage()); assertNull(failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
    }

    @Test void currentHeadAbsenceWrongGenerationCustomerAndNativeRevisionCannotDiscloseOldProjection() {
        var f = new Fixture(); String key = f.workflowId.toString();
        for (var fault : List.of(new Fault(HEADS, key, null, null, true),
                new Fault(HEADS, key, "generation", 1, false),
                new Fault(HEADS, key, "customerId", "synthetic-other", false),
                new Fault(HEADS, key, "revision", 1, false))) f.failsClosed(fault);
    }

    @Test void typedLaneAbsenceLegacyLabelAndMismatchedScopeCannotFallBackToLegacyView() {
        var f = new Fixture(); String key = f.workflowId.toString();
        for (var fault : List.of(new Fault(LANES, key, null, null, true),
                new Fault(LANES, key, "lane", "LEGACY", false),
                new Fault(LANES, key, "generation", 1, false))) f.failsClosed(fault);
    }

    @Test void workflowGenerationNativeTypeAndCustomerFaultsAreDependenciesRatherThanPartialListItems() {
        var f = new Fixture(); String key = f.workflowId.toString();
        for (var fault : List.of(new Fault(WORKFLOWS, key, "generation", 1, false),
                new Fault(WORKFLOWS, key, "generation", 2L, false),
                new Fault(WORKFLOWS, key, "customerId", "synthetic-other", false))) f.failsClosed(fault);
    }

    @Test void currentTargetResultScopeAndGrantJoinsCannotBorrowPriorGenerationResult() {
        var f = new Fixture(); String key = f.targetId.toString();
        assertNotEquals(f.oldResultId, f.resultId);
        for (var fault : List.of(new Fault(TARGETS, key, "generation", 1, false),
                new Fault(TARGETS, key, "resultId", f.oldResultId.toString(), false),
                new Fault(TARGETS, key, "grantId", id(82999).toString(), false))) f.failsClosed(fault);
    }

    @Test void actualGenerationTwoFirstKycChargeCannotBeSplicedOntoValidGenerationOneOrigin() {
        var f = new Fixture(true);
        String chargeKey = f.workflowId + ":KYC";
        var charge = f.store.snapshot().get("virtual_grant_profile_stage_charges").get(chargeKey);
        assertNotNull(charge); assertEquals(2, charge.get("generation"));
        assertEquals(f.typed.terms.kycPoints(), charge.get("points"));
        var target = f.store.snapshot().get(TARGETS).get(f.targetId.toString());
        assertEquals(2, target.get("generation")); assertEquals(charge.get("grantId"), target.get("grantId"));
        var marker = f.store.snapshot().get("virtual_grant_profile_kyc_preparations").get(f.targetId.toString());
        assertNotNull(marker); assertInstanceOf(Map.class, marker.get("identity"));
        var identity = (Map<?, ?>) marker.get("identity");
        assertEquals(2, identity.get("generation")); assertEquals(charge.get("phaseRequestId"), identity.get("globalRequestId"));
        f.store.transaction(tx -> {
            var prior = com.finsec.fuse.reimplementation.grant.VirtualGrantGenerationHistory.validate(tx, f.typed.scope(1));
            assertEquals(f.typed.scope(1), prior.scope()); assertEquals(f.typed.terms, prior.terms());
            return null;
        });
        // Both generation origins are legitimate; only the charge's association
        // is corrupted. Native types, points, grant/action/target/phase IDs stay valid.
        f.baseline();
        f.failsClosed(new Fault("virtual_grant_profile_stage_charges", chargeKey, "generation", 1, false));
        assertEquals(2, f.store.snapshot().get("virtual_grant_profile_stage_charges").get(chargeKey).get("generation"));
    }
}
