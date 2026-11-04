package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static org.junit.jupiter.api.Assertions.*;

final class VirtualExperimentServiceTest {
    private VirtualExperimentService service(SimulationFixture f, VirtualExperimentService.PairEvaluator evaluator) {
        return new VirtualExperimentService(f.store, f.access, List.of(new VirtualExperimentService.FixtureSet(
                "synthetic-suite", List.of(new VirtualExperimentService.Case("synthetic-normal", SimulationSpec.KycStatus.VERIFIED,
                        List.of(ID_FACT, FACE_FACT))))), evaluator, f::id);
    }
    private VirtualExperimentService.Plan plan(String model, int repeats) {
        return new VirtualExperimentService.Plan("synthetic-suite", List.of("synthetic-normal"), "PAIRED", model, repeats);
    }
    @Test void oneImmutableProposalIsSharedAndReplayNeverRerunsPair() {
        var f = new SimulationFixture(); var inputs = new ArrayList<Map<String, Object>>();
        var service = service(f, new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment, String id, int repeat, Map<String, Object> proposal) {
                inputs.add(proposal); assertThrows(UnsupportedOperationException.class, () -> proposal.put("status", "MUTATED"));
                return new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.WAIT_APPROVAL, VirtualExperimentService.Reason.SYNTHETIC_REVIEW);
            }
        });
        UUID id = UUID.fromString((String) service.create(ACTOR, f.id(), plan("REPLAY", 1)).get("experimentId"));
        UUID action = f.id(); service.advance(ACTOR, action, id); assertEquals(true, service.advance(ACTOR, action, id).get("replayed"));
        assertEquals(2, inputs.size()); assertSame(inputs.get(0), inputs.get(1));
        var report = service.get(ACTOR, id);
        assertEquals("COMPLETED", report.get("status")); assertEquals("VIRTUAL_SIMULATION", report.get("resultsSource"));
        assertEquals(true, report.get("syntheticModelOutputs")); assertEquals(false, report.get("liveRobustnessMeasured"));
    }
    @Test void liveRequestFailsWithoutFallbackOrCallingEvaluator() {
        var f = new SimulationFixture(); var calls = new AtomicInteger();
        var service = service(f, new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment, String id, int repeat, Map<String, Object> proposal) {
                calls.incrementAndGet(); return null;
            }
        });
        assertEquals(503, assertThrows(SimulationFailure.class, () -> service.create(ACTOR, f.id(), plan("LIVE", 1))).status());
        assertEquals(0, calls.get()); assertFalse(f.store.snapshot().containsKey("virtual_experiments"));
    }
    @Test void failedEnvironmentExcludesWholePairAndNeverCountsItAsDefenseSuccess() {
        var f = new SimulationFixture(); var service = service(f, new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment, String id, int repeat, Map<String, Object> proposal) {
                if (environment == VirtualExperimentService.Environment.BASELINE) throw new IllegalStateException("synthetic diagnostic must not be public");
                return new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.POLICY_BLOCKED, VirtualExperimentService.Reason.SYNTHETIC_POLICY_BLOCK);
            }
        });
        UUID id = UUID.fromString((String) service.create(ACTOR, f.id(), plan("REPLAY", 1)).get("experimentId"));
        service.advance(ACTOR, f.id(), id); var report = service.get(ACTOR, id); var metrics = (Map<?, ?>) report.get("metrics");
        assertEquals(1, metrics.get("excludedPairs")); assertEquals(0, metrics.get("eligiblePairs"));
        assertFalse(report.toString().contains("synthetic diagnostic")); assertFalse(metrics.containsKey("attackSuccessRate"));
    }
    @Test void resultsRequireCurrentAuthorityAndOwnerAndUnknownHistoricalFixtureIsRejected() {
        var f = new SimulationFixture(); var service = service(f, new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment, String id, int repeat, Map<String, Object> proposal) {
                return new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.WAIT_APPROVAL, VirtualExperimentService.Reason.SYNTHETIC_REVIEW);
            }
        });
        UUID id = UUID.fromString((String) service.create(ACTOR, f.id(), plan("REPLAY", 1)).get("experimentId"));
        assertEquals(403, assertThrows(SimulationFailure.class, () -> service.get(new ActorRef("synthetic-other"), id)).status());
        f.permitted.set(false); assertEquals(403, assertThrows(SimulationFailure.class, () -> service.get(ACTOR, id)).status());
        f.permitted.set(true);
        assertThrows(SimulationFailure.class, () -> service.create(ACTOR, f.id(),
                new VirtualExperimentService.Plan("synthetic-unknown", List.of("synthetic-normal"), "PAIRED", "REPLAY", 1)));
    }
    @Test void evaluatorModeChangeAfterConstructionExcludesPairWithoutEvaluation() {
        var f = new SimulationFixture(); var calls = new AtomicInteger();
        var mode = new AtomicReference<>(VirtualTransactionalStore.MODE);
        var service = service(f, new VirtualExperimentService.PairEvaluator() {
            public String mode() { return mode.get(); }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment, String id, int repeat, Map<String, Object> proposal) {
                calls.incrementAndGet(); throw new AssertionError("Changed-mode evaluator must not run");
            }
        });
        UUID id = UUID.fromString((String) service.create(ACTOR, f.id(), plan("REPLAY", 1)).get("experimentId"));
        var before = f.store.snapshot();
        mode.set("SYNTHETIC_UNAVAILABLE_MODE");
        service.advance(ACTOR, f.id(), id);
        assertEquals(0, calls.get());
        var report = service.get(ACTOR, id);
        assertEquals(1, report.get("completedPairs"));
        assertEquals(1, ((Map<?, ?>) report.get("metrics")).get("excludedPairs"));
        assertEquals(0, ((Map<?, ?>) report.get("metrics")).get("eligiblePairs"));
        for (var output : (List<?>) report.get("caseOutputs")) {
            assertEquals("ENVIRONMENT_ERROR", ((Map<?, ?>) output).get("outcome"));
            assertEquals(List.of("ENVIRONMENT_UNAVAILABLE"), ((Map<?, ?>) output).get("reasonCodes"));
        }
        // Only experiment progress and its action receipt may change; no workflow
        // or payment/risk side effect is created by the rejected evaluator.
        var after = f.store.snapshot();
        assertEquals(before.keySet(), after.keySet());
        before.forEach((table, rows) -> {
            if (!table.equals("virtual_experiments") && !table.equals("_virtual_action_journal"))
                assertEquals(rows, after.get(table));
        });
    }

    @Test void evaluatorModeIsRecheckedBetweenPairedEnvironments() {
        var f = new SimulationFixture(); var calls = new AtomicInteger();
        var mode = new AtomicReference<>(VirtualTransactionalStore.MODE);
        var service = service(f, new VirtualExperimentService.PairEvaluator() {
            public String mode() { return mode.get(); }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment, String id, int repeat, Map<String, Object> proposal) {
                calls.incrementAndGet(); mode.set("SYNTHETIC_UNAVAILABLE_MODE");
                return new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.WAIT_APPROVAL,
                        VirtualExperimentService.Reason.SYNTHETIC_REVIEW);
            }
        });
        UUID id = UUID.fromString((String) service.create(ACTOR, f.id(), plan("REPLAY", 1)).get("experimentId"));
        service.advance(ACTOR, f.id(), id);
        assertEquals(1, calls.get());
        var report = service.get(ACTOR, id);
        assertEquals(1, ((Map<?, ?>) report.get("metrics")).get("excludedPairs"));
        assertEquals(0, ((Map<?, ?>) report.get("metrics")).get("eligiblePairs"));
    }

    @Test void modeChangeDuringFinalEnvironmentExcludesPairAndReplayNeverEvaluatesAgain() {
        var f = new SimulationFixture(); var calls = new AtomicInteger();
        var mode = new AtomicReference<>(VirtualTransactionalStore.MODE);
        var service = service(f, new VirtualExperimentService.PairEvaluator() {
            public String mode() { return mode.get(); }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                    String id, int repeat, Map<String, Object> proposal) {
                calls.incrementAndGet();
                if (environment == VirtualExperimentService.Environment.FUSE) mode.set("SYNTHETIC_UNAVAILABLE_MODE");
                return new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.PAYMENT_COMMITTED,
                        VirtualExperimentService.Reason.SYNTHETIC_PAYMENT);
            }
        });
        UUID id = UUID.fromString((String) service.create(ACTOR, f.id(), plan("REPLAY", 1)).get("experimentId"));
        UUID action = f.id();
        service.advance(ACTOR, action, id);
        var report = service.get(ACTOR, id);
        var outputs = (List<?>) report.get("caseOutputs");
        assertEquals("PAYMENT_COMMITTED", ((Map<?, ?>) outputs.get(0)).get("outcome"));
        assertEquals("ENVIRONMENT_ERROR", ((Map<?, ?>) outputs.get(1)).get("outcome"));
        assertEquals(List.of("ENVIRONMENT_UNAVAILABLE"), ((Map<?, ?>) outputs.get(1)).get("reasonCodes"));
        assertEquals(1, ((Map<?, ?>) report.get("metrics")).get("excludedPairs"));
        assertEquals(0, ((Map<?, ?>) report.get("metrics")).get("eligiblePairs"));
        var before = f.store.snapshot();
        assertEquals(true, service.advance(ACTOR, action, id).get("replayed"));
        // A distinct action against the terminal experiment also cannot evaluate another pair.
        service.advance(ACTOR, f.id(), id);
        assertEquals(2, calls.get());
        assertEquals(report, service.get(ACTOR, id));
        assertEquals(before.get("virtual_experiments"), f.store.snapshot().get("virtual_experiments"));
        assertFalse(f.store.snapshot().containsKey("virtual_payments"));
    }

    @Test void competingAdvanceActionsFailFastWithoutRerunningPendingPair() throws Exception {
        var f = new SimulationFixture(); var calls = new AtomicInteger();
        var entered = new java.util.concurrent.CountDownLatch(1); var release = new java.util.concurrent.CountDownLatch(1);
        var service = service(f, blocking(calls, entered, release, VirtualExperimentService.Environment.BASELINE));
        UUID id = experiment(service, f, 1), action = f.id(), other = f.id();
        var workers = java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            var running = workers.submit(() -> service.advance(ACTOR, action, id));
            assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS));
            var before = f.store.snapshot();
            assertEquals(503, assertThrows(SimulationFailure.class, () -> service.advance(ACTOR, action, id)).status());
            assertEquals(503, assertThrows(SimulationFailure.class, () -> service.advance(ACTOR, other, id)).status());
            assertEquals(before, f.store.snapshot()); assertEquals(1, calls.get());
            var journal = new com.finsec.fuse.reimplementation.persistence.ActionJournal(f.store);
            assertThrows(com.finsec.fuse.reimplementation.persistence.ActionJournal.ActionConflictException.class,
                    () -> journal.execute(ACTOR.actorId(), action, "ANOTHER_SYNTHETIC_OPERATION",
                            com.finsec.fuse.reimplementation.persistence.CanonicalJson.sha256(Map.of()), tx -> Map.of("requestId", action.toString())));
            release.countDown(); assertEquals("COMPLETED", running.get(5, java.util.concurrent.TimeUnit.SECONDS).get("status"));
            assertEquals(true, service.advance(ACTOR, action, id).get("replayed"));
            // A contender that never reserved may now perform an independent terminal no-op.
            assertEquals(false, service.advance(ACTOR, other, id).get("replayed"));
            assertEquals(true, service.advance(ACTOR, other, id).get("replayed")); assertEquals(2, calls.get());
        } finally { release.countDown(); workers.shutdownNow(); }
    }

    @Test void cancellationDuringEitherArmPreservesCommittedPairsAndFencesLateResults() throws Exception {
        for (var blocked : VirtualExperimentService.Environment.values()) {
            var f = new SimulationFixture(); var calls = new AtomicInteger();
            var entered = new java.util.concurrent.CountDownLatch(1); var release = new java.util.concurrent.CountDownLatch(1);
            var shouldBlock = new java.util.concurrent.atomic.AtomicBoolean();
            var blocker = blocking(calls, entered, release, blocked);
            var service = service(f, new VirtualExperimentService.PairEvaluator() {
                public String mode() { return VirtualTransactionalStore.MODE; }
                public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment env, String c, int r, Map<String, Object> p) {
                    if (shouldBlock.get()) return blocker.evaluate(env, c, r, p);
                    return review();
                }
            });
            UUID id = experiment(service, f, 2); service.advance(ACTOR, f.id(), id);
            var committed = service.get(ACTOR, id); shouldBlock.set(true);
            UUID advance = f.id(), cancel = f.id(); var workers = java.util.concurrent.Executors.newFixedThreadPool(2);
            try {
                var running = workers.submit(() -> service.advance(ACTOR, advance, id));
                assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS));
                // Both operations must finish while evaluate is still blocked, proving no store lock is held.
                var visible = workers.submit(() -> service.get(ACTOR, id)).get(5, java.util.concurrent.TimeUnit.SECONDS);
                assertFalse(visible.containsKey("activeClaim")); assertFalse(visible.containsKey("fence"));
                var raw = f.store.snapshot().get("virtual_experiments").get(id.toString());
                var claim = (Map<?, ?>) raw.get("activeClaim");
                assertEquals(claim.get("attemptToken"), f.store.snapshot().get("_virtual_action_journal").get(advance.toString()).get("attemptToken"));
                var cancelled = workers.submit(() -> service.cancel(ACTOR, cancel, id)).get(5, java.util.concurrent.TimeUnit.SECONDS);
                assertEquals("CANCELLED", cancelled.get("status")); assertEquals(1, cancelled.get("completedPairs"));
                assertFalse(cancelled.toString().contains((String) claim.get("attemptToken")));
                var snapshot = f.store.snapshot(); release.countDown();
                assertEquals("CANCELLED", running.get(5, java.util.concurrent.TimeUnit.SECONDS).get("status"));
                assertEquals(snapshot, f.store.snapshot());
                assertEquals(true, service.advance(ACTOR, advance, id).get("replayed"));
                assertEquals(true, service.cancel(ACTOR, cancel, id).get("replayed"));
                var after = service.get(ACTOR, id);
                assertEquals(committed.get("caseOutputs"), after.get("caseOutputs"));
                assertEquals(committed.get("exclusions"), after.get("exclusions"));
                assertEquals(committed.get("completedPairs"), after.get("completedPairs"));
                assertEquals(blocked == VirtualExperimentService.Environment.BASELINE ? 1 : 2, calls.get());
            } finally { release.countDown(); workers.shutdownNow(); }
        }
    }

    @Test void cancellationAfterFinalizationIsTerminalNoOpAndRequiresCurrentOwnerAuthority() {
        var f = new SimulationFixture(); var service = service(f, constant()); UUID id = experiment(service, f, 1);
        UUID advance = f.id(); service.advance(ACTOR, advance, id); var before = service.get(ACTOR, id);
        UUID cancel = f.id(); assertEquals("COMPLETED", service.cancel(ACTOR, cancel, id).get("status"));
        assertEquals(before, service.get(ACTOR, id));
        var snapshot = f.store.snapshot();
        assertEquals(403, assertThrows(SimulationFailure.class,
                () -> service.cancel(new ActorRef("synthetic-other"), f.id(), id)).status());
        assertEquals(400, assertThrows(SimulationFailure.class, () -> service.cancel(ACTOR, f.id(), f.id())).status());
        f.permitted.set(false);
        assertEquals(403, assertThrows(SimulationFailure.class, () -> service.cancel(ACTOR, cancel, id)).status());
        assertEquals(403, assertThrows(SimulationFailure.class, () -> service.advance(ACTOR, advance, id)).status());
        assertEquals(snapshot, f.store.snapshot());
    }

    @Test void fatalErrorAndRevokedAuthorityLeavePendingUntilExplicitOwnerCancel() {
        for (boolean fatal : List.of(true, false)) {
            var f = new SimulationFixture(); var failure = new AssertionError("synthetic-fatal-marker"); var calls = new AtomicInteger();
            var service = service(f, new VirtualExperimentService.PairEvaluator() {
                public String mode() { return VirtualTransactionalStore.MODE; }
                public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment env, String c, int r, Map<String, Object> p) {
                    calls.incrementAndGet(); if (fatal) throw failure; f.permitted.set(false); return review();
                }
            });
            UUID id = experiment(service, f, 1), action = f.id();
            if (fatal) assertSame(failure, assertThrows(AssertionError.class, () -> service.advance(ACTOR, action, id)));
            else assertEquals(403, assertThrows(SimulationFailure.class, () -> service.advance(ACTOR, action, id)).status());
            f.permitted.set(true); var pending = f.store.snapshot();
            assertEquals(0, service.get(ACTOR, id).get("completedPairs"));
            assertEquals(503, assertThrows(SimulationFailure.class, () -> service.advance(ACTOR, action, id)).status());
            assertEquals(pending, f.store.snapshot());
            assertEquals("CANCELLED", service.cancel(ACTOR, f.id(), id).get("status"));
            assertEquals("CANCELLED", service.advance(ACTOR, action, id).get("status")); assertEquals(1, calls.get());
        }
    }

    @Test void missingOrMismatchedPendingTokenFailsClosedWithoutPartialCancellation() {
        for (boolean missing : List.of(true, false)) {
            var f = new SimulationFixture(); var service = service(f, new VirtualExperimentService.PairEvaluator() {
                public String mode() { return VirtualTransactionalStore.MODE; }
                public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment e, String c, int r, Map<String, Object> p) { throw new AssertionError(); }
            });
            UUID id = experiment(service, f, 1); assertThrows(AssertionError.class, () -> service.advance(ACTOR, f.id(), id));
            f.store.transaction(tx -> {
                var row = tx.get("virtual_experiments", id.toString()); var claim = new java.util.LinkedHashMap<String, Object>();
                ((Map<?, ?>) row.get("activeClaim")).forEach((k, v) -> claim.put((String) k, v));
                if (missing) claim.remove("attemptToken"); else claim.put("attemptToken", f.id().toString());
                tx.put("virtual_experiments", id.toString(), SimulationRows.changed(row, "activeClaim", claim)); return null;
            });
            var before = f.store.snapshot();
            assertEquals(503, assertThrows(SimulationFailure.class, () -> service.cancel(ACTOR, f.id(), id)).status());
            assertEquals(before, f.store.snapshot());
        }
    }

    @Test void checkedFenceExhaustionNeverWrapsOrMutatesReservations() {
        var f = new SimulationFixture(); var service = service(f, constant()); UUID id = experiment(service, f, 2);
        f.store.transaction(tx -> { var row = tx.get("virtual_experiments", id.toString());
            tx.put("virtual_experiments", id.toString(), SimulationRows.changed(row, "fence", Long.MAX_VALUE)); return null; });
        var before = f.store.snapshot();
        assertEquals(503, assertThrows(SimulationFailure.class, () -> service.advance(ACTOR, f.id(), id)).status());
        assertEquals(503, assertThrows(SimulationFailure.class, () -> service.cancel(ACTOR, f.id(), id)).status());
        assertEquals(before, f.store.snapshot());
        f.store.transaction(tx -> { var row = tx.get("virtual_experiments", id.toString());
            tx.put("virtual_experiments", id.toString(), SimulationRows.changed(row, "fence", Long.MAX_VALUE - 1)); return null; });
        UUID advance = f.id(); assertEquals("RUNNING", service.advance(ACTOR, advance, id).get("status"));
        assertEquals(Long.MAX_VALUE, f.store.snapshot().get("virtual_experiments").get(id.toString()).get("fence"));
        before = f.store.snapshot();
        assertEquals(true, service.advance(ACTOR, advance, id).get("replayed"));
        assertEquals(503, assertThrows(SimulationFailure.class, () -> service.cancel(ACTOR, f.id(), id)).status());
        assertEquals(before, f.store.snapshot()); // No universal owner-recovery claim at MAX.
        UUID completeId = experiment(service, f, 1); service.advance(ACTOR, f.id(), completeId);
        f.store.transaction(tx -> { var row = tx.get("virtual_experiments", completeId.toString());
            tx.put("virtual_experiments", completeId.toString(), SimulationRows.changed(row, "fence", Long.MAX_VALUE)); return null; });
        assertEquals("COMPLETED", service.cancel(ACTOR, f.id(), completeId).get("status"));
    }

    @Test void maximumFenceWithPendingTokenStillCannotCancelOrMutate() {
        var f = new SimulationFixture(); var service = service(f, new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment e, String c, int r, Map<String, Object> p) { throw new AssertionError(); }
        });
        UUID id = experiment(service, f, 1), action = f.id(); assertThrows(AssertionError.class, () -> service.advance(ACTOR, action, id));
        f.store.transaction(tx -> {
            var row = tx.get("virtual_experiments", id.toString()); var claim = new java.util.LinkedHashMap<String, Object>();
            ((Map<?, ?>) row.get("activeClaim")).forEach((k, v) -> claim.put((String) k, v)); claim.put("fence", Long.MAX_VALUE);
            tx.put("virtual_experiments", id.toString(), SimulationRows.changed(row, "fence", Long.MAX_VALUE, "activeClaim", claim)); return null;
        });
        var before = f.store.snapshot();
        assertEquals(503, assertThrows(SimulationFailure.class, () -> service.cancel(ACTOR, f.id(), id)).status());
        assertEquals(before, f.store.snapshot());
    }

    @Test void failureAfterPendingReceiptCompletionRollsBackCancellationAndBothJournals() {
        var f = new SimulationFixture(); var fail = new java.util.concurrent.atomic.AtomicBoolean();
        var wrapped = new com.finsec.fuse.reimplementation.persistence.TransactionalStore() {
            public String mode() { return f.store.mode(); }
            public Map<String, Map<String, Map<String, Object>>> snapshot() { return f.store.snapshot(); }
            public <R> R transaction(java.util.function.Function<Tx, R> work) {
                return f.store.transaction(tx -> work.apply(new Tx() {
                    public Map<String, Object> get(String table, String id) { return tx.get(table, id); }
                    public Map<String, Map<String, Object>> rows(String table) { return tx.rows(table); }
                    public void put(String table, String id, Map<String, Object> row) {
                        if (fail.get() && table.equals("virtual_experiments") && "CANCELLED".equals(row.get("status")))
                            throw SimulationFailure.unavailable();
                        tx.put(table, id, row);
                    }
                }));
            }
        };
        var service = new VirtualExperimentService(wrapped, f.access, List.of(new VirtualExperimentService.FixtureSet(
                "synthetic-suite", List.of(new VirtualExperimentService.Case("synthetic-normal", SimulationSpec.KycStatus.VERIFIED,
                        List.of(ID_FACT, FACE_FACT))))), new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment e, String c, int r, Map<String, Object> p) { throw new AssertionError(); }
        }, f::id);
        UUID id = experiment(service, f, 1), action = f.id(); assertThrows(AssertionError.class, () -> service.advance(ACTOR, action, id));
        var before = f.store.snapshot(); UUID cancel = f.id(); fail.set(true);
        assertEquals(503, assertThrows(SimulationFailure.class, () -> service.cancel(ACTOR, cancel, id)).status());
        assertEquals(before, f.store.snapshot()); // Includes advance still RESERVED and no cancellation receipt.
        fail.set(false); assertEquals("CANCELLED", service.cancel(ACTOR, cancel, id).get("status"));
        assertEquals(true, service.advance(ACTOR, action, id).get("replayed"));
    }

    @Test void finalizationFailureRollsBackPairAndReceiptWithoutAutomaticReevaluation() {
        var f = new SimulationFixture(); var fail = new java.util.concurrent.atomic.AtomicBoolean(true); var calls = new AtomicInteger();
        var wrapped = new com.finsec.fuse.reimplementation.persistence.TransactionalStore() {
            public String mode() { return f.store.mode(); }
            public Map<String, Map<String, Map<String, Object>>> snapshot() { return f.store.snapshot(); }
            public <R> R transaction(java.util.function.Function<Tx, R> work) {
                return f.store.transaction(tx -> work.apply(new Tx() {
                    public Map<String, Object> get(String table, String id) { return tx.get(table, id); }
                    public Map<String, Map<String, Object>> rows(String table) { return tx.rows(table); }
                    public void put(String table, String id, Map<String, Object> row) {
                        if (fail.get() && table.equals("virtual_experiments") && "COMPLETED".equals(row.get("status")))
                            throw SimulationFailure.unavailable();
                        tx.put(table, id, row);
                    }
                }));
            }
        };
        var service = new VirtualExperimentService(wrapped, f.access, List.of(new VirtualExperimentService.FixtureSet(
                "synthetic-suite", List.of(new VirtualExperimentService.Case("synthetic-normal", SimulationSpec.KycStatus.VERIFIED,
                        List.of(ID_FACT, FACE_FACT))))), new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment e, String c, int r, Map<String, Object> p) {
                calls.incrementAndGet(); return review();
            }
        }, f::id);
        UUID id = experiment(service, f, 1), action = f.id();
        assertEquals(503, assertThrows(SimulationFailure.class, () -> service.advance(ACTOR, action, id)).status());
        var pending = f.store.snapshot(); var row = pending.get("virtual_experiments").get(id.toString());
        assertEquals(0, row.get("completedPairs")); assertEquals(List.of(), row.get("caseOutputs")); assertEquals(List.of(), row.get("exclusions"));
        assertNotNull(row.get("activeClaim")); assertEquals("RESERVED", pending.get("_virtual_action_journal").get(action.toString()).get("reservationStatus"));
        fail.set(false);
        assertEquals(503, assertThrows(SimulationFailure.class, () -> service.advance(ACTOR, action, id)).status());
        assertEquals(pending, f.store.snapshot()); assertEquals(2, calls.get());
        assertEquals("CANCELLED", service.cancel(ACTOR, f.id(), id).get("status"));
    }

    private UUID experiment(VirtualExperimentService service, SimulationFixture f, int repeats) {
        return UUID.fromString((String) service.create(ACTOR, f.id(), plan("REPLAY", repeats)).get("experimentId"));
    }
    private static VirtualExperimentService.Observation review() {
        return new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.WAIT_APPROVAL, VirtualExperimentService.Reason.SYNTHETIC_REVIEW);
    }
    private static VirtualExperimentService.PairEvaluator constant() {
        return new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment e, String c, int r, Map<String, Object> p) { return review(); }
        };
    }
    private static VirtualExperimentService.PairEvaluator blocking(AtomicInteger calls, java.util.concurrent.CountDownLatch entered,
            java.util.concurrent.CountDownLatch release, VirtualExperimentService.Environment blocked) {
        return new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment e, String c, int r, Map<String, Object> p) {
                calls.incrementAndGet();
                if (e == blocked) {
                    entered.countDown();
                    try { if (!release.await(5, java.util.concurrent.TimeUnit.SECONDS)) throw new AssertionError("Synthetic latch not released"); }
                    catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
                }
                return review();
            }
        };
    }

    // Synthetic lease scenarios use explicit caller-supplied times.
    @Test void leasedClaimDispatchesEachArmOnceAndCompletedReplayHasNoNewPermit() {
        var f = new SimulationFixture(); var calls = new AtomicInteger();
        var service = service(f, counted(calls));
        UUID id = experiment(service, f, 1), action = f.id();
        var claim = service.claimLeased(ACTOR, action, id, "synthetic-worker-a", 0, 10);
        assertNotNull(claim.permit()); assertEquals(0, calls.get());
        var pending = f.store.snapshot();
        var active = leaseRow(f, id);
        assertEquals("VIRTUAL_LEASE_V1", active.get("claimFormat")); assertEquals(12, active.size());
        assertEquals("CLAIMED", active.get("executionState"));
        assertNotEquals(active.get("journalReservationToken"), active.get("workAttemptToken"));
        assertEquals(active.get("journalReservationToken"), pending.get("_virtual_action_journal").get(action.toString()).get("attemptToken"));
        assertEquals(503, assertThrows(SimulationFailure.class,
                () -> service.claimLeased(ACTOR, action, id, "synthetic-worker-a", 0, 10)).status());
        assertEquals(503, assertThrows(SimulationFailure.class,
                () -> service.claimLeased(ACTOR, f.id(), id, "synthetic-worker-b", 0, 10)).status());
        assertEquals(pending, f.store.snapshot());
        var outcome = service.evaluateLeased(ACTOR, claim.permit(), 1);
        assertNull(outcome.savedReceipt()); assertNotNull(outcome.evaluatedPair()); assertEquals(2, calls.get());
        var evaluated = f.store.snapshot();
        assertEquals(503, assertThrows(SimulationFailure.class,
                () -> service.evaluateLeased(ACTOR, claim.permit(), 1)).status());
        assertEquals(evaluated, f.store.snapshot()); assertEquals(2, calls.get());
        assertEquals("COMPLETED", service.finalizeLeased(ACTOR, claim.permit(), outcome.evaluatedPair(), 2).get("status"));
        var complete = f.store.snapshot();
        assertEquals(true, service.finalizeLeased(ACTOR, claim.permit(), outcome.evaluatedPair(), 100).get("replayed"));
        var replay = service.claimLeased(ACTOR, action, id, "synthetic-worker-b", 100, 101);
        assertNull(replay.permit()); assertEquals(true, replay.receipt().get("replayed"));
        var saved = service.evaluateLeased(ACTOR, claim.permit(), 100);
        assertNull(saved.evaluatedPair()); assertEquals(true, saved.savedReceipt().get("replayed"));
        assertEquals(complete, f.store.snapshot()); assertEquals(2, calls.get());
    }

    @Test void explicitLeaseExpiryStopsDispatchAtEqualityWithoutChangingPendingAction() {
        var f = new SimulationFixture(); var calls = new AtomicInteger(); var service = service(f, counted(calls));
        UUID id = experiment(service, f, 1), action = f.id();
        var claim = service.claimLeased(ACTOR, action, id, "synthetic-worker-a", 0, 10);
        var claimed = f.store.snapshot();
        assertEquals(503, assertThrows(SimulationFailure.class,
                () -> service.evaluateLeased(ACTOR, claim.permit(), 10)).status());
        assertEquals(claimed, f.store.snapshot()); assertEquals(0, calls.get());
    }

    @Test void safeHandoffKeepsOriginalReservationButFencesOldEvaluatedPair() {
        var f = new SimulationFixture(); var calls = new AtomicInteger(); var service = service(f, counted(calls));
        UUID id = experiment(service, f, 1), action = f.id();
        var old = service.claimLeased(ACTOR, action, id, "synthetic-worker-a", 0, 10);
        var oldPair = service.evaluateLeased(ACTOR, old.permit(), 1).evaluatedPair();
        var before = leaseRow(f, id);
        var handoff = service.handoffLeased(ACTOR, f.id(), id, handoff(action, before, "synthetic-worker-b", 10, 20,
                VirtualExperimentService.EffectDisposition.SIDE_EFFECT_FREE_CONFIRMED));
        assertNotNull(handoff.permit()); assertEquals(2, calls.get());
        var current = leaseRow(f, id);
        assertEquals(before.get("journalReservationToken"), current.get("journalReservationToken"));
        assertNotEquals(before.get("workAttemptToken"), current.get("workAttemptToken"));
        assertNotEquals(current.get("journalReservationToken"), current.get("workAttemptToken"));
        assertEquals(((Long) before.get("fence")) + 1, current.get("fence"));
        assertEquals(((Long) before.get("leaseVersion")) + 1, current.get("leaseVersion"));
        assertEquals("CLAIMED", current.get("executionState"));
        var pending = f.store.snapshot();
        assertEquals(503, assertThrows(SimulationFailure.class,
                () -> service.finalizeLeased(ACTOR, old.permit(), oldPair, 11)).status());
        assertEquals(503, assertThrows(SimulationFailure.class,
                () -> service.evaluateLeased(ACTOR, old.permit(), 11)).status());
        assertEquals(pending, f.store.snapshot()); assertEquals(2, calls.get());
        var newPair = service.evaluateLeased(ACTOR, handoff.permit(), 11).evaluatedPair();
        assertEquals("COMPLETED", service.finalizeLeased(ACTOR, handoff.permit(), newPair, 12).get("status"));
        assertEquals(4, calls.get()); assertEquals(1, service.get(ACTOR, id).get("completedPairs"));
        assertEquals(true, service.finalizeLeased(ACTOR, old.permit(), oldPair, 100).get("replayed"));
    }

    @Test void handoffInsideBaselineStopsOldFuseDispatchBeforeNewAttemptRuns() {
        var f = new SimulationFixture(); var calls = new AtomicInteger();
        var serviceRef = new AtomicReference<VirtualExperimentService>();
        var next = new AtomicReference<VirtualExperimentService.LeaseClaim>();
        var experimentRef = new AtomicReference<UUID>(); var actionRef = new AtomicReference<UUID>();
        var evaluator = new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                    String caseId, int repeat, Map<String, Object> proposal) {
                if (calls.incrementAndGet() == 1) {
                    assertEquals(VirtualExperimentService.Environment.BASELINE, environment);
                    next.set(serviceRef.get().handoffLeased(ACTOR, f.id(), experimentRef.get(),
                            handoff(actionRef.get(), leaseRow(f, experimentRef.get()), "synthetic-worker-b", 10, 20,
                                    VirtualExperimentService.EffectDisposition.SIDE_EFFECT_FREE_CONFIRMED)));
                }
                return review();
            }
        };
        var service = service(f, evaluator); serviceRef.set(service);
        UUID id = experiment(service, f, 1), action = f.id(); experimentRef.set(id); actionRef.set(action);
        var claim = service.claimLeased(ACTOR, action, id, "synthetic-worker-a", 0, 10);
        assertEquals(503, assertThrows(SimulationFailure.class,
                () -> service.evaluateLeased(ACTOR, claim.permit(), 1)).status());
        assertEquals(1, calls.get()); assertNotNull(next.get().permit());
        var retained = leaseRow(f, id);
        assertEquals("synthetic-worker-b", retained.get("executionOwner"));
        assertEquals("CLAIMED", retained.get("executionState"));
        assertEquals(0, service.get(ACTOR, id).get("completedPairs"));
        var pair = service.evaluateLeased(ACTOR, next.get().permit(), 11).evaluatedPair();
        service.finalizeLeased(ACTOR, next.get().permit(), pair, 12);
        assertEquals(3, calls.get()); // One old BASELINE, then exactly one complete new pair.
    }

    @Test void leasedCancelDuringBaselinePreservesWholeCommittedPrefixAndSkipsFuse() {
        var f = new SimulationFixture(); var baseline = new AtomicInteger(); var fuse = new AtomicInteger();
        var cancelNow = new java.util.concurrent.atomic.AtomicBoolean();
        var serviceRef = new AtomicReference<VirtualExperimentService>(); var experimentRef = new AtomicReference<UUID>();
        var service = service(f, new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                    String caseId, int repeat, Map<String, Object> proposal) {
                if (environment == VirtualExperimentService.Environment.BASELINE) {
                    baseline.incrementAndGet();
                    if (cancelNow.get()) serviceRef.get().cancel(ACTOR, f.id(), experimentRef.get());
                } else fuse.incrementAndGet();
                return review();
            }
        });
        serviceRef.set(service); UUID id = experiment(service, f, 2); experimentRef.set(id);
        var first = service.claimLeased(ACTOR, f.id(), id, "synthetic-worker-a", 0, 10);
        var firstPair = service.evaluateLeased(ACTOR, first.permit(), 1).evaluatedPair();
        service.finalizeLeased(ACTOR, first.permit(), firstPair, 2);
        var prefix = service.get(ACTOR, id).get("caseOutputs");
        UUID action = f.id(); var second = service.claimLeased(ACTOR, action, id, "synthetic-worker-a", 3, 10);
        cancelNow.set(true);
        var outcome = service.evaluateLeased(ACTOR, second.permit(), 4);
        assertNull(outcome.evaluatedPair()); assertEquals("CANCELLED", outcome.savedReceipt().get("status"));
        assertEquals(2, baseline.get()); assertEquals(1, fuse.get());
        var after = f.store.snapshot(); var report = service.get(ACTOR, id);
        assertEquals("CANCELLED", report.get("status")); assertEquals(1, report.get("completedPairs"));
        assertEquals(prefix, report.get("caseOutputs")); assertNull(after.get("virtual_experiments").get(id.toString()).get("activeClaim"));
        assertEquals(true, service.evaluateLeased(ACTOR, second.permit(), 100).savedReceipt().get("replayed"));
        assertEquals(true, service.advance(ACTOR, action, id).get("replayed"));
        assertEquals(after, f.store.snapshot()); assertEquals(1, fuse.get());
    }

    @Test void uncertainRecoveryBlocksDispatchAndOldFinalizeUntilExplicitCancel() {
        var f = new SimulationFixture(); var calls = new AtomicInteger(); var service = service(f, counted(calls));
        UUID id = experiment(service, f, 1), action = f.id();
        var claim = service.claimLeased(ACTOR, action, id, "synthetic-worker-a", 0, 10);
        var pair = service.evaluateLeased(ACTOR, claim.permit(), 1).evaluatedPair();
        var before = leaseRow(f, id);
        var blocked = service.handoffLeased(ACTOR, f.id(), id, handoff(action, before, "synthetic-worker-b", 10, 20,
                VirtualExperimentService.EffectDisposition.UNCERTAIN));
        assertNull(blocked.permit()); assertEquals("DENY", blocked.receipt().get("decision"));
        assertEquals(List.of("RECOVERY_EFFECT_UNCONFIRMED"), blocked.receipt().get("reasonCodes"));
        var current = leaseRow(f, id);
        for (String field : List.of("executionOwner", "fence", "leaseUntil", "workAttemptToken", "journalReservationToken"))
            assertEquals(before.get(field), current.get(field));
        assertEquals(((Long) before.get("leaseVersion")) + 1, current.get("leaseVersion"));
        assertEquals("RECOVERY_BLOCKED", current.get("executionState"));
        var snapshot = f.store.snapshot();
        assertEquals(503, assertThrows(SimulationFailure.class, () -> service.evaluateLeased(ACTOR, claim.permit(), 11)).status());
        assertEquals(503, assertThrows(SimulationFailure.class, () -> service.finalizeLeased(ACTOR, claim.permit(), pair, 11)).status());
        assertEquals(503, assertThrows(SimulationFailure.class, () -> service.handoffLeased(ACTOR, f.id(), id,
                handoff(action, current, "synthetic-worker-c", 11, 21, VirtualExperimentService.EffectDisposition.SIDE_EFFECT_FREE_CONFIRMED))).status());
        assertEquals(snapshot, f.store.snapshot()); assertEquals(2, calls.get());
        assertEquals("RESERVED", snapshot.get("_virtual_action_journal").get(action.toString()).get("reservationStatus"));
        assertEquals("CANCELLED", service.cancel(ACTOR, f.id(), id).get("status"));
        assertEquals("CANCELLED", service.finalizeLeased(ACTOR, claim.permit(), pair, 100).get("status"));
        assertEquals(2, calls.get());
    }

    @Test void leasedFinalizeAndHandoffRollbackKeepOriginalPendingJournalAndDoNotReevaluate() {
        var f = new SimulationFixture(); var fail = new java.util.concurrent.atomic.AtomicBoolean(); var calls = new AtomicInteger();
        var wrapped = new com.finsec.fuse.reimplementation.persistence.TransactionalStore() {
            public String mode() { return f.store.mode(); }
            public Map<String, Map<String, Map<String, Object>>> snapshot() { return f.store.snapshot(); }
            public <R> R transaction(java.util.function.Function<Tx, R> work) {
                return f.store.transaction(tx -> work.apply(new Tx() {
                    public Map<String, Object> get(String table, String id) { return tx.get(table, id); }
                    public Map<String, Map<String, Object>> rows(String table) { return tx.rows(table); }
                    public void put(String table, String id, Map<String, Object> row) {
                        if (fail.get() && table.equals("virtual_experiments")) throw SimulationFailure.unavailable();
                        tx.put(table, id, row);
                    }
                }));
            }
        };
        var service = new VirtualExperimentService(wrapped, f.access, List.of(new VirtualExperimentService.FixtureSet(
                "synthetic-suite", List.of(new VirtualExperimentService.Case("synthetic-normal", SimulationSpec.KycStatus.VERIFIED,
                        List.of(ID_FACT, FACE_FACT))))), counted(calls), f::id);
        UUID id = experiment(service, f, 1), action = f.id();
        var claim = service.claimLeased(ACTOR, action, id, "synthetic-worker-a", 0, 10);
        var pair = service.evaluateLeased(ACTOR, claim.permit(), 1).evaluatedPair();
        var pending = f.store.snapshot(); fail.set(true);
        assertEquals(503, assertThrows(SimulationFailure.class, () -> service.finalizeLeased(ACTOR, claim.permit(), pair, 2)).status());
        assertEquals(pending, f.store.snapshot()); assertEquals(2, calls.get());
        UUID control = f.id(); var request = handoff(action, leaseRow(f, id), "synthetic-worker-b", 10, 20,
                VirtualExperimentService.EffectDisposition.SIDE_EFFECT_FREE_CONFIRMED);
        assertEquals(503, assertThrows(SimulationFailure.class, () -> service.handoffLeased(ACTOR, control, id, request)).status());
        assertEquals(pending, f.store.snapshot());
        fail.set(false);
        var winner = service.handoffLeased(ACTOR, control, id, request);
        assertNotNull(winner.permit()); assertEquals(2, calls.get());
        var newPair = service.evaluateLeased(ACTOR, winner.permit(), 11).evaluatedPair();
        assertEquals("COMPLETED", service.finalizeLeased(ACTOR, winner.permit(), newPair, 12).get("status"));
        assertEquals(4, calls.get());
        assertEquals(true, service.advance(ACTOR, action, id).get("replayed"));
    }

    private static Map<?, ?> leaseRow(SimulationFixture f, UUID id) {
        return (Map<?, ?>) f.store.snapshot().get("virtual_experiments").get(id.toString()).get("activeClaim");
    }
    private static VirtualExperimentService.HandoffRequest handoff(UUID action, Map<?, ?> claim, String owner,
            long now, long until, VirtualExperimentService.EffectDisposition disposition) {
        return new VirtualExperimentService.HandoffRequest(action, (String) claim.get("executionOwner"),
                (Long) claim.get("fence"), (Long) claim.get("leaseVersion"), owner, now, until, disposition);
    }
    private static VirtualExperimentService.PairEvaluator counted(AtomicInteger calls) {
        return new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                    String caseId, int repeat, Map<String, Object> proposal) { calls.incrementAndGet(); return review(); }
        };
    }

    @Test void leasedCompletionAtExactExpiryKeepsOriginalPendingAndWholeSnapshot() {
        var f = new SimulationFixture(); var service = service(f, constant());
        UUID id = experiment(service, f, 1), action = f.id();
        var claim = service.claimLeased(ACTOR, action, id, "synthetic-owner-a", 10L, 20L);
        assertNotNull(claim.receipt()); assertNotNull(claim.permit());
        var evaluated = service.evaluateLeased(ACTOR, claim.permit(), 10L);
        assertNull(evaluated.savedReceipt()); assertNotNull(evaluated.evaluatedPair());
        var before = f.store.snapshot();
        assertEquals(503, assertThrows(SimulationFailure.class,
                () -> service.finalizeLeased(ACTOR, claim.permit(), evaluated.evaluatedPair(), 20L)).status());
        assertEquals(before, f.store.snapshot());
        var pending = f.store.snapshot().get("_virtual_action_journal").get(action.toString());
        assertEquals("RESERVED", pending.get("reservationStatus"));
        assertFalse(pending.containsKey("reply"));
        assertEquals(0, service.get(ACTOR, id).get("completedPairs"));
    }

    @Test void leasedHandoffStaleOwnerFenceOrVersionCannotReserveControlOrChangeClaim() {
        var f = new SimulationFixture(); var service = service(f, constant());
        UUID id = experiment(service, f, 1), action = f.id();
        service.claimLeased(ACTOR, action, id, "synthetic-owner-a", 10L, 20L);
        var stored = leaseBoundaryClaim(f, id);
        long fence = (Long) stored.get("fence"), version = (Long) stored.get("leaseVersion");
        for (int arm = 0; arm < 3; arm++) {
            var request = new VirtualExperimentService.HandoffRequest(action,
                    arm == 0 ? "synthetic-owner-other" : "synthetic-owner-a",
                    arm == 1 ? fence + 1 : fence, arm == 2 ? version + 1 : version,
                    "synthetic-owner-b", 20L, 30L,
                    VirtualExperimentService.EffectDisposition.SIDE_EFFECT_FREE_CONFIRMED);
            var before = f.store.snapshot(); UUID control = f.id();
            assertEquals(503, assertThrows(SimulationFailure.class,
                    () -> service.handoffLeased(ACTOR, control, id, request)).status());
            assertEquals(before, f.store.snapshot());
            assertFalse(f.store.snapshot().get("_virtual_action_journal").containsKey(control.toString()));
        }
    }

    @Test void leasedCheckedCountersAndJournalWorkTokenCollisionFailWithoutMutation() {
        for (String counter : List.of("fence", "leaseVersion")) {
            var f = new SimulationFixture(); var service = service(f, constant());
            UUID id = experiment(service, f, 1), action = f.id();
            service.claimLeased(ACTOR, action, id, "synthetic-owner-a", 10L, 20L);
            var claim = leaseBoundaryClaim(f, id); claim.put(counter, Long.MAX_VALUE);
            f.store.transaction(tx -> {
                var row = tx.get("virtual_experiments", id.toString());
                var changed = SimulationRows.changed(row, "activeClaim", claim);
                if (counter.equals("fence")) changed = SimulationRows.changed(changed, "fence", Long.MAX_VALUE);
                tx.put("virtual_experiments", id.toString(), changed); return null;
            });
            var before = f.store.snapshot(); UUID control = f.id();
            var request = new VirtualExperimentService.HandoffRequest(action, "synthetic-owner-a",
                    (Long) claim.get("fence"), (Long) claim.get("leaseVersion"),
                    "synthetic-owner-b", 20L, 30L,
                    VirtualExperimentService.EffectDisposition.SIDE_EFFECT_FREE_CONFIRMED);
            assertEquals(503, assertThrows(SimulationFailure.class,
                    () -> service.handoffLeased(ACTOR, control, id, request)).status());
            assertEquals(before, f.store.snapshot());
        }
        var f = new SimulationFixture(); UUID repeatedToken = new UUID(55L, 1L);
        var service = new VirtualExperimentService(f.store, f.access,
                List.of(new VirtualExperimentService.FixtureSet("synthetic-suite",
                        List.of(new VirtualExperimentService.Case("synthetic-normal",
                                SimulationSpec.KycStatus.VERIFIED, List.of(ID_FACT, FACE_FACT))))),
                constant(), () -> repeatedToken);
        UUID id = experiment(service, f, 1), action = f.id();
        var before = f.store.snapshot();
        assertEquals(503, assertThrows(SimulationFailure.class,
                () -> service.claimLeased(ACTOR, action, id, "synthetic-owner-a", 10L, 20L)).status());
        assertEquals(before, f.store.snapshot());
    }

    @Test void legacyAndMalformedTwelveFieldClaimsAreNotSilentlyConvertedOrRepaired() {
        var legacy = new SimulationFixture();
        var fatal = new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment e,
                    String c, int repeat, Map<String, Object> proposal) {
                throw new AssertionError("synthetic-leave-legacy-pending");
            }
        };
        var legacyService = service(legacy, fatal); UUID legacyId = experiment(legacyService, legacy, 1);
        UUID legacyAction = legacy.id();
        assertThrows(AssertionError.class, () -> legacyService.advance(ACTOR, legacyAction, legacyId));
        assertEquals(6, leaseBoundaryClaim(legacy, legacyId).size());
        var legacyBefore = legacy.store.snapshot();
        var request = new VirtualExperimentService.HandoffRequest(legacyAction, "synthetic-owner-a", 1L, 0L,
                "synthetic-owner-b", 20L, 30L,
                VirtualExperimentService.EffectDisposition.SIDE_EFFECT_FREE_CONFIRMED);
        // Selected shape-invalid rule: valid legacy format is not a leased claim.
        assertEquals(400, assertThrows(SimulationFailure.class,
                () -> legacyService.handoffLeased(ACTOR, legacy.id(), legacyId, request)).status());
        assertEquals(legacyBefore, legacy.store.snapshot());
        for (String mutation : List.of("format", "missing-token", "wrong-journal-token", "same-token", "extra")) {
            var f = new SimulationFixture(); var service = service(f, constant());
            UUID id = experiment(service, f, 1), action = f.id();
            service.claimLeased(ACTOR, action, id, "synthetic-owner-a", 10L, 20L);
            var claim = leaseBoundaryClaim(f, id); assertEquals(12, claim.size());
            long fence = (Long) claim.get("fence"), version = (Long) claim.get("leaseVersion");
            switch (mutation) {
                case "format" -> claim.put("claimFormat", "synthetic-unknown-format");
                case "missing-token" -> claim.remove("journalReservationToken");
                case "wrong-journal-token" -> claim.put("journalReservationToken", f.id().toString());
                case "same-token" -> claim.put("workAttemptToken", claim.get("journalReservationToken"));
                case "extra" -> claim.put("synthetic-extra", true);
                default -> throw new AssertionError("unreachable synthetic arm");
            }
            f.store.transaction(tx -> {
                var row = tx.get("virtual_experiments", id.toString());
                tx.put("virtual_experiments", id.toString(), SimulationRows.changed(row, "activeClaim", claim)); return null;
            });
            var before = f.store.snapshot();
            var takeover = new VirtualExperimentService.HandoffRequest(action, "synthetic-owner-a", fence, version,
                    "synthetic-owner-b", 20L, 30L,
                    VirtualExperimentService.EffectDisposition.SIDE_EFFECT_FREE_CONFIRMED);
            // Unknown format is unsupported lease shape; damage inside the selected
            // tagged format is an unavailable operational claim, never repaired.
            int expectedStatus = mutation.equals("format") ? 400 : 503;
            assertEquals(expectedStatus, assertThrows(SimulationFailure.class,
                    () -> service.handoffLeased(ACTOR, f.id(), id, takeover)).status());
            assertEquals(before, f.store.snapshot());
        }
    }

    private static java.util.Map<String, Object> leaseBoundaryClaim(SimulationFixture f, UUID id) {
        var result = new java.util.LinkedHashMap<String, Object>();
        var row = f.store.snapshot().get("virtual_experiments").get(id.toString());
        var claim = (Map<?, ?>) row.get("activeClaim");
        claim.forEach((key, value) -> result.put((String) key, value));
        return result;
    }

    @Test void leasedCompletedReceiptReplayStillRequiresCurrentAuthorityAndStoredActorOwner() {
        var f = new SimulationFixture(); var service = service(f, constant());
        UUID id = experiment(service, f, 1), action = f.id();
        var claimed = service.claimLeased(ACTOR, action, id, "synthetic-owner-a", 1L, 10L);
        assertNotNull(claimed.permit());
        var evaluated = service.evaluateLeased(ACTOR, claimed.permit(), 2L);
        var completed = service.finalizeLeased(ACTOR, claimed.permit(), evaluated.evaluatedPair(), 3L);
        assertEquals("COMPLETED", completed.get("status"));
        f.permitted.set(false);
        assertEquals(403, assertThrows(SimulationFailure.class,
                () -> service.claimLeased(ACTOR, action, id, "synthetic-owner-a", 50L, 60L)).status());
        assertEquals(403, assertThrows(SimulationFailure.class,
                () -> service.evaluateLeased(ACTOR, claimed.permit(), 50L)).status());
        f.permitted.set(true);
        var foreign = new com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef("synthetic-other");
        assertEquals(403, assertThrows(SimulationFailure.class,
                () -> service.claimLeased(foreign, action, id, "synthetic-owner-a", 50L, 60L)).status());
        assertEquals(403, assertThrows(SimulationFailure.class,
                () -> service.get(foreign, id)).status());
        var replay = service.claimLeased(ACTOR, action, id, "synthetic-owner-a", 50L, 60L);
        assertNull(replay.permit());
        assertEquals("COMPLETED", replay.receipt().get("status"));
        assertEquals(true, replay.receipt().get("replayed"));
    }

    @Test void sameHandoffControlReplayReturnsSafeReceiptWithoutAnotherWorkPermit() {
        var f = new SimulationFixture(); var service = service(f, constant());
        UUID id = experiment(service, f, 1), advance = f.id(), handoff = f.id();
        service.claimLeased(ACTOR, advance, id, "synthetic-owner-a", 1L, 10L);
        var claim = (Map<?, ?>) f.store.snapshot().get("virtual_experiments").get(id.toString()).get("activeClaim");
        var request = new VirtualExperimentService.HandoffRequest(advance, "synthetic-owner-a",
                ((Number) claim.get("fence")).longValue(), ((Number) claim.get("leaseVersion")).longValue(),
                "synthetic-owner-b", 10L, 20L, VirtualExperimentService.EffectDisposition.SIDE_EFFECT_FREE_CONFIRMED);
        var first = service.handoffLeased(ACTOR, handoff, id, request);
        assertNotNull(first.permit());
        var replay = service.handoffLeased(ACTOR, handoff, id, request);
        assertNull(replay.permit());
        assertEquals(true, replay.receipt().get("replayed"));
        assertEquals(java.util.Set.of("requestId", "experimentId", "advanceActionId", "decision", "reasonCodes", "replayed"),
                replay.receipt().keySet());
        assertEquals(first.receipt().get("requestId"), replay.receipt().get("requestId"));
        assertEquals(first.receipt().get("reasonCodes"), replay.receipt().get("reasonCodes"));
        assertThrows(UnsupportedOperationException.class, () -> replay.receipt().put("permit", "forged"));
    }

    @Test void leasedGetReceiptsAndOpaqueHoldersDoNotRevealInternalAttemptOrJournalFields() {
        var f = new SimulationFixture(); var service = service(f, constant());
        UUID id = experiment(service, f, 1), action = f.id();
        var claimed = service.claimLeased(ACTOR, action, id, "synthetic-owner-private", 1L, 10L);
        var stored = (Map<?, ?>) f.store.snapshot().get("virtual_experiments").get(id.toString()).get("activeClaim");
        var pendingPublic = service.get(ACTOR, id);
        assertFalse(pendingPublic.containsKey("activeClaim")); assertFalse(pendingPublic.containsKey("fence"));
        var evaluated = service.evaluateLeased(ACTOR, claimed.permit(), 2L);
        assertNotNull(evaluated.evaluatedPair());
        var completed = service.finalizeLeased(ACTOR, claimed.permit(), evaluated.evaluatedPair(), 3L);
        for (String text : java.util.List.of(claimed.receipt().toString(), pendingPublic.toString(), completed.toString(),
                claimed.permit().toString(), evaluated.evaluatedPair().toString(), service.get(ACTOR, id).toString())) {
            for (String forbidden : java.util.List.of("journalReservationToken", "workAttemptToken", "executionOwner",
                    "leaseUntil", "leaseVersion", "executionState", "proposalSha256", "synthetic-owner-private"))
                assertFalse(text.contains(forbidden), "Public projection exposes an internal lease field");
            for (String tokenKey : java.util.List.of("journalReservationToken", "workAttemptToken"))
                assertFalse(text.contains((String) stored.get(tokenKey)), "Public projection exposes an internal value");
        }
        assertEquals(java.util.Set.of("requestId", "experimentId", "status", "completedPairs", "replayed", "resultsSource"),
                completed.keySet());
    }
}
