package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.persistence.*;
import java.util.*;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.*;
import static com.finsec.fuse.reimplementation.simulation.VirtualGrantContinuationFixture.id;

/** Finite synchronous synthetic interleavings; no real race, provider or durable backend. */
class VirtualGrantContinuationIntegrationTest {
    static final class FaultStore implements TransactionalStore {
        final VirtualTransactionalStore delegate = new VirtualTransactionalStore();
        int attemptedWrites, publications, failAt = Integer.MAX_VALUE;
        boolean loseNextAcknowledgement;
        ContinuationCommand failAfterLaneFor;
        boolean latePrefixReached;
        public String mode() { return delegate.mode(); }
        public Map<String, Map<String, Map<String, Object>>> snapshot() { return delegate.snapshot(); }
        public <R> R transaction(Function<Tx, R> work) {
            R value = delegate.transaction(tx -> work.apply(new Tx() {
                public Map<String, Object> get(String table, String key) { return tx.get(table, key); }
                public Map<String, Map<String, Object>> rows(String table) { return tx.rows(table); }
                public void put(String table, String key, Map<String, Object> row) {
                    if (++attemptedWrites == failAt) throw new IllegalStateException("synthetic staged write failure");
                    tx.put(table, key, row);
                    if (failAfterLaneFor != null && "virtual_workflow_lanes".equals(table)
                            && failAfterLaneFor.identity().workflowId().toString().equals(key)
                            && Integer.valueOf(failAfterLaneFor.identity().generation()).equals(row.get("generation"))) {
                        requireStagedContinuationPrefix(tx, failAfterLaneFor);
                        latePrefixReached = true;
                        throw new IllegalStateException("synthetic late staged continuation failure");
                    }
                }
            }));
            publications++;
            if (loseNextAcknowledgement) {
                loseNextAcknowledgement = false;
                throw new IllegalStateException("synthetic acknowledgement unavailable");
            }
            return value;
        }
    }
    private static Map<String, Object> staged(TransactionalStore.Tx tx, String table, String key) {
        var row = tx.get(table, key); assertNotNull(row, "required staged row " + table); return row;
    }
    private static void requireStagedContinuationPrefix(TransactionalStore.Tx tx, ContinuationCommand c) {
        var i = c.identity(); String workflow = i.workflowId().toString(), request = i.globalRequestId().toString();
        assertEquals("ISSUED", staged(tx, "virtual_grant_profile_grants", i.grantId().toString()).get("state"));
        assertEquals(i.grantId().toString(), staged(tx, "virtual_grant_profile_target_bindings", i.targetRunId().toString()).get("grantId"));
        assertEquals(staged(tx, "virtual_grant_profile_root_material", i.grantId().toString()),
                staged(tx, "virtual_grant_profile_root_receipts", request));
        var receipt = staged(tx, "virtual_grant_profile_continuation_receipts", request);
        assertEquals("ADVANCED", receipt.get("kind")); assertEquals(i.generation(), receipt.get("committedGeneration"));
        var global = staged(tx, ActionJournal.TABLE, request);
        assertFalse(global.containsKey("reservationStatus")); assertFalse(global.containsKey("attemptToken"));
        assertInstanceOf(Map.class, global.get("reply"));
        var reply = (Map<?, ?>) global.get("reply");
        assertEquals(request, reply.get("requestId")); assertEquals(receipt.get("rootOrigin"), reply.get("rootOrigin"));
        assertEquals("ADVANCED", reply.get("kind"));
        assertEquals(i.grantId().toString(), staged(tx, "virtual_grant_profile_generations", workflow + ":" + i.generation()).get("rootGrantId"));
        var head = staged(tx, "virtual_grant_profile_current_heads", workflow);
        assertEquals(i.generation(), head.get("generation")); assertEquals(c.nextRevision(), head.get("revision"));
        assertEquals(i.grantId().toString(), head.get("rootGrantId"));
        assertEquals(i.generation(), staged(tx, "virtual_workflow_lanes", workflow).get("generation"));
        var current = staged(tx, "virtual_workflows", workflow);
        assertEquals(i.generation(), current.get("generation")); assertEquals("KYC_PENDING", current.get("state"));
    }

    private static void unknown(ContinuationOutcome outcome, Status status) {
        assertEquals(status, outcome.status()); assertNull(outcome.receipt());
        assertFalse(outcome.actualAuthority()); assertFalse(outcome.durable());
    }

    @Test void actualRootOriginsAndContinuationHistoryRemainJoinedAcrossActiveGenerationChange() {
        var f = new VirtualGrantContinuationFixture(); f.blockAndRelease(); var c = f.firstCommand();
        var advanced = f.advance(c);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, advanced.status());
        assertEquals(ContinuationKind.ADVANCED, advanced.receipt().kind());
        assertEquals(2, advanced.receipt().committedGeneration());
        f.store.transaction(tx -> {
            var oldOrigin = VirtualGrantTransactionJournal.originalGeneration(tx, f.scope(1));
            var nextOrigin = VirtualGrantTransactionJournal.generationOrigin(tx, f.scope(2), c.identity().grantId(), c.identity().globalRequestId());
            assertEquals(f.oldRootCommand.identity().grantId(), oldOrigin.rootGrantId());
            assertEquals(c.identity().grantId(), nextOrigin.rootGrantId());
            assertEquals(f.scope(1), oldOrigin.scope()); assertEquals(f.scope(2), nextOrigin.scope());
            return null;
        });
        var before = f.store.snapshot();
        var history = f.service(null).reconcileContinuation(f.context, c);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS, history.status());
        assertEquals(advanced.receipt(), history.receipt()); assertEquals(before, f.store.snapshot());
        assertEquals("KYC_PENDING", f.workflow().get("state")); assertNull(f.workflow().get("activeJobId"));
        assertNull(f.workflow().get("currentKycResultId"));
    }

    @Test void heldOldResultBlocksThatHistoryButNotAValidFreshContinuationTarget() {
        var f = new VirtualGrantContinuationFixture();
        var prepared = f.prepareCurrent();
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, prepared.status());
        String inputHash = prepared.receipt().inputSnapshotHash();
        var consumed = f.consume(1, inputHash, 9960);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, consumed.status());
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS, f.consume(1, inputHash, 9960).status());
        f.blockAndRelease();
        f.hold(new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.RESULT,
                Map.of("resultId", consumed.receipt().result().resultId().toString())));
        var c = f.firstCommand(); var advanced = f.advance(c);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, advanced.status());
        var before = f.store.snapshot(); var blocked = f.consume(1, inputHash, 9960);
        assertNotEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS, blocked.status());
        assertNotEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, blocked.status()); assertNull(blocked.receipt());
        assertEquals(before, f.store.snapshot());
        var newHistory = f.service(null).reconcileContinuation(f.context, c);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS, newHistory.status());
        assertEquals(advanced.receipt(), newHistory.receipt()); assertEquals(before, f.store.snapshot());
    }

    @Test void foreignGlobalPendingMetadataCannotBeAssumedUnrelatedAndAdmissionRollsBack() {
        var f = new VirtualGrantContinuationFixture(); f.blockAndRelease(); var c = f.firstCommand();
        var foreign = new ActionJournal.ActionIdentity("synthetic-foreign", id(9901), "synthetic-opaque", "b".repeat(64));
        new ActionJournal(f.store).reservedTransaction(tx -> { tx.reserve(foreign, id(9902)); return null; });
        var before = f.store.snapshot(); int resolutions = f.resolutions.get();
        unknown(f.advance(c), Status.RECONCILIATION_UNCONFIRMED);
        assertEquals(before, f.store.snapshot()); assertEquals(resolutions, f.resolutions.get());
        assertFalse(f.store.snapshot().get(ActionJournal.TABLE).containsKey(c.identity().globalRequestId().toString()));
        assertEquals(1, f.workflow().get("generation"));
        new ActionJournal(f.store).reservedTransaction(tx -> { tx.requirePending(foreign, id(9902)); return null; });
    }

    @Test void stagedWriteFailureRollsBackContinuationRootHeadLaneAndGlobalCompletionTogether() {
        var store = new FaultStore(); var f = new VirtualGrantContinuationFixture(store); f.blockAndRelease();
        var c = f.firstCommand(); var before = store.snapshot();
        int writes = store.attemptedWrites, publications = store.publications;
        store.failAt = writes + 3;
        unknown(f.advance(c), Status.UNCONFIRMED_BEFORE_ADMISSION);
        assertEquals(writes + 3, store.attemptedWrites); assertEquals(publications, store.publications);
        assertEquals(before, store.snapshot()); assertEquals(1, f.workflow().get("generation"));
        assertFalse(store.snapshot().get(ActionJournal.TABLE).containsKey(c.identity().globalRequestId().toString()));
    }

    @Test void lateLaneWriteFailureRollsBackAlreadyStagedRootHeadReceiptAndGlobalCompletion() {
        var store = new FaultStore(); var f = new VirtualGrantContinuationFixture(store); f.blockAndRelease();
        var c = f.firstCommand(); var before = store.snapshot();
        int writes = store.attemptedWrites, publications = store.publications, resolutions = f.resolutions.get();
        store.failAfterLaneFor = c;
        unknown(f.advance(c), Status.UNCONFIRMED_BEFORE_ADMISSION);
        assertTrue(store.latePrefixReached, "late lane interception and all staged prefix checks must be reached");
        assertTrue(store.attemptedWrites > writes + 3); assertTrue(f.resolutions.get() > resolutions);
        assertEquals(publications, store.publications); assertEquals(before, store.snapshot());
        assertEquals(1, f.workflow().get("generation"));
        assertFalse(store.snapshot().get(ActionJournal.TABLE).containsKey(c.identity().globalRequestId().toString()));

        // Independent otherwise-identical control; never retry an uncertain production command.
        var controlStore = new FaultStore(); var control = new VirtualGrantContinuationFixture(controlStore); control.blockAndRelease();
        var valid = control.firstCommand(); assertEquals(c, valid);
        int controlPublications = controlStore.publications;
        var success = control.advance(valid);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, success.status());
        assertEquals(ContinuationKind.ADVANCED, success.receipt().kind());
        assertEquals(controlPublications + 1, controlStore.publications); assertEquals(2, control.workflow().get("generation"));
        assertFalse(controlStore.latePrefixReached);
    }

    @Test void ordinaryRootTimeAtExpiryIsUnknownBeforeResolutionAndBeforeExpiryControlCanAdvance() {
        var f = new VirtualGrantContinuationFixture(); f.blockAndRelease(); var c = f.firstCommand();
        var expired = new ContinuationCommand(c.identity(), c.prior(), c.newRoot(), c.application(), c.originalTerms(),
                c.laneReference(), c.stageAgents(), java.time.Instant.ofEpochSecond(c.newRoot().claims().expiresAt()));
        var before = f.store.snapshot(); int resolutions = f.resolutions.get();
        unknown(f.advance(expired), Status.UNCONFIRMED_BEFORE_ADMISSION);
        assertEquals(before, f.store.snapshot()); assertEquals(resolutions, f.resolutions.get());
        var valid = new ContinuationCommand(c.identity(), c.prior(), c.newRoot(), c.application(), c.originalTerms(),
                c.laneReference(), c.stageAgents(), java.time.Instant.ofEpochSecond(c.newRoot().claims().expiresAt() - 1));
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, f.advance(valid).status());
    }

    @Test void lostAcknowledgementBlocksDifferentRequestUntilExactStoredReconciliationWithoutRepublishing() {
        var store = new FaultStore(); var f = new VirtualGrantContinuationFixture(store); f.blockAndRelease();
        var c = f.firstCommand(); store.loseNextAcknowledgement = true;
        unknown(f.advance(c), Status.COMMIT_UNKNOWN);
        var committed = store.snapshot(); assertEquals(2, f.workflow().get("generation"));
        var head = f.store.transaction(tx -> VirtualGrantGenerationHistory.readHead(tx, c.identity().workflowId()));
        var next = f.command(3, new ExistingHead(head), 9950);
        int publications = store.publications, resolutions = f.resolutions.get();
        var blocked = f.advance(next);
        unknown(blocked, Status.RECONCILIATION_UNCONFIRMED);
        assertEquals(ContinuationEffect.UNKNOWN, blocked.effectKnowledge());
        assertEquals(publications, store.publications); assertEquals(committed, store.snapshot());
        assertEquals(resolutions, f.resolutions.get());
        var reconciled = f.service(null).reconcileContinuation(f.context, c);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS, reconciled.status());
        assertTrue(reconciled.receipt().matches(c)); assertEquals(committed, store.snapshot());
        assertEquals(publications, store.publications); assertEquals(resolutions, f.resolutions.get());
    }
}
