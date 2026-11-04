package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.GrantStageTransactionServiceTest.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static org.junit.jupiter.api.Assertions.*;

/** COW fault injection is not a database crash or OS isolation test. */
class VirtualGrantTransactionJournalTest {
    static StageOutcome absent() {
        return StageOutcome.of(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, null, EffectKnowledge.UNKNOWN);
    }
    static final class FaultStore implements TransactionalStore {
        final VirtualTransactionalStore delegate = new VirtualTransactionalStore();
        boolean failAfterCommit, failBeforeCommit, failOnDomain;
        int transactions;
        public String mode() { return delegate.mode(); }
        public Map<String, Map<String, Map<String, Object>>> snapshot() { return delegate.snapshot(); }
        public <R> R transaction(Function<Tx, R> work) {
            transactions++;
            R result = delegate.transaction(tx -> {
                Tx wrapped = new Tx() {
                    public Map<String, Object> get(String table, String key) { return tx.get(table, key); }
                    public Map<String, Map<String, Object>> rows(String table) { return tx.rows(table); }
                    public void put(String table, String key, Map<String, Object> value) {
                        if (failOnDomain && table.equals("virtual_grant_profile_domain"))
                            throw new IllegalStateException("SYNTHETIC_WRITE_FAILURE");
                        tx.put(table, key, value);
                    }
                };
                R answer = work.apply(wrapped);
                if (failBeforeCommit) { failBeforeCommit = false; throw new IllegalStateException("SYNTHETIC_LOST_COMMIT_ACK"); }
                return answer;
            });
            if (failAfterCommit) { failAfterCommit = false; throw new IllegalStateException("SYNTHETIC_POST_COMMIT_FAILURE"); }
            return result;
        }
    }

    @Test void ordinaryJournalOperationSharesGlobalRequestNamespace() {
        Fixture f = new Fixture();
        new ActionJournal(f.store).execute("other-actor", f.command.identity().globalRequestId(),
                "ordinary-operation", "a".repeat(64), tx -> Map.of("requestId", f.command.identity().globalRequestId().toString()));
        var before = f.store.snapshot();
        assertEquals(Status.IDENTITY_CONFLICT, f.complete().status());
        assertEquals(0, f.facts.resolutions); assertEquals(before, f.store.snapshot());
    }

    @Test void pendingNamespaceEntryDoesNotBecomeFreshFromNullCompletedLookup() {
        Fixture f = new Fixture();
        new ActionJournal(f.store).reservedTransaction(tx -> {
            tx.reserve(new ActionJournal.ActionIdentity("synthetic-actor", f.command.identity().globalRequestId(),
                    "other-operation", "b".repeat(64)), id(300)); return null;
        });
        var before = f.store.snapshot();
        // This conflicting reservation also demonstrates no resolution before positive admission.
        assertEquals(Status.IDENTITY_CONFLICT, f.complete().status());
        assertEquals(0, f.facts.resolutions); assertEquals(before, f.store.snapshot());
    }

    @Test void freshAdmissionCannotSkipLookupOrReturnWithoutCompletion() {
        Fixture f = new Fixture(); var before = f.store.snapshot();
        assertEquals(Status.RECONCILIATION_UNCONFIRMED, f.journal.transact(f.command, tx -> {
            tx.admitFresh(f.command); return absent();
        }).status());
        assertEquals(before, f.store.snapshot());
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION, f.journal.transact(f.command, tx -> {
            assertNull(tx.lookup(f.command)); tx.admitFresh(f.command); return absent();
        }).status());
        assertEquals(before, f.store.snapshot());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, f.complete().status());
    }

    @Test void facadeIsRetiredAfterCallbackBeforeAnyLaterStoreTransaction() {
        FaultStore store = new FaultStore(); Fixture f = new Fixture(store);
        AtomicReference<OwnedTx> retained = new AtomicReference<>();
        f.journal.transact(f.command, tx -> { retained.set(tx); return absent(); });
        int before = store.transactions;
        assertThrows(IllegalStateException.class, () -> retained.get().grant(f.root.grantId()));
        assertThrows(IllegalStateException.class, () -> retained.get().lookup(f.command));
        assertEquals(before, store.transactions);
    }

    @Test void wrongThreadFacadeUseIsRejectedInsideLiveCallback() throws InterruptedException {
        Fixture f = new Fixture(); AtomicReference<Throwable> observed = new AtomicReference<>();
        StageOutcome outcome = f.journal.transact(f.command, tx -> {
            Thread foreign = new Thread(() -> {
                try { tx.grant(f.root.grantId()); }
                catch (Throwable failure) { observed.set(failure); }
            });
            // Synthetic fixture budget only; not an operational transaction timeout.
            final long joinWaitMillis = 1000;
            foreign.setDaemon(true);
            foreign.start();
            InterruptedException firstInterrupt = null;
            try {
                foreign.join(joinWaitMillis);
            } catch (InterruptedException failure) {
                firstInterrupt = failure;
            } finally {
                try {
                    if (foreign.isAlive()) {
                        foreign.interrupt();
                        try { foreign.join(joinWaitMillis); }
                        catch (InterruptedException failure) {
                            if (firstInterrupt == null) firstInterrupt = failure;
                            else firstInterrupt.addSuppressed(failure);
                        }
                    }
                } catch (RuntimeException cleanupFailure) {
                    if (firstInterrupt == null) throw cleanupFailure;
                    firstInterrupt.addSuppressed(cleanupFailure);
                } finally {
                    if (firstInterrupt != null) Thread.currentThread().interrupt();
                }
            }
            if (firstInterrupt != null) throw new IllegalStateException("SYNTHETIC_INTERRUPTED", firstInterrupt);
            assertFalse(foreign.isAlive(), "Synthetic worker did not terminate within fixture waits");
            return absent();
        });
        assertInstanceOf(IllegalStateException.class, observed.get());
        assertEquals(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, outcome.status());
    }

    @Test void reentryIsRefusedWithoutOpeningAnotherTransaction() {
        FaultStore store = new FaultStore(); Fixture f = new Fixture(store);
        StageOutcome outer = f.journal.transact(f.command, tx -> {
            int before = store.transactions;
            assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,
                    f.journal.transact(f.command, nested -> { fail("reentrant callback"); return absent(); }).status());
            assertEquals(before, store.transactions); return absent();
        });
        assertEquals(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, outer.status());
    }

    @Test void callerFabricatedReceiptCannotPromoteAnAbsentTransactionToSuccess() {
        Fixture f = new Fixture(); var before = f.store.snapshot();
        StageOutcome forged = f.journal.transact(f.command, tx -> StageOutcome.of(
                Status.VIRTUAL_COMMITTED_IN_PROCESS,
                new Receipt(f.command.identity(), ReceiptKind.CONSUMPTION, f.prepared, null),
                EffectKnowledge.COMMITTED_IN_PROCESS));
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION, forged.status()); assertNull(forged.receipt());
        assertEquals(before, f.store.snapshot());
    }

    @Test void atomicDomainWriteFailureLeavesNoCompletedReservationOrConsumedGrant() {
        FaultStore store = new FaultStore(); Fixture f = new Fixture(store); var before = store.snapshot();
        store.failOnDomain = true;
        StageOutcome failed = f.complete();
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION, failed.status());
        assertEquals(EffectKnowledge.NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION, failed.effectKnowledge());
        assertEquals(before, store.snapshot());
        store.failOnDomain = false;
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, f.complete().status());
    }

    @Test void postCommitFailurePreservesHistoryButRequiresExactReconciliation() {
        FaultStore store = new FaultStore(); Fixture f = new Fixture(store); store.failAfterCommit = true;
        StageOutcome unknown = f.complete();
        assertEquals(Status.COMMIT_UNKNOWN, unknown.status()); assertEquals(EffectKnowledge.UNKNOWN, unknown.effectKnowledge());
        assertNull(unknown.receipt()); var committed = store.snapshot();
        assertEquals(1, committed.get("virtual_grant_profile_results").size());
        StageOutcome reconciled = f.service.reconcile(f.context, f.command);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS, reconciled.status());
        assertEquals(f.prepared, reconciled.receipt().result()); assertEquals(committed, store.snapshot());
        assertEquals(1, f.facts.resolutions); assertFalse(reconciled.actualAuthority()); assertFalse(reconciled.durable());
    }

    @Test void unknownWithoutCommitBlocksNewRequestAndNewJournalOnSameStoreObject() {
        FaultStore store = new FaultStore(); Fixture f = new Fixture(store); store.failBeforeCommit = true;
        StageOutcome unknown = f.complete(); assertEquals(Status.COMMIT_UNKNOWN, unknown.status());
        assertEquals(EffectKnowledge.UNKNOWN, unknown.effectKnowledge());
        assertEquals(Status.RECONCILIATION_UNCONFIRMED, f.service.reconcile(f.context, f.command).status());
        VirtualGrantTransactionJournal second = VirtualGrantTransactionJournal.detachedReference(store, () -> id(600), 65536);
        GrantStageTransactionService service = new GrantStageTransactionService(second, f.facts);
        int resolutions = f.facts.resolutions; var before = store.snapshot();
        assertEquals(Status.RECONCILIATION_UNCONFIRMED,
                service.completeStage(f.context, command(601, f.root), f.prepared).status());
        assertEquals(resolutions, f.facts.resolutions); assertEquals(before, store.snapshot());
    }

    @Test void absentEpochQueryIsUnknownNotDurableRollbackOrNewConsumption() {
        Fixture f = new Fixture(); var before = f.store.snapshot();
        StageOutcome absent = f.service.reconcile(f.context, f.command);
        assertEquals(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, absent.status());
        assertEquals(EffectKnowledge.UNKNOWN, absent.effectKnowledge()); assertNull(absent.receipt());
        assertFalse(absent.actualAuthority()); assertFalse(absent.durable());
        assertEquals(0, f.facts.resolutions); assertEquals(before, f.store.snapshot());
    }

    @Test void receiptByteCapRefusalRollsBackAllStagedRows() {
        VirtualTransactionalStore store = new VirtualTransactionalStore();
        var journal = VirtualGrantTransactionJournal.detachedReference(store, () -> id(700), 1);
        Fixture template = new Fixture(); journal.seedSyntheticRoot(template.root);
        var service = new GrantStageTransactionService(journal, template.facts); var before = store.snapshot();
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,
                service.completeStage(template.context, template.command, template.prepared).status());
        assertEquals(before, store.snapshot());
    }
    @Test void readOnlyReplayFailureIsReconciliationUnknownNotANewCommit() {
        FaultStore store = new FaultStore(); Fixture f = new Fixture(store); f.complete();
        var before = store.snapshot(); store.failAfterCommit = true;
        StageOutcome failedRead = f.service.reconcile(f.context, f.command);
        assertEquals(Status.RECONCILIATION_UNCONFIRMED, failedRead.status());
        assertEquals(EffectKnowledge.UNKNOWN, failedRead.effectKnowledge());
        assertNull(failedRead.receipt()); assertEquals(before, store.snapshot());
        assertEquals(1, f.facts.resolutions);
    }

    @Test void exactPendingIdentityIsNotMistakenForFreshWhenCompletedLookupIsNull() {
        Fixture f = new Fixture(); var i = f.command.identity();
        // Public namespace fixture: bind every admitted identity component exactly.
        String fingerprint = com.finsec.fuse.reimplementation.persistence.CanonicalJson.sha256(Map.ofEntries(
                Map.entry("actorId", i.actorId()), Map.entry("globalRequestId", i.globalRequestId().toString()),
                Map.entry("operation", i.operation()), Map.entry("canonicalizationVersion", i.canonicalizationVersion()),
                Map.entry("canonicalBodyDigest", i.canonicalBodyDigest()), Map.entry("grantId", i.grantId().toString()),
                Map.entry("actionId", i.actionId().toString()), Map.entry("targetRunId", i.targetRunId().toString()),
                Map.entry("workflowId", i.workflowId().toString()), Map.entry("generation", i.generation()),
                Map.entry("customerId", i.customerId())));
        new ActionJournal(f.store).reservedTransaction(tx -> {
            tx.reserve(new ActionJournal.ActionIdentity(i.actorId(), i.globalRequestId(), i.operation(), fingerprint), id(800));
            return null;
        });
        var before = f.store.snapshot(); StageOutcome result = f.complete();
        assertEquals(Status.RECONCILIATION_UNCONFIRMED, result.status());
        assertEquals(EffectKnowledge.UNKNOWN, result.effectKnowledge()); assertNull(result.receipt());
        assertEquals(1, f.facts.checks); assertEquals(0, f.facts.resolutions);
        assertEquals(before, f.store.snapshot());
    }

}
