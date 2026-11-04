package com.finsec.fuse.reimplementation.persistence;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ActionJournalTest {
    private static final UUID REQUEST = UUID.fromString("00000000-0000-4000-8000-000000000101");
    private static final String HASH = CanonicalJson.sha256(Map.of("synthetic", true));

    private static Map<String, Object> reply(UUID request) {
        return Map.of("requestId", request.toString(), "workflowId", "synthetic-workflow", "state", "QUEUED");
    }

    @Test void savesDomainChangesAndReceiptInOneVirtualTransactionWithoutPublicModeFields() {
        var store = new VirtualTransactionalStore();
        var journal = new ActionJournal(store);
        var response = journal.execute("actor", REQUEST, "START_WORKFLOW", HASH, tx -> {
            tx.put("workflow", "synthetic-workflow", Map.of("state", "QUEUED"));
            return reply(REQUEST);
        });
        assertEquals(false, response.get("replayed"));
        assertFalse(response.containsKey("persistenceMode"));
        assertFalse(response.containsKey("durable"));
        var saved = store.snapshot().get(ActionJournal.TABLE).get(REQUEST.toString());
        assertEquals("actor", saved.get("actorId"));
        assertEquals("START_WORKFLOW", saved.get("operation"));
        assertEquals(HASH, saved.get("canonicalBodyHash"));
        assertEquals("VIRTUAL_NON_DURABLE", saved.get("persistenceMode"));
        assertEquals(false, saved.get("durable"));
        assertEquals(response, saved.get("reply"));
        assertEquals("QUEUED", store.snapshot().get("workflow").get("synthetic-workflow").get("state"));
    }

    @Test void replayNeverRunsTheCallbackOrMutatesTheOriginalStoredReceipt() {
        var store = new VirtualTransactionalStore();
        var journal = new ActionJournal(store);
        var calls = new AtomicInteger();
        var supplied = new LinkedHashMap<>(reply(REQUEST));
        var first = journal.execute("actor", REQUEST, "START_WORKFLOW", HASH, tx -> {
            calls.incrementAndGet();
            return supplied;
        });
        supplied.put("state", "changed after return");
        var replay = journal.execute("actor", REQUEST, "START_WORKFLOW", HASH, tx -> {
            calls.incrementAndGet();
            throw new AssertionError("A replay must not execute domain mutations");
        });
        assertEquals(1, calls.get());
        assertEquals("QUEUED", replay.get("state"));
        assertEquals(true, replay.get("replayed"));
        assertEquals(false, first.get("replayed"));
        assertEquals(first, store.snapshot().get(ActionJournal.TABLE).get(REQUEST.toString()).get("reply"));
        assertThrows(UnsupportedOperationException.class, () -> replay.put("state", "changed"));
    }

    @Test void requestIdsAreGlobalAndAnyActorOperationOrBodyMismatchIsAConflict() {
        var store = new VirtualTransactionalStore();
        var journal = new ActionJournal(store);
        journal.execute("actor", REQUEST, "START_WORKFLOW", HASH, tx -> reply(REQUEST));
        var calls = new AtomicInteger();
        for (String[] binding : new String[][]{
                {"other-actor", "START_WORKFLOW", HASH},
                {"actor", "RESUME_WORKFLOW", HASH},
                {"actor", "START_WORKFLOW", "b".repeat(64)}}) {
            assertThrows(ActionJournal.ActionConflictException.class, () ->
                journal.execute(binding[0], REQUEST, binding[1], binding[2], tx -> {
                    calls.incrementAndGet();
                    return reply(REQUEST);
                }));
        }
        assertEquals(0, calls.get());
        assertEquals(1, store.snapshot().get(ActionJournal.TABLE).size());
    }

    @Test void invalidOrUnboundRepliesAndCallbackFailuresRollBackDomainChanges() {
        var store = new VirtualTransactionalStore();
        var journal = new ActionJournal(store);
        UUID another = UUID.fromString("00000000-0000-4000-8000-000000000102");
        assertThrows(ActionJournal.JournalContractException.class, () ->
            journal.execute("actor", REQUEST, "START_WORKFLOW", HASH, tx -> {
                tx.put("workflow", "synthetic-workflow", Map.of("state", "QUEUED"));
                return reply(another);
            }));
        assertTrue(store.snapshot().isEmpty());
        var refusal = new IllegalStateException("Synthetic refusal");
        assertSame(refusal, assertThrows(IllegalStateException.class, () ->
            journal.execute("actor", REQUEST, "START_WORKFLOW", HASH, tx -> {
                tx.put("payment", "synthetic-payment", Map.of("amount", 1));
                throw refusal;
            })));
        assertTrue(store.snapshot().isEmpty());
        assertThrows(ActionJournal.JournalContractException.class, () ->
                journal.execute("actor", REQUEST, "START_WORKFLOW", HASH, tx -> null));
        assertTrue(store.snapshot().isEmpty());
    }

    @Test void validationHappensBeforeMutationAndANewInstanceHasNoDurableHistory() {
        var store = new VirtualTransactionalStore();
        var journal = new ActionJournal(store);
        assertThrows(IllegalArgumentException.class, () ->
                journal.execute("actor", REQUEST, "START_WORKFLOW", "not-a-hash", tx -> reply(REQUEST)));
        assertTrue(store.snapshot().isEmpty());
        var first = journal.execute("actor", REQUEST, "START_WORKFLOW", HASH, tx -> {
            tx.put("workflow", "synthetic-workflow", Map.of("state", "QUEUED", "instance", "first"));
            return reply(REQUEST);
        });
        var original = store.snapshot();
        assertEquals(true, new ActionJournal(store).execute("actor", REQUEST, "START_WORKFLOW", HASH,
                tx -> { throw new AssertionError("Same-store replay must preserve its committed receipt"); }).get("replayed"));
        assertEquals(original, store.snapshot());
        var restartedStore = new VirtualTransactionalStore();
        var restartedJournal = new ActionJournal(restartedStore);
        assertTrue(restartedStore.snapshot().isEmpty());
        assertNull(restartedStore.transaction(tx -> tx.get("workflow", "synthetic-workflow")));
        assertNull(restartedStore.transaction(tx -> tx.get(ActionJournal.TABLE, REQUEST.toString())));
        var calls = new AtomicInteger();
        var fresh = restartedJournal.execute("actor", REQUEST, "START_WORKFLOW", HASH, tx -> {
            calls.incrementAndGet();
            tx.put("workflow", "synthetic-workflow", Map.of("state", "QUEUED", "instance", "second"));
            var response = new LinkedHashMap<>(reply(REQUEST)); response.put("message", "synthetic new-instance execution");
            return response;
        });
        assertEquals(1, calls.get());
        assertEquals(false, fresh.get("replayed"));
        assertTrue(restartedStore.snapshot().containsKey(ActionJournal.TABLE));
        assertNotEquals(first, fresh);
        assertEquals("second", restartedStore.snapshot().get("workflow").get("synthetic-workflow").get("instance"));
        assertEquals(original, store.snapshot());
        assertEquals("first", store.snapshot().get("workflow").get("synthetic-workflow").get("instance"));
    }

    @Test void reservedGlobalKeyRejectsExecuteAndMismatchesUntilExactCompletion() {
        var store = new VirtualTransactionalStore(); var journal = new ActionJournal(store);
        var identity = new ActionJournal.ActionIdentity("actor", REQUEST, "ADVANCE", HASH);
        UUID token = new UUID(0, 9);
        assertEquals(ActionJournal.ReservationStatus.RESERVED,
                journal.reservedTransaction(tx -> tx.reserve(identity, token)).status());
        assertThrows(ActionJournal.PendingActionException.class, () ->
                journal.execute("actor", REQUEST, "ADVANCE", HASH, tx -> { throw new AssertionError(); }));
        assertThrows(ActionJournal.ActionConflictException.class, () ->
                journal.execute("other", REQUEST, "ADVANCE", HASH, tx -> reply(REQUEST)));
        assertThrows(ActionJournal.PendingActionException.class, () ->
                journal.reservedTransaction(tx -> tx.reserve(identity, new UUID(0, 10))));
        var before = store.snapshot();
        assertThrows(ActionJournal.ActionConflictException.class, () -> journal.reservedTransaction(tx -> {
            tx.put("domain", "one", Map.of("value", 1));
            tx.complete(identity, new UUID(0, 10), reply(REQUEST)); return null;
        }));
        assertEquals(before, store.snapshot());
        journal.reservedTransaction(tx -> { tx.complete(identity, token, reply(REQUEST)); return null; });
        assertEquals(true, journal.execute("actor", REQUEST, "ADVANCE", HASH,
                tx -> { throw new AssertionError(); }).get("replayed"));
        var committed = store.snapshot();
        assertThrows(ActionJournal.ActionConflictException.class, () -> journal.reservedTransaction(tx -> {
            tx.complete(identity, token, reply(REQUEST)); return null;
        }));
        assertEquals(committed, store.snapshot());
    }
    @Test void reservedFacadeLifetimeAndJournalNamespaceAreConfined() {
        var store = new VirtualTransactionalStore(); var journal = new ActionJournal(store);
        var escaped = journal.reservedTransaction(tx -> tx);
        assertThrows(IllegalStateException.class, () -> escaped.rows("domain"));
        assertThrows(IllegalStateException.class, () -> escaped.requirePending(
                new ActionJournal.ActionIdentity("actor", REQUEST, "ADVANCE", HASH), new UUID(0, 9)));
        assertThrows(ActionJournal.JournalContractException.class, () -> journal.reservedTransaction(tx -> {
            tx.put(ActionJournal.TABLE, REQUEST.toString(), Map.of()); return null;
        }));
        assertTrue(store.snapshot().isEmpty());
    }
    @Test void reservedCompletionAndDomainWritesRollBackTogetherOnFailure() {
        var store = new VirtualTransactionalStore(); var journal = new ActionJournal(store);
        var identity = new ActionJournal.ActionIdentity("actor", REQUEST, "ADVANCE", HASH);
        UUID token = new UUID(0, 9);
        journal.reservedTransaction(tx -> tx.reserve(identity, token));
        var before = store.snapshot();
        assertThrows(IllegalStateException.class, () -> journal.reservedTransaction(tx -> {
            tx.put("domain", "one", Map.of("value", 1));
            tx.complete(identity, token, reply(REQUEST));
            throw new IllegalStateException("synthetic rollback");
        }));
        assertEquals(before, store.snapshot());
        assertNull(journal.reservedTransaction(tx -> tx.completed(identity)));
        journal.reservedTransaction(tx -> { tx.put("domain", "one", Map.of("value", 1));
            tx.complete(identity, token, reply(REQUEST)); return null; });
        assertEquals(true, journal.reservedTransaction(tx -> tx.completed(identity)).get("replayed"));
        assertEquals(1, store.snapshot().get("domain").get("one").get("value"));
    }

    @Test void exactPendingGuardLeavesStateAndExistingPendingBehaviorUnchanged() {
        var store = new VirtualTransactionalStore(); var journal = new ActionJournal(store);
        var identity = new ActionJournal.ActionIdentity("actor", REQUEST, "ADVANCE", HASH);
        UUID token = new UUID(0, 9);
        journal.reservedTransaction(tx -> tx.reserve(identity, token));
        var before = store.snapshot();
        journal.reservedTransaction(tx -> {
            tx.requirePending(identity, token);
            assertNull(tx.completed(identity));
            return null;
        });
        assertEquals(before, store.snapshot());
        assertThrows(ActionJournal.PendingActionException.class, () ->
                journal.reservedTransaction(tx -> tx.reserve(identity, token)));
        assertThrows(ActionJournal.PendingActionException.class, () ->
                journal.reservedTransaction(tx -> tx.reserve(identity, new UUID(0, 10))));
        assertThrows(ActionJournal.PendingActionException.class, () ->
                journal.execute("actor", REQUEST, "ADVANCE", HASH, tx -> { throw new AssertionError(); }));
        assertEquals(before, store.snapshot());
        journal.reservedTransaction(tx -> {
            tx.requirePending(identity, token);
            tx.complete(identity, token, reply(REQUEST)); return null;
        });
        assertEquals(true, journal.reservedTransaction(tx -> tx.completed(identity)).get("replayed"));
    }

    @Test void pendingGuardRejectsEveryWrongBindingWithFixedConflictAndNoMutation() {
        var store = new VirtualTransactionalStore(); var journal = new ActionJournal(store);
        var identity = new ActionJournal.ActionIdentity("actor", REQUEST, "ADVANCE", HASH);
        UUID token = new UUID(0, 9);
        journal.reservedTransaction(tx -> tx.reserve(identity, token));
        var before = store.snapshot();
        for (var wrong : new ActionJournal.ActionIdentity[] {
                new ActionJournal.ActionIdentity("other-actor", REQUEST, "ADVANCE", HASH),
                new ActionJournal.ActionIdentity("actor", REQUEST, "OTHER_OPERATION", HASH),
                new ActionJournal.ActionIdentity("actor", REQUEST, "ADVANCE", "b".repeat(64)),
                new ActionJournal.ActionIdentity("actor", new UUID(0, 12), "ADVANCE", HASH), null}) {
            var error = assertThrows(ActionJournal.ActionConflictException.class, () ->
                    journal.reservedTransaction(tx -> { tx.requirePending(wrong, token); return null; }));
            assertEquals("The request conflicts with an existing virtual action", error.getMessage());
            assertNull(error.getCause()); assertEquals(0, error.getSuppressed().length);
            assertEquals(before, store.snapshot());
        }
        for (UUID wrongToken : new UUID[] {new UUID(0, 10), null}) {
            var error = assertThrows(ActionJournal.ActionConflictException.class, () ->
                    journal.reservedTransaction(tx -> { tx.requirePending(identity, wrongToken); return null; }));
            assertEquals("The request conflicts with an existing virtual action", error.getMessage());
            assertFalse(error.getMessage().contains(token.toString()));
            assertFalse(error.getMessage().contains(REQUEST.toString()));
            assertNull(error.getCause()); assertEquals(before, store.snapshot());
        }
    }

    @Test void pendingGuardRejectsAbsentAndCompletedActionsWithoutChangingReceipts() {
        for (boolean reserved : new boolean[] {false, true}) {
            var store = new VirtualTransactionalStore(); var journal = new ActionJournal(store);
            var identity = new ActionJournal.ActionIdentity("actor", REQUEST, "ADVANCE", HASH);
            UUID token = new UUID(0, 9);
            assertThrows(ActionJournal.ActionConflictException.class, () ->
                    journal.reservedTransaction(tx -> { tx.requirePending(identity, token); return null; }));
            assertTrue(store.snapshot().isEmpty());
            if (reserved) {
                journal.reservedTransaction(tx -> {
                    tx.reserve(identity, token); tx.complete(identity, token, reply(REQUEST)); return null;
                });
            } else {
                journal.execute("actor", REQUEST, "ADVANCE", HASH, tx -> reply(REQUEST));
            }
            var completed = store.snapshot();
            assertThrows(ActionJournal.ActionConflictException.class, () ->
                    journal.reservedTransaction(tx -> { tx.requirePending(identity, token); return null; }));
            assertEquals(completed, store.snapshot());
            var replay = journal.execute("actor", REQUEST, "ADVANCE", HASH,
                    tx -> { throw new AssertionError("Completed receipt must replay"); });
            assertEquals(true, replay.get("replayed"));
            assertEquals("QUEUED", replay.get("state"));
            assertEquals(completed, store.snapshot());
        }
    }
}
