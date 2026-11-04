package com.finsec.fuse.reimplementation.persistence;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.persistence.ActionJournal.*;

/** Identity-only synthetic inventory; no database, provider or operational credentials. */
class ActionJournalPendingInventoryTest {
    private static final String HASH = "a".repeat(64);
    private static final String CANARY = "synthetic-reply-not-in-inventory";
    private static UUID id(long n) { return new UUID(0xabc, n); }
    private static ActionIdentity identity(long n) {
        return new ActionIdentity("synthetic-actor", id(n), "synthetic-operation", HASH);
    }
    private static final class CountingStore implements TransactionalStore {
        final VirtualTransactionalStore delegate = new VirtualTransactionalStore();
        int writes;
        public String mode() { return delegate.mode(); }
        public Map<String, Map<String, Map<String, Object>>> snapshot() { return delegate.snapshot(); }
        public <R> R transaction(Function<Tx, R> work) {
            return delegate.transaction(tx -> work.apply(new Tx() {
                public Map<String, Object> get(String table, String key) { return tx.get(table, key); }
                public Map<String, Map<String, Object>> rows(String table) { return tx.rows(table); }
                public void put(String table, String key, Map<String, Object> row) {
                    writes++; tx.put(table, key, row);
                }
            }));
        }
    }
    private static void reserve(ActionJournal journal, long n) {
        journal.reservedTransaction(tx -> {
            assertEquals(ReservationStatus.RESERVED, tx.reserve(identity(n), id(900+n)).status());
            return null;
        });
    }
    private static Map<String, Object> pendingRow(long n) {
        var row = new LinkedHashMap<String, Object>();
        row.put("actorId", "synthetic-actor"); row.put("requestId", id(n).toString());
        row.put("operation", "synthetic-operation"); row.put("canonicalBodyHash", HASH);
        row.put("persistenceMode", VirtualTransactionalStore.MODE); row.put("durable", false);
        row.put("reservationStatus", "RESERVED"); row.put("attemptToken", id(900+n).toString());
        return row;
    }
    private static void contractFailure(org.junit.jupiter.api.function.Executable work) {
        var failure = assertThrows(JournalContractException.class, work);
        assertEquals("The virtual backend reply is not bound to the request", failure.getMessage());
        assertNull(failure.getCause()); assertFalse(failure.toString().contains(CANARY));
    }
    private static void lifetimeFailure(Throwable failure) {
        assertInstanceOf(IllegalStateException.class, failure);
        assertEquals("Reserved transaction is closed or belongs to another thread", failure.getMessage());
    }

    @Test void mixedLegacyAndReservedCompletionReturnsOnlyFourFieldPendingIdentitiesIncludingOwn() {
        var store = new CountingStore(); var journal = new ActionJournal(store);
        journal.execute("synthetic-actor", id(1), "synthetic-operation", HASH,
                tx -> Map.of("requestId", id(1).toString(), "privateReply", CANARY));
        journal.reservedTransaction(tx -> {
            tx.reserve(identity(2), id(902));
            tx.complete(identity(2), id(902), Map.of("requestId", id(2).toString(), "privateReply", CANARY));
            return null;
        });
        reserve(journal, 3);
        journal.reservedTransaction(tx -> {
            tx.reserve(identity(4), id(904)); int writes = store.writes;
            var inventory = tx.pendingIdentities();
            assertEquals(Set.of(identity(3), identity(4)), new HashSet<>(inventory));
            assertEquals(2, inventory.size()); assertEquals(writes, store.writes);
            assertFalse(inventory.toString().contains(CANARY));
            assertFalse(inventory.toString().contains(id(903).toString()));
            assertFalse(inventory.toString().contains(id(904).toString()));
            assertEquals(Set.of("actorId", "requestId", "operation", "canonicalBodyHash"),
                    new HashSet<>(Arrays.stream(ActionIdentity.class.getRecordComponents()).map(c -> c.getName()).toList()));
            return null;
        });
    }

    @Test void returnedListIsImmutableAndDetachedFromLaterReserveAndComplete() {
        var journal = new ActionJournal(new VirtualTransactionalStore()); reserve(journal, 1);
        List<ActionIdentity> first = journal.reservedTransaction(tx -> {
            var prior = tx.pendingIdentities();
            assertThrows(UnsupportedOperationException.class, () -> prior.add(identity(2)));
            assertThrows(UnsupportedOperationException.class, () -> prior.set(0, identity(2)));
            assertThrows(UnsupportedOperationException.class, prior::clear);
            tx.reserve(identity(2), id(902));
            assertEquals(List.of(identity(1)), prior);
            tx.complete(identity(1), id(901), Map.of("requestId", id(1).toString()));
            assertEquals(List.of(identity(2)), tx.pendingIdentities());
            return prior;
        });
        assertEquals(List.of(identity(1)), first);
        assertEquals(List.of(identity(2)), journal.reservedTransaction(ReservedTx::pendingIdentities));
    }

    @Test void repeatedInventoryDoesNotChangeDomainJournalReplyOrToken() {
        var store = new CountingStore(); var journal = new ActionJournal(store); reserve(journal, 1);
        store.transaction(tx -> { tx.put("synthetic-domain", "item", Map.of("v", "unchanged")); return null; });
        var before = store.snapshot(); int writes = store.writes;
        journal.reservedTransaction(tx -> {
            assertEquals(tx.pendingIdentities(), tx.pendingIdentities());
            tx.requirePending(identity(1), id(901));
            assertEquals(Map.of("v", "unchanged"), tx.get("synthetic-domain", "item"));
            return null;
        });
        assertEquals(writes, store.writes); assertEquals(before, store.snapshot());
    }

    @Test void completionRemovesPendingWithoutReturningPrivateReply() {
        var store = new VirtualTransactionalStore(); var journal = new ActionJournal(store); reserve(journal, 1);
        journal.reservedTransaction(tx -> {
            tx.complete(identity(1), id(901), Map.of("requestId", id(1).toString(), "privateReply", CANARY));
            assertEquals(List.of(), tx.pendingIdentities());
            assertEquals(CANARY, tx.completed(identity(1)).get("privateReply"));
            return null;
        });
        var before = store.snapshot();
        assertEquals(List.of(), journal.reservedTransaction(ReservedTx::pendingIdentities));
        assertEquals(before, store.snapshot());
    }

    @Test void inventoryCannotBeUsedAfterCallbackCloses() {
        var journal = new ActionJournal(new VirtualTransactionalStore());
        AtomicReference<ReservedTx> escaped = new AtomicReference<>();
        journal.reservedTransaction(tx -> { escaped.set(tx); return null; });
        lifetimeFailure(assertThrows(IllegalStateException.class, () -> escaped.get().pendingIdentities()));
    }

    @Test void foreignThreadCannotQueryWhileOwnerCallbackRemainsOpen() throws InterruptedException {
        var store = new VirtualTransactionalStore(); var journal = new ActionJournal(store); reserve(journal, 1);
        var before = store.snapshot();
        journal.reservedTransaction(tx -> {
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread worker = new Thread(() -> {
                try { tx.pendingIdentities(); } catch (Throwable caught) { failure.set(caught); }
            });
            worker.setDaemon(true);
            try {
                worker.start(); worker.join(1000);
                assertFalse(worker.isAlive(), "synthetic foreign callback did not terminate");
                lifetimeFailure(failure.get());
                assertEquals(List.of(identity(1)), tx.pendingIdentities());
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt(); throw new AssertionError("synthetic owner interrupted", interrupted);
            } finally { if (worker.isAlive()) worker.interrupt(); }
            return null;
        });
        assertEquals(before, store.snapshot());
    }

    @Test void inventoryDoesNotGrantRawJournalGetRowsOrPutAccess() {
        var store = new VirtualTransactionalStore(); var journal = new ActionJournal(store); reserve(journal, 1);
        var before = store.snapshot();
        journal.reservedTransaction(tx -> {
            assertEquals(List.of(identity(1)), tx.pendingIdentities());
            contractFailure(() -> tx.get(TABLE, id(1).toString()));
            contractFailure(() -> tx.rows(TABLE));
            contractFailure(() -> tx.put(TABLE, id(2).toString(), pendingRow(2)));
            return null;
        });
        assertEquals(before, store.snapshot());
    }

    @Test void malformedPendingRowsFailClosedWithoutPartialResultOrMutation() {
        for (int variant = 0; variant < 17; variant++) {
            var store = new VirtualTransactionalStore(); var journal = new ActionJournal(store);
            var row = pendingRow(2); String key = id(2).toString();
            switch (variant) {
                case 0 -> key = id(99).toString();
                case 1 -> row.put("requestId", "not-a-uuid");
                case 2 -> row.put("requestId", id(2).toString().toUpperCase(Locale.ROOT));
                case 3 -> row.put("reservationStatus", "UNKNOWN");
                case 4 -> row.put("reservationStatus", "COMPLETED");
                case 5 -> row.put("attemptToken", "not-a-token");
                case 6 -> row.put("attemptToken", id(902).toString().toUpperCase(Locale.ROOT));
                case 7 -> row.remove("attemptToken");
                case 8 -> row.put("actorId", " ");
                case 9 -> row.put("operation", 1);
                case 10 -> row.put("canonicalBodyHash", "bad-hash");
                case 11 -> row.put("persistenceMode", "not-virtual");
                case 12 -> row.put("durable", true);
                case 13 -> row.put("reply", Map.of("requestId", id(2).toString(), "privateReply", CANARY));
                case 14 -> row.put("extra", CANARY);
                case 15 -> row.put("requestId", 1);
                case 16 -> row.put("actorId", false);
                default -> throw new AssertionError();
            }
            String badKey = key;
            store.transaction(tx -> { tx.put(TABLE, id(1).toString(), pendingRow(1)); tx.put(TABLE, badKey, row); return null; });
            var before = store.snapshot();
            contractFailure(() -> journal.reservedTransaction(ReservedTx::pendingIdentities));
            assertEquals(before, store.snapshot());
        }
    }

    @Test void malformedCompletedReplyIsNotSilentlySkippedFromInventoryValidation() {
        var store = new VirtualTransactionalStore(); var journal = new ActionJournal(store);
        journal.execute("synthetic-actor", id(1), "synthetic-operation", HASH,
                tx -> Map.of("requestId", id(1).toString(), "privateReply", CANARY));
        store.transaction(tx -> {
            var row = new LinkedHashMap<>(tx.get(TABLE, id(1).toString()));
            row.put("reply", Map.of("requestId", id(999).toString(), "privateReply", CANARY));
            tx.put(TABLE, id(1).toString(), row); return null;
        });
        var before = store.snapshot();
        contractFailure(() -> journal.reservedTransaction(ReservedTx::pendingIdentities));
        assertEquals(before, store.snapshot());
    }

    @Test void nullInventoryOrRowFromAdversarialStoreFailsWithFixedContractError() {
        for (boolean nullInventory : List.of(true, false)) {
            var backing = new VirtualTransactionalStore();
            TransactionalStore hostile = new TransactionalStore() {
                public String mode() { return backing.mode(); }
                public Map<String, Map<String, Map<String, Object>>> snapshot() { return backing.snapshot(); }
                public <R> R transaction(Function<Tx, R> work) {
                    return backing.transaction(tx -> work.apply(new Tx() {
                        public Map<String, Object> get(String table, String key) { return tx.get(table, key); }
                        public Map<String, Map<String, Object>> rows(String table) {
                            if (TABLE.equals(table)) return nullInventory ? null : Collections.singletonMap(id(1).toString(), null);
                            return tx.rows(table);
                        }
                        public void put(String table, String key, Map<String, Object> row) { tx.put(table, key, row); }
                    }));
                }
            };
            var journal = new ActionJournal(hostile); var before = backing.snapshot();
            contractFailure(() -> journal.reservedTransaction(ReservedTx::pendingIdentities));
            assertEquals(before, backing.snapshot());
        }
    }

    @Test void ownReservationIsIncludedAndReturnedIdentityCannotAuthorizeWrongToken() {
        var store = new VirtualTransactionalStore(); var journal = new ActionJournal(store);
        journal.reservedTransaction(tx -> {
            tx.reserve(identity(1), id(901));
            assertEquals(List.of(identity(1)), tx.pendingIdentities());
            assertThrows(ActionConflictException.class, () -> tx.requirePending(identity(1), id(999)));
            tx.requirePending(identity(1), id(901));
            assertThrows(PendingActionException.class, () -> tx.reserve(identity(1), id(901)));
            assertEquals(List.of(identity(1)), tx.pendingIdentities());
            return null;
        });
    }
}
