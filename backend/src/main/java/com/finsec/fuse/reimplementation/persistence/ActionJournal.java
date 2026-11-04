package com.finsec.fuse.reimplementation.persistence;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;

/**
 * VIRTUAL action journal: domain mutations and the bound reply share one virtual transaction.
 * Restart loses the journal. Caller authority is an external responsibility.
 */
public final class ActionJournal {
    public static final String TABLE = "_virtual_action_journal";
    private final TransactionalStore store;

    public ActionJournal(TransactionalStore store) {
        this.store = Objects.requireNonNull(store, "store");
        if (!VirtualTransactionalStore.MODE.equals(store.mode())) {
            throw new IllegalArgumentException("This journal requires an explicit VIRTUAL store");
        }
    }

    /**
     * requestId is global to this store. Matching actor, operation and canonical body hash
     * replay the stored reply without calling work. Every mismatch is a fixed conflict.
     * The callback must return the same canonical UUID string in reply.requestId.
     */
    public Map<String, Object> execute(String actorId, UUID requestId, String operation,
                                       String canonicalBodyHash,
                                       Function<TransactionalStore.Tx, Map<String, Object>> work) {
        requireText(actorId);
        Objects.requireNonNull(requestId, "requestId");
        requireText(operation);
        if (canonicalBodyHash == null || !canonicalBodyHash.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("A canonical SHA-256 fingerprint is required");
        }
        Objects.requireNonNull(work, "work");
        String key = requestId.toString();
        return store.transaction(tx -> {
            Map<String, Object> saved = tx.get(TABLE, key);
            if (saved != null) {
                if (!actorId.equals(saved.get("actorId")) || !key.equals(saved.get("requestId"))
                        || !operation.equals(saved.get("operation"))
                        || !canonicalBodyHash.equals(saved.get("canonicalBodyHash"))) {
                    throw new ActionConflictException();
                }
                if ("RESERVED".equals(saved.get("reservationStatus"))) throw new PendingActionException();
                return receipt(saved.get("reply"), key, true);
            }
            Map<String, Object> fresh = receipt(work.apply(tx), key, false);
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("actorId", actorId);
            entry.put("requestId", key);
            entry.put("operation", operation);
            entry.put("canonicalBodyHash", canonicalBodyHash);
            entry.put("reply", fresh);
            entry.put("persistenceMode", VirtualTransactionalStore.MODE);
            entry.put("durable", false);
            tx.put(TABLE, key, entry);
            return fresh;
        });
    }


    public record ActionIdentity(String actorId, UUID requestId, String operation, String canonicalBodyHash) {
        public ActionIdentity {
            requireText(actorId); Objects.requireNonNull(requestId, "requestId"); requireText(operation);
            if (canonicalBodyHash == null || !canonicalBodyHash.matches("[0-9a-f]{64}"))
                throw new IllegalArgumentException("A canonical SHA-256 fingerprint is required");
        }
    }
    public enum ReservationStatus { RESERVED, COMPLETED }
    public record Reservation(ReservationStatus status, Map<String, Object> receipt) {}
    public interface ReservedTx extends TransactionalStore.Tx {
        /** Immutable identity-only inventory, including this transaction's own pending action. */
        List<ActionIdentity> pendingIdentities();
        Reservation reserve(ActionIdentity identity, UUID attemptToken);
        /** Checks an exact pending binding without changing journal or domain state. */
        void requirePending(ActionIdentity identity, UUID attemptToken);
        void complete(ActionIdentity identity, UUID attemptToken, Map<String, Object> reply);
        Map<String, Object> completed(ActionIdentity identity);
    }
    public <R> R reservedTransaction(Function<ReservedTx, R> work) {
        Objects.requireNonNull(work, "work");
        return store.transaction(tx -> {
            var facade = new ReservedFacade(tx);
            try { return work.apply(facade); }
            finally { facade.open = false; }
        });
    }
    private static void match(ActionIdentity identity, Map<String, Object> saved) {
        if (!identity.actorId().equals(saved.get("actorId"))
                || !identity.requestId().toString().equals(saved.get("requestId"))
                || !identity.operation().equals(saved.get("operation"))
                || !identity.canonicalBodyHash().equals(saved.get("canonicalBodyHash")))
            throw new ActionConflictException();
    }
    private static Map<String, Object> boundEntry(ActionIdentity identity) {
        var row = new LinkedHashMap<String, Object>();
        row.put("actorId", identity.actorId()); row.put("requestId", identity.requestId().toString());
        row.put("operation", identity.operation()); row.put("canonicalBodyHash", identity.canonicalBodyHash());
        row.put("persistenceMode", VirtualTransactionalStore.MODE); row.put("durable", false);
        return row;
    }
    private static final class ReservedFacade implements ReservedTx {
        private final TransactionalStore.Tx tx;
        private final Thread owner = Thread.currentThread();
        private boolean open = true;
        private ReservedFacade(TransactionalStore.Tx tx) { this.tx = tx; }
        private void check() {
            if (!open || Thread.currentThread() != owner)
                throw new IllegalStateException("Reserved transaction is closed or belongs to another thread");
        }
        private void domain(String table) {
            check(); if (TABLE.equals(table)) throw new JournalContractException();
        }
        @Override public Map<String, Object> get(String table, String id) { domain(table); return tx.get(table, id); }
        @Override public Map<String, Map<String, Object>> rows(String table) { domain(table); return tx.rows(table); }
        @Override public void put(String table, String id, Map<String, Object> row) { domain(table); tx.put(table, id, row); }
        @Override public List<ActionIdentity> pendingIdentities() {
            check();
            var pending = new ArrayList<ActionIdentity>();
            var rows = tx.rows(TABLE);
            if (rows == null) throw new JournalContractException();
            for (var entry : rows.entrySet()) {
                var row = entry.getValue();
                if (row == null || !VirtualTransactionalStore.MODE.equals(row.get("persistenceMode"))
                        || !Boolean.FALSE.equals(row.get("durable"))) throw new JournalContractException();
                boolean reserved = "RESERVED".equals(row.get("reservationStatus"));
                var expected = reserved
                        ? Set.of("actorId", "requestId", "operation", "canonicalBodyHash", "persistenceMode", "durable", "reservationStatus", "attemptToken")
                        : Set.of("actorId", "requestId", "operation", "canonicalBodyHash", "persistenceMode", "durable", "reply");
                if (!row.keySet().equals(expected)) throw new JournalContractException();
                ActionIdentity identity;
                try {
                    if (!(row.get("actorId") instanceof String actor)
                            || !(row.get("requestId") instanceof String request)
                            || !(row.get("operation") instanceof String operation)
                            || !(row.get("canonicalBodyHash") instanceof String hash)) throw new JournalContractException();
                    UUID requestId = UUID.fromString(request);
                    if (!requestId.toString().equals(request) || !request.equals(entry.getKey()))
                        throw new JournalContractException();
                    identity = new ActionIdentity(actor, requestId, operation, hash);
                    if (reserved) {
                        if (!(row.get("attemptToken") instanceof String token)
                                || !UUID.fromString(token).toString().equals(token)) throw new JournalContractException();
                    }
                } catch (IllegalArgumentException malformed) {
                    throw new JournalContractException();
                }
                if (reserved) pending.add(identity);
                else receipt(row.get("reply"), identity.requestId().toString(), true);
            }
            return List.copyOf(pending);
        }
        @Override public Reservation reserve(ActionIdentity identity, UUID token) {
            check(); Objects.requireNonNull(identity, "identity"); Objects.requireNonNull(token, "token");
            String key = identity.requestId().toString(); var saved = tx.get(TABLE, key);
            if (saved != null) {
                match(identity, saved);
                if ("RESERVED".equals(saved.get("reservationStatus"))) throw new PendingActionException();
                return new Reservation(ReservationStatus.COMPLETED, receipt(saved.get("reply"), key, true));
            }
            var row = boundEntry(identity); row.put("reservationStatus", "RESERVED");
            row.put("attemptToken", token.toString()); tx.put(TABLE, key, row);
            return new Reservation(ReservationStatus.RESERVED, null);
        }
        @Override public Map<String, Object> completed(ActionIdentity identity) {
            check(); Objects.requireNonNull(identity, "identity");
            String key = identity.requestId().toString(); var saved = tx.get(TABLE, key);
            if (saved == null) return null;
            match(identity, saved);
            return "RESERVED".equals(saved.get("reservationStatus")) ? null : receipt(saved.get("reply"), key, true);
        }
        @Override public void requirePending(ActionIdentity identity, UUID token) {
            check();
            if (identity == null || token == null) throw new ActionConflictException();
            var saved = tx.get(TABLE, identity.requestId().toString());
            if (saved == null) throw new ActionConflictException();
            match(identity, saved);
            if (!"RESERVED".equals(saved.get("reservationStatus"))
                    || !token.toString().equals(saved.get("attemptToken")))
                throw new ActionConflictException();
        }
        @Override public void complete(ActionIdentity identity, UUID token, Map<String, Object> reply) {
            check(); Objects.requireNonNull(identity, "identity"); Objects.requireNonNull(token, "token");
            String key = identity.requestId().toString(); var saved = tx.get(TABLE, key);
            if (saved == null) throw new ActionConflictException();
            match(identity, saved);
            if (!"RESERVED".equals(saved.get("reservationStatus")) || !token.toString().equals(saved.get("attemptToken")))
                throw new ActionConflictException();
            var row = boundEntry(identity); row.put("reply", receipt(reply, key, false));
            tx.put(TABLE, key, row);
        }
    }
    public static final class PendingActionException extends RuntimeException {
        public PendingActionException() { super("The virtual action is pending"); }
    }

    private static Map<String, Object> receipt(Object value, String requestId, boolean replayed) {
        if (!(value instanceof Map<?, ?> original)) {
            throw new JournalContractException();
        }
        Map<String, Object> copy = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : original.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new JournalContractException();
            }
            // Do not collapse identity/custom-map duplicate keys before JSON validation.
            if (copy.containsKey(key)) {
                throw new JournalContractException();
            }
            copy.put(key, entry.getValue());
        }
        if (!requestId.equals(copy.get("requestId"))) {
            throw new JournalContractException();
        }
        copy.put("replayed", replayed);
        return CanonicalJson.immutableObject(copy);
    }

    private static void requireText(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Actor and operation identifiers must not be blank");
        }
    }

    public static final class ActionConflictException extends RuntimeException {
        public ActionConflictException() {
            super("The request conflicts with an existing virtual action");
        }
    }

    public static final class JournalContractException extends IllegalStateException {
        public JournalContractException() {
            super("The virtual backend reply is not bound to the request");
        }
    }
}
