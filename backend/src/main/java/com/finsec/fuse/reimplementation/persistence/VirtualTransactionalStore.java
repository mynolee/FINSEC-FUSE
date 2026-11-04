package com.finsec.fuse.reimplementation.persistence;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Explicit VIRTUAL copy-on-write transactions. Nothing is written to a database or disk;
 * process restart loses every row. This class makes no authentication or durability claim.
 */
public final class VirtualTransactionalStore implements TransactionalStore {
    public static final String MODE = "VIRTUAL_NON_DURABLE";

    private Map<String, Map<String, Map<String, Object>>> committed = Map.of();
    private boolean transactionActive;

    @Override
    public String mode() {
        return MODE;
    }

    @Override
    public synchronized <R> R transaction(Function<Tx, R> work) {
        Objects.requireNonNull(work, "work");
        if (transactionActive) {
            throw new IllegalStateException("Nested virtual transactions are not supported");
        }
        transactionActive = true;
        Map<String, Map<String, Map<String, Object>>> working = new LinkedHashMap<>();
        committed.forEach((name, rows) -> working.put(name, new LinkedHashMap<>(rows)));
        VirtualTx tx = new VirtualTx(working);
        try {
            R result = work.apply(tx);
            tx.close();
            Map<String, Map<String, Map<String, Object>>> next = new LinkedHashMap<>();
            working.forEach((name, rows) ->
                    next.put(name, Collections.unmodifiableMap(new LinkedHashMap<>(rows))));
            committed = Collections.unmodifiableMap(next);
            return result;
        } finally {
            tx.close();
            transactionActive = false;
        }
    }

    /** Only committed data is visible here, even while called reentrantly from a transaction. */
    @Override
    public synchronized Map<String, Map<String, Map<String, Object>>> snapshot() {
        return committed;
    }

    private static void requireIdentifier(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Table and row identifiers must not be blank");
        }
    }

    private static final class VirtualTx implements Tx {
        private final Map<String, Map<String, Map<String, Object>>> working;
        private final Thread owner = Thread.currentThread();
        private boolean open = true;

        private VirtualTx(Map<String, Map<String, Map<String, Object>>> working) {
            this.working = working;
        }

        private void checkOpen() {
            if (!open || Thread.currentThread() != owner) {
                throw new IllegalStateException("Virtual transaction is closed or belongs to another thread");
            }
        }

        private void close() {
            open = false;
        }

        @Override
        public Map<String, Object> get(String table, String id) {
            checkOpen();
            requireIdentifier(table);
            requireIdentifier(id);
            Map<String, Map<String, Object>> rows = working.get(table);
            return rows == null ? null : rows.get(id);
        }

        @Override
        public Map<String, Map<String, Object>> rows(String table) {
            checkOpen();
            requireIdentifier(table);
            Map<String, Map<String, Object>> rows = working.get(table);
            return rows == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(rows));
        }

        @Override
        public void put(String table, String id, Map<String, Object> row) {
            checkOpen();
            requireIdentifier(table);
            requireIdentifier(id);
            Map<String, Object> copy = CanonicalJson.immutableObject(row);
            working.computeIfAbsent(table, name -> new LinkedHashMap<>()).put(id, copy);
        }
    }
}
