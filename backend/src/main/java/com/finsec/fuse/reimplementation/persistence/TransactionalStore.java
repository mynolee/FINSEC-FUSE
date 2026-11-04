package com.finsec.fuse.reimplementation.persistence;

import java.util.Map;
import java.util.function.Function;

/** Transaction contract only. The supplied implementation is explicitly VIRTUAL and non-durable. */
public interface TransactionalStore {
    String mode();

    <R> R transaction(Function<Tx, R> work);

    /** A deeply immutable view of committed tables, keyed by table name and row identifier. */
    Map<String, Map<String, Map<String, Object>>> snapshot();

    interface Tx {
        /** Returns a deeply immutable row, or null when the identifier does not exist. */
        Map<String, Object> get(String table, String id);

        /** Returns a deeply immutable identifier-to-row snapshot for this transaction. */
        Map<String, Map<String, Object>> rows(String table);

        /** Copies and validates JSON-compatible data; no caller-owned mutable value is retained. */
        void put(String table, String id, Map<String, Object> row);
    }
}
