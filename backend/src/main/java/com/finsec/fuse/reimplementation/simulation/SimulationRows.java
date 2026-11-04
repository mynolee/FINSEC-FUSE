package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

/** Internal immutable-row helpers; no I/O or real database adapter. */
final class SimulationRows {
    private SimulationRows() {}
    static Map<String, Object> require(TransactionalStore.Tx tx, String table, UUID id) {
        var value = tx.get(table, id.toString());
        if (value == null) throw SimulationFailure.invalid();
        return value;
    }
    static Map<String, Object> changed(Map<String, Object> original, Object... entries) {
        var value = new LinkedHashMap<String, Object>(original);
        for (int i = 0; i < entries.length; i += 2) value.put((String) entries[i], entries[i + 1]);
        return SimulationSpec.object(value.entrySet().stream().flatMap(e -> java.util.stream.Stream.of(e.getKey(), e.getValue())).toArray());
    }
    static UUID id(Map<String, Object> row, String key) { return UUID.fromString((String) row.get(key)); }
    static int integer(Map<String, Object> row, String key) { return ((Number) row.get(key)).intValue(); }
    static long number(Map<String, Object> row, String key) { return ((Number) row.get(key)).longValue(); }
    static boolean sameWorkflow(Map<String, Object> row, UUID workflow) { return workflow.toString().equals(row.get("workflowId")); }
    static List<Map<String, Object>> forWorkflow(TransactionalStore.Tx tx, String table, UUID workflow) {
        return tx.rows(table).values().stream().filter(row -> sameWorkflow(row, workflow)).toList();
    }
    static UUID fresh(TransactionalStore.Tx tx, String table, Supplier<UUID> ids) {
        UUID id = java.util.Objects.requireNonNull(ids.get());
        if (tx.get(table, id.toString()) != null) throw SimulationFailure.unavailable();
        return id;
    }
    static List<String> strings(Object value) {
        if (!(value instanceof List<?> list) || list.stream().anyMatch(v -> !(v instanceof String))) throw SimulationFailure.invalid();
        return list.stream().map(String.class::cast).toList();
    }
}
