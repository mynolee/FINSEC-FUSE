package com.finsec.fuse.reimplementation.persistence;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class VirtualTransactionalStoreTest {
    @Test void advertisesItsVirtualModeAndHasNoRowsInANewInstance() {
        var store = new VirtualTransactionalStore();
        assertEquals("VIRTUAL_NON_DURABLE", store.mode());
        assertTrue(store.snapshot().isEmpty());
        assertNull(store.transaction(tx -> tx.get("workflow", "missing")));
    }

    @Test void commitsCopiesAndReturnsDeeplyImmutableSnapshots() {
        var store = new VirtualTransactionalStore();
        List<Object> reasons = new ArrayList<>(List.of("SYNTHETIC"));
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("state", "QUEUED");
        row.put("reasons", reasons);
        row.put("optional", null);
        store.transaction(tx -> { tx.put("workflow", "w1", row); return null; });
        reasons.clear();
        row.put("state", "changed outside transaction");
        var saved = store.snapshot().get("workflow").get("w1");
        assertEquals("QUEUED", saved.get("state"));
        assertEquals(List.of("SYNTHETIC"), saved.get("reasons"));
        assertTrue(saved.containsKey("optional"));
        assertThrows(UnsupportedOperationException.class, () -> saved.put("state", "changed"));
        assertThrows(UnsupportedOperationException.class, () -> store.snapshot().clear());
        assertThrows(UnsupportedOperationException.class, () -> store.snapshot().get("workflow").clear());
    }

    @Test void exceptionsRollBackAllTablesAndLeaveThePriorCommittedVersionExact() {
        var store = new VirtualTransactionalStore();
        store.transaction(tx -> { tx.put("workflow", "w1", Map.of("state", "QUEUED")); return null; });
        var before = store.snapshot();
        var failure = new IllegalStateException("Synthetic refusal");
        assertSame(failure, assertThrows(IllegalStateException.class, () -> store.transaction(tx -> {
            tx.put("workflow", "w1", Map.of("state", "PAID"));
            tx.put("payment", "p1", Map.of("workflowId", "w1"));
            throw failure;
        })));
        assertEquals(before, store.snapshot());
        assertFalse(store.snapshot().containsKey("payment"));
    }

    @Test void transactionHandlesCannotEscapeOrRunNestedTransactions() {
        var store = new VirtualTransactionalStore();
        var escaped = new AtomicReference<TransactionalStore.Tx>();
        store.transaction(tx -> { escaped.set(tx); return null; });
        assertThrows(IllegalStateException.class, () -> escaped.get().get("workflow", "w1"));
        assertThrows(IllegalStateException.class, () -> escaped.get().put("workflow", "w1", Map.of()));
        assertThrows(IllegalStateException.class, () -> store.transaction(tx -> {
            tx.put("workflow", "w1", Map.of("state", "QUEUED"));
            return store.transaction(inner -> null);
        }));
        assertTrue(store.snapshot().isEmpty());
    }

    @Test void rowsIsAnImmutableTransactionSnapshotAndValidationFailureRollsBack() {
        var store = new VirtualTransactionalStore();
        store.transaction(tx -> {
            tx.put("workflow", "w1", Map.of("state", "QUEUED"));
            var rows = tx.rows("workflow");
            tx.put("workflow", "w2", Map.of("state", "QUEUED"));
            assertEquals(1, rows.size());
            assertThrows(UnsupportedOperationException.class, () -> rows.clear());
            return null;
        });
        assertThrows(IllegalArgumentException.class, () -> store.transaction(tx -> {
            tx.put("workflow", "w3", Map.of("state", "QUEUED"));
            tx.put("workflow", "w4", Map.of("unsupported", new Object()));
            return null;
        }));
        assertEquals(2, store.snapshot().get("workflow").size());
    }
}
