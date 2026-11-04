package com.finsec.fuse.reimplementation.persistence;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class MutableNumberBoundaryTest {
    private static final class MutableDecimal extends BigDecimal {
        private int current = 1;
        MutableDecimal() { super("1"); }
        @Override public int intValue() { return current; }
        @Override public BigDecimal stripTrailingZeros() { return BigDecimal.valueOf(current); }
    }

    private static final class MutableInteger extends BigInteger {
        private int current = 1;
        MutableInteger() { super("1"); }
        @Override public int intValue() { return current; }
    }

    @Test void rejectsExtensibleNumbersBeforeTheyCanBecomeSnapshotOrFingerprintValues() {
        for (Number value : List.<Number>of(new MutableDecimal(), new MutableInteger())) {
            assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(value));
            assertThrows(IllegalArgumentException.class, () -> CanonicalJson.orderedSha256(value));
            assertThrows(IllegalArgumentException.class,
                    () -> CanonicalJson.immutableObject(Map.of("nested", List.of(value))));
        }
        assertEquals("1", CanonicalJson.write(new BigDecimal("1.00")));
        assertEquals("1", CanonicalJson.write(new BigInteger("1")));
    }

    @Test void aCallerOwnedMutableNumberCannotEnterCommittedRowsOrJournalReceipts() {
        var store = new VirtualTransactionalStore();
        store.transaction(tx -> { tx.put("workflow", "synthetic", Map.of("amount", 1)); return null; });
        var before = store.snapshot();
        var number = new MutableDecimal();
        assertThrows(IllegalArgumentException.class, () -> store.transaction(tx -> {
            tx.put("workflow", "synthetic", Map.of("amount", 2));
            tx.put("decision", "synthetic", Map.of("amount", number));
            return null;
        }));
        var journal = new ActionJournal(store);
        var request = UUID.fromString("00000000-0000-4000-8000-000000000301");
        assertThrows(IllegalArgumentException.class, () -> journal.execute("synthetic-actor", request,
                "SYNTHETIC_OPERATION", CanonicalJson.sha256(Map.of("amount", 1)), tx -> {
                    tx.put("workflow", "synthetic", Map.of("amount", 3));
                    return Map.of("requestId", request.toString(), "amount", number);
                }));
        number.current = 99;
        assertSame(before, store.snapshot());
        assertEquals(1, store.snapshot().get("workflow").get("synthetic").get("amount"));
        assertFalse(store.snapshot().containsKey(ActionJournal.TABLE));
    }
}
