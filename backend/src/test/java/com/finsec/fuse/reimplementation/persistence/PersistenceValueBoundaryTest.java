package com.finsec.fuse.reimplementation.persistence;

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PersistenceValueBoundaryTest {
    private static final UUID REQUEST = UUID.fromString("00000000-0000-4000-8000-000000000601");
    private static final String HASH = CanonicalJson.sha256(Map.of("synthetic", true));

    private static Map<String, Object> duplicateReply(String field, Object first, Object second) {
        var reply = new IdentityHashMap<String, Object>();
        reply.put("requestId", REQUEST.toString());
        reply.put(new String(field), first);
        reply.put(new String(field), second);
        return reply;
    }

    @Test void rejectsDuplicateTextualReceiptFieldsIncludingNullBeforeTheyCanCommit() {
        for (var reply : List.of(
                duplicateReply("state", "QUEUED", "PAID"),
                duplicateReply("state", null, null),
                duplicateReply("requestId", REQUEST.toString(), REQUEST.toString()),
                duplicateReply("replayed", false, true))) {
            var store = new VirtualTransactionalStore();
            store.transaction(tx -> { tx.put("workflow", "synthetic", Map.of("state", "QUEUED")); return null; });
            var before = store.snapshot();
            var journal = new ActionJournal(store);
            var error = assertThrows(ActionJournal.JournalContractException.class, () ->
                    journal.execute("synthetic-actor", REQUEST, "SYNTHETIC_OPERATION", HASH, tx -> {
                        tx.put("workflow", "synthetic", Map.of("state", "PAID"));
                        tx.put("payment", "synthetic", Map.of("amount", 1));
                        return reply;
                    }));
            assertEquals("The virtual backend reply is not bound to the request", error.getMessage());
            assertNull(error.getCause());
            assertSame(before, store.snapshot());
            assertFalse(store.snapshot().containsKey("payment"));
            assertFalse(store.snapshot().containsKey(ActionJournal.TABLE));
        }
    }

    @Test void rejectionLeavesRequestUnusedAndLaterValidReceiptRemainsDetachedOnReplay() {
        var store = new VirtualTransactionalStore();
        var journal = new ActionJournal(store);
        assertThrows(ActionJournal.JournalContractException.class, () ->
                journal.execute("synthetic-actor", REQUEST, "SYNTHETIC_OPERATION", HASH,
                        tx -> duplicateReply("state", null, null)));
        var reasons = new ArrayList<>(List.of("SYNTHETIC_REASON"));
        var supplied = new LinkedHashMap<String, Object>();
        supplied.put("requestId", REQUEST.toString());
        supplied.put("reasons", reasons);
        var first = journal.execute("synthetic-actor", REQUEST, "SYNTHETIC_OPERATION", HASH, tx -> {
            tx.put("workflow", "synthetic", Map.of("state", "QUEUED"));
            return supplied;
        });
        reasons.clear();
        supplied.clear();
        var replay = journal.execute("synthetic-actor", REQUEST, "SYNTHETIC_OPERATION", HASH,
                tx -> { throw new AssertionError("A valid saved receipt must replay without work"); });
        assertEquals(List.of("SYNTHETIC_REASON"), first.get("reasons"));
        assertEquals(List.of("SYNTHETIC_REASON"), replay.get("reasons"));
        assertEquals(false, first.get("replayed"));
        assertEquals(true, replay.get("replayed"));
        assertEquals(1, store.snapshot().get(ActionJournal.TABLE).size());
        assertThrows(UnsupportedOperationException.class, () -> replay.put("reasons", List.of()));
    }
}
