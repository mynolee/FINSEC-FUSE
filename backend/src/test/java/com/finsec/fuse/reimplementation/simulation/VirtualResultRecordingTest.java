package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;
import static com.finsec.fuse.reimplementation.simulation.VirtualWorkflowService.*;
import static org.junit.jupiter.api.Assertions.*;

final class VirtualResultRecordingTest {
    private static final UUID WORKFLOW = new UUID(2, 1), RUN = new UUID(2, 2),
            RESULT = new UUID(2, 3), ACTION = new UUID(2, 4), RESERVATION = new UUID(2, 5),
            APPROVAL = new UUID(2, 6), ACCOUNT = new UUID(2, 7), PAYMENT = new UUID(2, 8);
    private static final VirtualResultRecording.Scope SCOPE = new VirtualResultRecording.Scope(WORKFLOW, 1);
    private static final VirtualResultRecording.Port PORT = VirtualResultRecording.transactionPort();

    private VirtualTransactionalStore store(String role) {
        var store = new VirtualTransactionalStore();
        store.transaction(tx -> {
            tx.put(RUNS, RUN.toString(), object("runId", RUN.toString(), "workflowId", WORKFLOW.toString(),
                    "generation", 1, "role", role));
            return null;
        });
        return store;
    }

    @Test void agentSnapshotDetachesNestedInputAndRetainsExactEightFieldRows() {
        for (var role : VirtualResultRecording.AgentRole.values()) {
            var nested = new ArrayList<Object>(List.of("original"));
            var body = new LinkedHashMap<String, Object>(); body.put("items", nested);
            var result = new VirtualResultRecording.AgentResult(RESULT, RUN, SCOPE, role, body, "evidence");
            nested.add("later"); body.put("injected", true);
            assertEquals(Map.of("items", List.of("original")), result.body());
            assertThrows(UnsupportedOperationException.class, () -> result.body().put("x", true));
            assertThrows(UnsupportedOperationException.class, () -> ((List<?>) result.body().get("items")).clear());
            var store = store(role.name());
            store.transaction(tx -> { PORT.recordAgentResult(tx, result); return null; });
            assertEquals(object("resultId", RESULT.toString(), "runId", RUN.toString(),
                    "workflowId", WORKFLOW.toString(), "generation", 1, "role", role.name(),
                    "body", object("items", List.of("original")),
                    "resultHash", CanonicalJson.sha256(object("items", List.of("original"))),
                    "evidenceBundleHash", "evidence"), store.snapshot().get(RESULTS).get(RESULT.toString()));
            assertEquals(8, store.snapshot().get(RESULTS).get(RESULT.toString()).size());
            assertFalse(result.toString().contains("original"));
        }
    }

    @Test void wrongRoleWorkflowOrGenerationCannotRecordAgentResult() {
        for (var scope : List.of(SCOPE, new VirtualResultRecording.Scope(new UUID(9, 9), 1),
                new VirtualResultRecording.Scope(WORKFLOW, 2))) {
            var store = store(scope == SCOPE ? "PAYMENT" : "KYC"); var before = store.snapshot();
            var result = new VirtualResultRecording.AgentResult(RESULT, RUN, scope,
                    VirtualResultRecording.AgentRole.KYC, object("status", "VERIFIED"), "evidence");
            assertThrows(SimulationFailure.class, () -> store.transaction(tx -> {
                PORT.recordAgentResult(tx, result); return null;
            }));
            assertEquals(before, store.snapshot());
        }
    }

    @Test void paymentRecordIsSeparateExactDomainRowWithoutInventedReceiptDigestOrStatus() {
        var store = store("PAYMENT");
        store.transaction(tx -> {
            tx.put(RESERVATIONS, RESERVATION.toString(), object("workflowId", WORKFLOW.toString(),
                    "generation", 1, "runId", RUN.toString(), "approvalId", APPROVAL.toString()));
            PORT.recordMockPayment(tx, payment()); return null;
        });
        assertEquals(object("paymentId", PAYMENT.toString(), "workflowId", WORKFLOW.toString(), "generation", 1,
                "reservationId", RESERVATION.toString(), "approvalId", APPROVAL.toString(), "runId", RUN.toString(),
                "actionId", ACTION.toString(), "customerId", "synthetic", "amountKrw", 1000L,
                "payoutAccountId", ACCOUNT.toString(), "createdAt", "2026-10-21T00:00:00Z",
                "executionMode", VirtualTransactionalStore.MODE), store.snapshot().get(PAYMENTS).get(PAYMENT.toString()));
        assertEquals(12, store.snapshot().get(PAYMENTS).get(PAYMENT.toString()).size());
        assertFalse(store.snapshot().containsKey(RESULTS));
        assertFalse(payment().toString().contains("synthetic"));
    }

    @Test void mismatchedReservationFailsWithoutPaymentOrOtherWrites() {
        var store = store("PAYMENT");
        store.transaction(tx -> {
            tx.put(RESERVATIONS, RESERVATION.toString(), object("workflowId", WORKFLOW.toString(),
                    "generation", 1, "runId", new UUID(8, 8).toString(), "approvalId", APPROVAL.toString()));
            return null;
        });
        var before = store.snapshot();
        assertThrows(SimulationFailure.class, () -> store.transaction(tx -> {
            PORT.recordMockPayment(tx, payment()); return null;
        }));
        assertEquals(before, store.snapshot());
    }

    @Test void laterTransactionFailureRollsBackTypedResultAndJournalTogether() {
        var store = store("KYC"); var journal = new ActionJournal(store); var before = store.snapshot();
        var failure = new IllegalStateException("synthetic failure");
        assertSame(failure, assertThrows(IllegalStateException.class, () -> journal.execute(
                "synthetic-actor", ACTION, "SYNTHETIC_RECORD", "0".repeat(64), tx -> {
                    PORT.recordAgentResult(tx, new VirtualResultRecording.AgentResult(RESULT, RUN, SCOPE,
                            VirtualResultRecording.AgentRole.KYC, object("status", "VERIFIED"), "evidence"));
                    throw failure;
                })));
        assertEquals(before, store.snapshot());
        journal.execute("synthetic-actor", ACTION, "SYNTHETIC_RECORD", "0".repeat(64), tx -> {
            PORT.recordAgentResult(tx, new VirtualResultRecording.AgentResult(RESULT, RUN, SCOPE,
                    VirtualResultRecording.AgentRole.KYC, object("status", "VERIFIED"), "evidence"));
            return object("requestId", ACTION.toString(), "status", "domain-recorded");
        });
        var committed = store.snapshot();
        var replay = journal.execute("synthetic-actor", ACTION, "SYNTHETIC_RECORD", "0".repeat(64), tx -> {
            fail("replay must not call recording callback"); return Map.of();
        });
        assertEquals(true, replay.get("replayed")); assertEquals(committed, store.snapshot());
    }

    @Test void typedRecordsRejectMissingScopeAndDoNotClaimGrantAuthority() {
        assertThrows(SimulationFailure.class, () -> new VirtualResultRecording.Scope(WORKFLOW, 0));
        assertThrows(NullPointerException.class, () -> new VirtualResultRecording.Scope(null, 1));
        assertThrows(NullPointerException.class, () -> new VirtualResultRecording.AgentResult(RESULT, RUN, SCOPE,
                null, Map.of(), "evidence"));
        assertEquals(Set.of("KYC", "LOAN"), Set.of(VirtualResultRecording.AgentRole.KYC.name(),
                VirtualResultRecording.AgentRole.LOAN.name()));
    }

    @Test void failureAfterSecondTypedWriteDoesNotPublishFirstOrSecondResultOrJournal() {
        var store = store("KYC"); var journal = new ActionJournal(store); var before = store.snapshot();
        var failure = new IllegalStateException("synthetic second write failure");
        assertSame(failure, assertThrows(IllegalStateException.class, () -> journal.execute(
                "synthetic-actor", ACTION, "SYNTHETIC_TWO_RECORDS", "0".repeat(64), tx -> {
                    var writes = new int[] {0};
                    TransactionalStore.Tx failing = new TransactionalStore.Tx() {
                        @Override public Map<String, Object> get(String table, String id) { return tx.get(table, id); }
                        @Override public Map<String, Map<String, Object>> rows(String table) { return tx.rows(table); }
                        @Override public void put(String table, String id, Map<String, Object> row) {
                            tx.put(table, id, row);
                            if (RESULTS.equals(table) && ++writes[0] == 2) throw failure;
                        }
                    };
                    PORT.recordAgentResult(failing, new VirtualResultRecording.AgentResult(RESULT, RUN, SCOPE,
                            VirtualResultRecording.AgentRole.KYC, object("step", 1), "evidence"));
                    PORT.recordAgentResult(failing, new VirtualResultRecording.AgentResult(new UUID(3, 3), RUN, SCOPE,
                            VirtualResultRecording.AgentRole.KYC, object("step", 2), "evidence"));
                    fail("second recording must fail"); return Map.of();
                })));
        assertEquals(before, store.snapshot());
    }

    private VirtualResultRecording.MockPayment payment() {
        return new VirtualResultRecording.MockPayment(PAYMENT, RUN, ACTION, SCOPE, RESERVATION, APPROVAL,
                "synthetic", 1000L, ACCOUNT, Instant.parse("2026-10-21T00:00:00Z"));
    }
}
