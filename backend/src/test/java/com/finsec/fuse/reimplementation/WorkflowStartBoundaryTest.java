package com.finsec.fuse.reimplementation;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class WorkflowStartBoundaryTest {
    private static final UUID ACTION = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID WORKFLOW = UUID.fromString("00000000-0000-4000-8000-000000000002");
    private static final UUID ACCOUNT = UUID.fromString("00000000-0000-4000-8000-000000000003");
    private static final WorkflowStartBoundary.ActorRef ACTOR = new WorkflowStartBoundary.ActorRef("synthetic-actor");

    private static WorkflowStartBoundary.Request request() {
        return new WorkflowStartBoundary.Request("synthetic-reference", "synthetic-customer", 1L, ACCOUNT);
    }

    private static WorkflowStartBoundary.Result result(UUID action) {
        return new WorkflowStartBoundary.Result(action, WORKFLOW, 1, "QUEUED", null,
                List.of(), "Synthetic backend receipt", false);
    }

    @Test void requiresAnExplicitBackendPort() {
        assertThrows(NullPointerException.class, () -> new WorkflowStartBoundary(null));
    }

    @Test void keepsThePublicRequestLimitsAndDoesNotRewriteIdentifiers() {
        assertEquals(" reference ", new WorkflowStartBoundary.Request(" reference ", "customer", 50_000_000L, ACCOUNT).businessReference());
        assertThrows(IllegalArgumentException.class, () -> new WorkflowStartBoundary.Request(" ", "customer", 1L, ACCOUNT));
        assertThrows(IllegalArgumentException.class, () -> new WorkflowStartBoundary.Request("x".repeat(81), "customer", 1L, ACCOUNT));
        assertThrows(IllegalArgumentException.class, () -> new WorkflowStartBoundary.Request("reference", "x".repeat(65), 1L, ACCOUNT));
        assertThrows(IllegalArgumentException.class, () -> new WorkflowStartBoundary.Request("reference", "customer", 0L, ACCOUNT));
        assertThrows(IllegalArgumentException.class, () -> new WorkflowStartBoundary.Request("reference", "customer", 50_000_001L, ACCOUNT));
        assertThrows(IllegalArgumentException.class, () -> new WorkflowStartBoundary.Request("reference", "customer", null, ACCOUNT));
        assertThrows(NullPointerException.class, () -> new WorkflowStartBoundary.Request("reference", "customer", 1L, null));
    }

    @Test void dispatchesTheExactActorActionAndRequestAndReturnsTheBackendReceipt() {
        var captured = new AtomicReference<WorkflowStartBoundary.Command>();
        var expected = result(ACTION);
        var boundary = new WorkflowStartBoundary(command -> { captured.set(command); return expected; });
        var request = request();
        assertSame(expected, boundary.start(ACTOR, ACTION, request));
        assertSame(ACTOR, captured.get().actor());
        assertEquals(ACTION, captured.get().requestId());
        assertSame(request, captured.get().request());
    }

    @Test void neverSynthesizesSuccessOrSwallowsBackendRefusal() {
        var refusal = new IllegalStateException("Synthetic backend refusal");
        var failing = new WorkflowStartBoundary(command -> { throw refusal; });
        assertSame(refusal, assertThrows(IllegalStateException.class, () -> failing.start(ACTOR, ACTION, request())));
        var absent = new WorkflowStartBoundary(command -> null);
        assertThrows(IllegalStateException.class, () -> absent.start(ACTOR, ACTION, request()));
        var mismatched = new WorkflowStartBoundary(command -> result(UUID.fromString("00000000-0000-4000-8000-000000000099")));
        assertThrows(IllegalStateException.class, () -> mismatched.start(ACTOR, ACTION, request()));
    }

    @Test void leavesReplayAndIdempotencyToTheBackendInsteadOfKeepingAnInMemorySuccessCache() {
        var calls = new AtomicInteger();
        var boundary = new WorkflowStartBoundary(command -> { calls.incrementAndGet(); return result(ACTION); });
        boundary.start(ACTOR, ACTION, request());
        boundary.start(ACTOR, ACTION, request());
        assertEquals(2, calls.get());
    }

    @Test void copiesResultReasonsAndRejectsMutation() {
        var reasons = new ArrayList<>(List.of("SYNTHETIC_REASON"));
        var receipt = new WorkflowStartBoundary.Result(ACTION, WORKFLOW, 1, "QUEUED", null, reasons, "", false);
        reasons.clear();
        assertEquals(List.of("SYNTHETIC_REASON"), receipt.reasonCodes());
        assertThrows(UnsupportedOperationException.class, () -> receipt.reasonCodes().add("OTHER"));
    }

    @Test void rejectsInvalidEnvelopeBeforeCallingTheBackend() {
        var calls = new AtomicInteger();
        var boundary = new WorkflowStartBoundary(command -> { calls.incrementAndGet(); return result(ACTION); });
        assertThrows(NullPointerException.class, () -> boundary.start(null, ACTION, request()));
        assertThrows(NullPointerException.class, () -> boundary.start(ACTOR, null, request()));
        assertThrows(NullPointerException.class, () -> boundary.start(ACTOR, ACTION, null));
        assertEquals(0, calls.get());
    }
}
