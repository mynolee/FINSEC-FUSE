package com.finsec.fuse.reimplementation;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class WorkflowResumeBoundaryTest {
    private static final UUID ACTION = UUID.fromString("00000000-0000-4000-8000-000000000011");
    private static final UUID WORKFLOW = UUID.fromString("00000000-0000-4000-8000-000000000012");
    private static final WorkflowStartBoundary.ActorRef ACTOR = new WorkflowStartBoundary.ActorRef("synthetic-reviewer");

    private static WorkflowStartBoundary.Result result(UUID action, UUID workflow, int generation) {
        return new WorkflowStartBoundary.Result(action, workflow, generation, "QUEUED", null,
                List.of(), "Synthetic backend receipt", false);
    }

    @Test void requiresAnExplicitBackendPortAndValidResumeInput() {
        assertThrows(NullPointerException.class, () -> new WorkflowResumeBoundary(null));
        assertThrows(IllegalArgumentException.class, () -> new WorkflowResumeBoundary.Request(0, "reviewed"));
        assertThrows(IllegalArgumentException.class, () -> new WorkflowResumeBoundary.Request(Integer.MAX_VALUE, "reviewed"));
        assertThrows(IllegalArgumentException.class, () -> new WorkflowResumeBoundary.Request(1, " "));
        assertThrows(IllegalArgumentException.class, () -> new WorkflowResumeBoundary.Request(1, "x".repeat(1001)));
        assertEquals(1000, new WorkflowResumeBoundary.Request(1, "x".repeat(1000)).reason().length());
    }

    @Test void dispatchesTheRequestedWorkflowAndExpectedGeneration() {
        var captured = new AtomicReference<WorkflowResumeBoundary.Command>();
        var expected = result(ACTION, WORKFLOW, 8);
        var boundary = new WorkflowResumeBoundary(command -> { captured.set(command); return expected; });
        var request = new WorkflowResumeBoundary.Request(7, "Synthetic reviewed remediation");
        assertSame(expected, boundary.resume(ACTOR, ACTION, WORKFLOW, request));
        assertSame(ACTOR, captured.get().actor());
        assertEquals(ACTION, captured.get().requestId());
        assertEquals(WORKFLOW, captured.get().workflowId());
        assertSame(request, captured.get().request());
    }

    @Test void rejectsUnboundBackendReceipts() {
        var request = new WorkflowResumeBoundary.Request(7, "reviewed");
        var another = UUID.fromString("00000000-0000-4000-8000-000000000099");
        var receipts = List.of(result(another, WORKFLOW, 8), result(ACTION, another, 8),
                result(ACTION, WORKFLOW, 7), result(ACTION, WORKFLOW, 9));
        for (var receipt : receipts) {
            var boundary = new WorkflowResumeBoundary(command -> receipt);
            assertThrows(IllegalStateException.class, () -> boundary.resume(ACTOR, ACTION, WORKFLOW, request));
        }
    }

    @Test void doesNotTurnMissingBackendOrAuthoritativeDenialIntoSuccess() {
        var request = new WorkflowResumeBoundary.Request(7, "reviewed");
        var absent = new WorkflowResumeBoundary(command -> null);
        assertThrows(IllegalStateException.class, () -> absent.resume(ACTOR, ACTION, WORKFLOW, request));
        var denial = new IllegalStateException("Synthetic quarantine still active");
        var denied = new WorkflowResumeBoundary(command -> { throw denial; });
        assertSame(denial, assertThrows(IllegalStateException.class, () -> denied.resume(ACTOR, ACTION, WORKFLOW, request)));
    }

    @Test void acceptsOnlyBoundBlockedOrHeldDenialsWithoutAdvancingGeneration() {
        var request = new WorkflowResumeBoundary.Request(7, "reviewed");
        for (String state : List.of("BLOCKED", "ON_HOLD")) {
            var receipt = new WorkflowStartBoundary.Result(ACTION, WORKFLOW, 7, state, "DENY",
                    List.of("RESUME_BLOCKED"), "RESUME_BLOCKED", false);
            assertSame(receipt, new WorkflowResumeBoundary(command -> receipt).resume(ACTOR, ACTION, WORKFLOW, request));
        }
        for (var receipt : List.of(
                new WorkflowStartBoundary.Result(ACTION, WORKFLOW, 7, "KYC_PENDING", "DENY", List.of(), "denied", false),
                new WorkflowStartBoundary.Result(ACTION, WORKFLOW, 7, "ON_HOLD", "ALLOW", List.of(), "allowed", false),
                new WorkflowStartBoundary.Result(ACTION, WORKFLOW, 6, "ON_HOLD", "DENY", List.of(), "denied", false),
                new WorkflowStartBoundary.Result(UUID.fromString("00000000-0000-4000-8000-000000000099"),
                        WORKFLOW, 7, "ON_HOLD", "DENY", List.of(), "denied", false))) {
            assertThrows(IllegalStateException.class,
                    () -> new WorkflowResumeBoundary(command -> receipt).resume(ACTOR, ACTION, WORKFLOW, request));
        }
    }

    @Test void leavesReplayChecksToTheBackendAndValidatesBeforeDispatch() {
        var calls = new AtomicInteger();
        var boundary = new WorkflowResumeBoundary(command -> { calls.incrementAndGet(); return result(ACTION, WORKFLOW, 8); });
        var request = new WorkflowResumeBoundary.Request(7, "reviewed");
        assertThrows(NullPointerException.class, () -> boundary.resume(ACTOR, ACTION, null, request));
        assertThrows(NullPointerException.class, () -> boundary.resume(ACTOR, null, WORKFLOW, request));
        assertEquals(0, calls.get());
        boundary.resume(ACTOR, ACTION, WORKFLOW, request);
        boundary.resume(ACTOR, ACTION, WORKFLOW, request);
        assertEquals(2, calls.get());
    }
}
