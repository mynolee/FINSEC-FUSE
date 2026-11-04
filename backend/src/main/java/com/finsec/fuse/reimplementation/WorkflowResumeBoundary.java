package com.finsec.fuse.reimplementation;

import java.util.Objects;
import java.util.UUID;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary.Result;

/**
 * Dispatches a resume command without pretending that local checks establish authority
 * or current database state. A real transactional backend adapter is still required.
 */
public final class WorkflowResumeBoundary {
    private final Port port;

    public WorkflowResumeBoundary(Port port) {
        this.port = Objects.requireNonNull(port, "A backend workflow-resume port is required");
    }

    public record Request(int expectedGeneration, String reason) {
        public Request {
            if (expectedGeneration < 1 || expectedGeneration == Integer.MAX_VALUE) {
                throw new IllegalArgumentException("expectedGeneration must allow a positive next generation");
            }
            if (reason == null || reason.isBlank() || reason.length() > 1000) {
                throw new IllegalArgumentException("reason must contain between 1 and 1000 characters");
            }
        }
    }

    public record Command(ActorRef actor, UUID requestId, UUID workflowId, Request request) {
        public Command {
            Objects.requireNonNull(actor, "actor");
            Objects.requireNonNull(requestId, "requestId");
            Objects.requireNonNull(workflowId, "workflowId");
            Objects.requireNonNull(request, "request");
        }
    }

    /**
     * The production adapter must enforce caller authority and durable idempotency,
     * atomically verify the expected generation, unpaid blocked/held state, all active
     * and dependency-ancestral quarantines, and required remediation, then commit the next generation.
     * An independent generation that reuses no historical run/result does not inherit
     * those historical RUN/RESULT holds; active workflow/source/agent scope holds still apply.
     * This boundary supplies none of those authoritative decisions or persistence.
     */
    @FunctionalInterface
    public interface Port {
        Result execute(Command command);
    }

    public Result resume(ActorRef actor, UUID requestId, UUID workflowId, Request request) {
        Command command = new Command(actor, requestId, workflowId, request);
        Result result = port.execute(command);
        if (result == null) {
            throw new IllegalStateException("The backend returned no resume result");
        }
        // A denied resume leaves the blocked/held generation unchanged. It is a
        // backend denial receipt, not acknowledgement of a new generation.
        boolean unchangedDenial = "DENY".equals(result.decision())
                && ("BLOCKED".equals(result.state()) || "ON_HOLD".equals(result.state()))
                && result.generation() == request.expectedGeneration();
        if (!requestId.equals(result.requestId()) || !workflowId.equals(result.workflowId())
                || (!unchangedDenial && result.generation() != request.expectedGeneration() + 1)) {
            throw new IllegalStateException("The backend resume result is not bound to the command");
        }
        return result;
    }
}
