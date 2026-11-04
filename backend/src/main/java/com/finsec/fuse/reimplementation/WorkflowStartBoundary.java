package com.finsec.fuse.reimplementation;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Validates and dispatches the existing workflow-start contract.
 * This class exposes no HTTP endpoint and supplies no storage or authority implementation.
 */
public final class WorkflowStartBoundary {
    private final Port port;

    public WorkflowStartBoundary(Port port) {
        this.port = Objects.requireNonNull(port, "A backend workflow-start port is required");
    }

    /** An opaque identifier; constructing this value does not authenticate or authorize a caller. */
    public record ActorRef(String actorId) {
        public ActorRef {
            requireText(actorId, "actorId");
        }
    }

    public record Request(String businessReference, String customerId, Long amountKrw,
                          UUID payoutAccountId) {
        public Request {
            requireText(businessReference, "businessReference");
            requireText(customerId, "customerId");
            if (businessReference.length() > 80 || customerId.length() > 64) {
                throw new IllegalArgumentException("Workflow reference or customer identifier is too long");
            }
            if (amountKrw == null || amountKrw < 1 || amountKrw > 50_000_000) {
                throw new IllegalArgumentException("amountKrw must be between 1 and 50000000");
            }
            Objects.requireNonNull(payoutAccountId, "payoutAccountId");
        }
    }

    public record Command(ActorRef actor, UUID requestId, Request request) {
        public Command {
            Objects.requireNonNull(actor, "actor");
            Objects.requireNonNull(requestId, "requestId");
            Objects.requireNonNull(request, "request");
        }
    }

    /** A receipt supplied by the backend, never synthesized by this boundary. */
    public record Result(UUID requestId, UUID workflowId, int generation, String state,
                         String decision, List<String> reasonCodes, String message,
                         boolean replayed) {
        public Result {
            Objects.requireNonNull(requestId, "requestId");
            Objects.requireNonNull(workflowId, "workflowId");
            if (generation < 1) {
                throw new IllegalArgumentException("generation must be positive");
            }
            requireText(state, "state");
            Objects.requireNonNull(reasonCodes, "reasonCodes");
            reasonCodes = List.copyOf(reasonCodes);
            Objects.requireNonNull(message, "message");
        }
    }

    /**
     * The production adapter must resolve caller authority, enforce customer ownership,
     * validate registered business inputs, and provide transactional durable idempotency
     * and commit acknowledgement. No permissive or in-memory adapter is supplied here.
     */
    @FunctionalInterface
    public interface Port {
        Result execute(Command command);
    }

    public Result start(ActorRef actor, UUID requestId, Request request) {
        Command command = new Command(actor, requestId, request);
        Result result = port.execute(command);
        if (result == null) {
            throw new IllegalStateException("The backend returned no workflow result");
        }
        if (!requestId.equals(result.requestId())) {
            throw new IllegalStateException("The backend workflow result has another requestId");
        }
        return result;
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
