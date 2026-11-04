package com.finsec.fuse.reimplementation;

import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.simulation.SimulationFailure;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * New HTTP contract adapter for the existing public start/resume routes.
 * There is no default authority, database, idempotency store, or server bootstrap.
 * Both ports must be supplied by an independently approved production application.
 */
@RestController
@RequestMapping("/api/v1/workflows")
public final class WorkflowHttpController {
    public enum Operation { START, RESUME }
    public enum State {
        KYC_PENDING, KYC_VALIDATED, REVIEW_READY, WAIT_APPROVAL, APPROVED,
        PAYMENT_RESERVED, PAID, REJECTED, BLOCKED, ON_HOLD
    }
    public enum Decision { ALLOW, WAIT_APPROVAL, DENY, ERROR }
    public enum Denial { UNAUTHENTICATED, FORBIDDEN }

    public static final class Rejection extends RuntimeException {
        private final Denial denial;
        public Rejection(Denial denial) {
            super("Caller authority was not established");
            this.denial = Objects.requireNonNull(denial);
        }
    }

    /**
     * Must authenticate and authorize this operation, including customer/workflow
     * ownership. Returning an ActorRef without those checks violates this port.
     * Constructing an ActorRef alone never establishes authority.
     */
    @FunctionalInterface
    public interface ActorPort {
        WorkflowStartBoundary.ActorRef authorize(HttpServletRequest request,
                Operation operation, UUID workflowId, String customerId);
    }

    /**
     * Must enforce authoritative policy/state, transaction boundaries, durable
     * idempotency and commit acknowledgement. This adapter never caches success.
     */
    public interface CommandPort {
        Receipt start(WorkflowStartBoundary.Command command);
        Receipt resume(WorkflowResumeBoundary.Command command);
    }

    /** Public receipt fields; message/reason codes must already be public-safe. */
    public record Receipt(UUID requestId, UUID workflowId, int generation,
                          State state, Decision decision, List<String> reasonCodes,
                          String message, boolean replayed, UUID kycJobId) {
        public Receipt {
            Objects.requireNonNull(requestId); Objects.requireNonNull(workflowId);
            Objects.requireNonNull(state); Objects.requireNonNull(decision);
            Objects.requireNonNull(message);
            reasonCodes = List.copyOf(Objects.requireNonNull(reasonCodes));
            if (generation < 1) throw new IllegalArgumentException("Invalid generation");
        }
    }

    private final ActorPort actors;
    private final CommandPort commands;

    public WorkflowHttpController(ActorPort actors, CommandPort commands) {
        this.actors = Objects.requireNonNull(actors, "An explicit actor-authority port is required");
        this.commands = Objects.requireNonNull(commands, "An explicit transactional command port is required");
    }

    @PostMapping(consumes = "application/json", produces = "application/json")
    public ResponseEntity<Map<String, Object>> start(HttpServletRequest http,
                                                    @RequestBody Map<String, Object> body) {
        UUID requestId = actionId(http);
        closed(body, Set.of("businessReference", "customerId", "amountKrw", "payoutAccountId"));
        var input = new WorkflowStartBoundary.Request(text(body, "businessReference"),
                text(body, "customerId"), amount(body.get("amountKrw")),
                canonicalUuid(text(body, "payoutAccountId")));
        var actor = authorize(http, Operation.START, null, input.customerId());
        Receipt result;
        try {
            result = commands.start(new WorkflowStartBoundary.Command(actor, requestId, input));
        } catch (SimulationFailure fixed) {
            return failure(HttpStatus.valueOf(fixed.status()), fixed.code());
        } catch (ActionJournal.ActionConflictException conflict) {
            return failure(HttpStatus.BAD_REQUEST, "INVALID_REQUEST");
        } catch (RuntimeException unavailable) {
            return unavailable();
        }
        if (!bound(result, requestId) || result.kycJobId() != null) return unavailable();
        return ResponseEntity.ok(publicReceipt(result, false));
    }

    @PostMapping(path = "/{workflowId}/resume", consumes = "application/json", produces = "application/json")
    public ResponseEntity<Map<String, Object>> resume(HttpServletRequest http,
            @PathVariable String workflowId, @RequestBody Map<String, Object> body) {
        UUID workflow = canonicalUuid(workflowId);
        UUID requestId = actionId(http);
        closed(body, Set.of("expectedGeneration", "reason"));
        Object generation = body.get("expectedGeneration");
        if (!(generation instanceof Integer)) throw new IllegalArgumentException("Invalid generation");
        var input = new WorkflowResumeBoundary.Request((Integer) generation, text(body, "reason"));
        var actor = authorize(http, Operation.RESUME, workflow, null);
        Receipt result;
        try {
            result = commands.resume(new WorkflowResumeBoundary.Command(actor, requestId, workflow, input));
        } catch (SimulationFailure fixed) {
            return failure(HttpStatus.valueOf(fixed.status()), fixed.code());
        } catch (ActionJournal.ActionConflictException conflict) {
            return failure(HttpStatus.BAD_REQUEST, "INVALID_REQUEST");
        } catch (RuntimeException unavailable) {
            return unavailable();
        }
        if (!bound(result, requestId) || !workflow.equals(result.workflowId())) return unavailable();
        boolean allowed = result.decision() == Decision.ALLOW
                && result.state() == State.KYC_PENDING
                && result.generation() == input.expectedGeneration() + 1 && result.kycJobId() != null;
        boolean denied = result.decision() == Decision.DENY
                && result.state() == State.ON_HOLD
                && result.generation() == input.expectedGeneration() && result.kycJobId() == null;
        if (!allowed && !denied) return unavailable();
        return ResponseEntity.ok(publicReceipt(result, allowed));
    }

    private WorkflowStartBoundary.ActorRef authorize(HttpServletRequest request,
            Operation operation, UUID workflow, String customer) {
        try {
            var actor = actors.authorize(request, operation, workflow, customer);
            if (actor == null) throw new Rejection(Denial.UNAUTHENTICATED);
            return actor;
        } catch (Rejection rejected) {
            throw rejected;
        } catch (RuntimeException unavailable) {
            throw new AuthorityUnavailable();
        }
    }

    private static final class AuthorityUnavailable extends RuntimeException {}

    @ExceptionHandler(Rejection.class)
    public ResponseEntity<Map<String, Object>> rejected(Rejection rejected) {
        boolean missing = rejected.denial == Denial.UNAUTHENTICATED;
        return failure(missing ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN,
                missing ? "UNAUTHENTICATED" : "FORBIDDEN");
    }

    @ExceptionHandler({IllegalArgumentException.class, HttpMessageNotReadableException.class})
    public ResponseEntity<Map<String, Object>> invalid(Exception ignored) {
        return failure(HttpStatus.BAD_REQUEST, "INVALID_REQUEST");
    }

    @ExceptionHandler(AuthorityUnavailable.class)
    public ResponseEntity<Map<String, Object>> authorityUnavailable() {
        return unavailable();
    }

    private static boolean bound(Receipt value, UUID requestId) {
        return value != null && requestId.equals(value.requestId());
    }

    private static Map<String, Object> publicReceipt(Receipt receipt, boolean includeJob) {
        var body = new LinkedHashMap<String, Object>();
        body.put("requestId", receipt.requestId().toString());
        body.put("workflowId", receipt.workflowId().toString());
        body.put("generation", receipt.generation());
        body.put("state", receipt.state().name()); body.put("decision", receipt.decision().name());
        body.put("reasonCodes", receipt.reasonCodes()); body.put("message", receipt.message());
        body.put("replayed", receipt.replayed());
        if (includeJob) body.put("kycJobId", receipt.kycJobId().toString());
        return Collections.unmodifiableMap(body);
    }

    private static ResponseEntity<Map<String, Object>> unavailable() {
        return failure(HttpStatus.SERVICE_UNAVAILABLE, "DEPENDENCY_UNAVAILABLE");
    }

    private static ResponseEntity<Map<String, Object>> failure(HttpStatus status, String code) {
        return ResponseEntity.status(status).body(Map.of(
                "decision", "ERROR", "reasonCodes", List.of(code), "message", code));
    }

    private static UUID actionId(HttpServletRequest request) {
        var values = Collections.list(request.getHeaders("Idempotency-Key"));
        if (values.size() != 1) throw new IllegalArgumentException("One action identifier is required");
        return canonicalUuid(values.get(0));
    }

    private static UUID canonicalUuid(String value) {
        if (value == null || !value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
            throw new IllegalArgumentException("Invalid identifier");
        return UUID.fromString(value);
    }

    private static void closed(Map<String, Object> body, Set<String> keys) {
        if (body == null || !body.keySet().equals(keys)) throw new IllegalArgumentException("Invalid fields");
    }

    private static String text(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (!(value instanceof String)) throw new IllegalArgumentException("Invalid text");
        return (String) value;
    }

    private static Long amount(Object value) {
        if (value instanceof Integer integer) return integer.longValue();
        if (value instanceof Long number) return number;
        throw new IllegalArgumentException("Invalid integer amount");
    }
}
