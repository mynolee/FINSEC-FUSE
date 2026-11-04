package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;

/** Manual test-harness adapter for the existing public routes. No server is started. */
@RestController
@RequestMapping("/api/v1")
public final class SimulationApiController {
    @FunctionalInterface public interface HttpActors {
        /** Must authenticate AND authorize the requested operation and object scope; no default implementation exists. */
        ActorRef authorize(HttpServletRequest request, SimulationAccess.Operation operation, UUID workflowId);
    }
    private final VirtualWorkflowService workflows;
    private final VirtualQuarantineService quarantines;
    private final VirtualExperimentService experiments;
    private final HttpActors actors;

    public SimulationApiController(VirtualWorkflowService workflows, VirtualQuarantineService quarantines,
            VirtualExperimentService experiments, HttpActors actors) {
        this.workflows = Objects.requireNonNull(workflows); this.quarantines = Objects.requireNonNull(quarantines);
        this.experiments = Objects.requireNonNull(experiments); this.actors = Objects.requireNonNull(actors);
    }
    /** Preserved direct no-filter controller entry point; only the state-aware overload is HTTP mapped. */
    public ResponseEntity<?> workflows(HttpServletRequest http, int page, int size) {
        return workflows(http, "", page, size);
    }
    @GetMapping(path = "/workflows", produces = "application/json")
    public ResponseEntity<?> workflows(HttpServletRequest http,
                                       @RequestParam(name = "state", defaultValue = "") String state,
                                       @RequestParam(defaultValue = "0") int page,
                                       @RequestParam(defaultValue = "20") int size) {
        return ok(workflows.list(actor(http, SimulationAccess.Operation.READ, null), state, page, size));
    }
    @GetMapping(path = "/workflows/{workflowId}", produces = "application/json")
    public ResponseEntity<?> workflow(HttpServletRequest http, @PathVariable String workflowId) {
        UUID id = uuid(workflowId); return ok(workflows.get(actor(http, SimulationAccess.Operation.READ, id), id));
    }
    @GetMapping(path = "/workflows/{workflowId}/trace", produces = "application/json")
    public ResponseEntity<?> trace(HttpServletRequest http, @PathVariable String workflowId) {
        UUID id = uuid(workflowId); return ok(workflows.trace(actor(http, SimulationAccess.Operation.READ, id), id));
    }
    @GetMapping(path = "/workflows/{workflowId}/approval-preview", produces = "application/json")
    public ResponseEntity<?> preview(HttpServletRequest http, @PathVariable String workflowId) {
        UUID id = uuid(workflowId); return ok(workflows.approvalPreview(actor(http, SimulationAccess.Operation.REVIEW, id), id));
    }
    @PostMapping(path = "/workflows/{workflowId}/approvals", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> approval(HttpServletRequest http, @PathVariable String workflowId, @RequestBody Map<String, Object> body) {
        closed(body, Set.of("decision", "reviewSnapshotHash", "comment"));
        String decision = text(body, "decision");
        if (!Set.of("APPROVE", "REJECT").contains(decision)) throw SimulationFailure.invalid();
        UUID id = uuid(workflowId);
        return ok(workflows.approve(actor(http, SimulationAccess.Operation.REVIEW, id), action(http), id,
                decision.equals("APPROVE"), text(body, "reviewSnapshotHash"), text(body, "comment")));
    }
    @PostMapping(path = "/quarantines", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> quarantine(HttpServletRequest http, @RequestBody Map<String, Object> body) {
        VirtualQuarantineService.Scope scope;
        try { scope = VirtualQuarantineService.Scope.valueOf(text(body, "scope")); }
        catch (IllegalArgumentException invalid) { throw SimulationFailure.invalid(); }
        Set<String> keys = switch (scope) {
            case RUN -> Set.of("runId"); case RESULT -> Set.of("resultId"); case WORKFLOW -> Set.of("workflowId");
            case SOURCE_VERSION -> Set.of("documentId", "documentVersion"); case AGENT_VERSION -> Set.of("agentId", "agentVersion");
        };
        var expected = new java.util.HashSet<>(keys); expected.addAll(Set.of("scope", "reasonCode", "note"));
        closed(body, expected);
        var target = new java.util.LinkedHashMap<String, Object>();
        keys.stream().sorted().forEach(key -> target.put(key, body.get(key)));
        return ok(quarantines.create(actor(http, SimulationAccess.Operation.QUARANTINE, null), action(http),
                new VirtualQuarantineService.Target(scope, target), text(body, "reasonCode"), text(body, "note")));
    }
    @PostMapping(path = "/quarantines/{quarantineId}/release", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> release(HttpServletRequest http, @PathVariable String quarantineId, @RequestBody Map<String, Object> body) {
        closed(body, Set.of("remediation"));
        Map<String, Object> remediation = nested(body, "remediation");
        Set<String> basic = Set.of("safeDocumentId", "safeDocumentVersion", "checkEvidenceIds", "note");
        Set<String> agent = Set.of("safeDocumentId", "safeDocumentVersion", "checkEvidenceIds", "note", "safeAgentId", "safeAgentVersion");
        if (!remediation.keySet().equals(basic) && !remediation.keySet().equals(agent)) throw SimulationFailure.invalid();
        UUID id = uuid(quarantineId);
        return ok(quarantines.release(actor(http, SimulationAccess.Operation.RELEASE, null), action(http), id,
                new VirtualQuarantineService.Remediation(uuid(text(remediation, "safeDocumentId")), integer(remediation, "safeDocumentVersion"),
                        uuidList(remediation.get("checkEvidenceIds")), text(remediation, "note"),
                        remediation.containsKey("safeAgentId") ? text(remediation, "safeAgentId") : null,
                        remediation.containsKey("safeAgentVersion") ? integer(remediation, "safeAgentVersion") : null)));
    }
    @GetMapping(path = "/incidents/{quarantineId}/impact", produces = "application/json")
    public ResponseEntity<?> impact(HttpServletRequest http, @PathVariable String quarantineId) {
        return ok(quarantines.impact(actor(http, SimulationAccess.Operation.READ, null), uuid(quarantineId)));
    }
    @PostMapping(path = "/experiments", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> experiment(HttpServletRequest http, @RequestBody Map<String, Object> body) {
        closed(body, Set.of("fixtureSetId", "caseIds", "mode", "modelMode", "repeatCount"));
        return ok(experiments.create(actor(http, SimulationAccess.Operation.EXPERIMENT, null), action(http),
                new VirtualExperimentService.Plan(text(body, "fixtureSetId"), strings(body.get("caseIds")),
                        text(body, "mode"), text(body, "modelMode"), integer(body, "repeatCount"))));
    }
    @PostMapping(path = "/experiments/{experimentId}/cancel", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> cancelExperiment(HttpServletRequest http, @PathVariable String experimentId,
                                             @RequestBody Map<String, Object> body) {
        closed(body, Set.of());
        return ok(experiments.cancel(actor(http, SimulationAccess.Operation.EXPERIMENT, null), action(http), uuid(experimentId)));
    }

    @GetMapping(path = "/experiments/{experimentId}", produces = "application/json")
    public ResponseEntity<?> experiment(HttpServletRequest http, @PathVariable String experimentId) {
        return ok(experiments.get(actor(http, SimulationAccess.Operation.EXPERIMENT, null), uuid(experimentId)));
    }
    /** Explicit new synthetic registry: original/private fixture sets are never guessed or reconstructed. */
    @GetMapping(path = "/simulation/fixtures", produces = "application/json")
    public ResponseEntity<?> fixtures(HttpServletRequest http) {
        return ok(object("fixtureSets", experiments.fixtureMetadata(actor(http, SimulationAccess.Operation.EXPERIMENT, null)),
                "executionMode", VirtualTransactionalStore.MODE));
    }

    @ExceptionHandler(SimulationFailure.class)
    public ResponseEntity<?> failure(SimulationFailure failure) {
        return ResponseEntity.status(failure.status()).body(object("decision", "ERROR", "reasonCodes", List.of(failure.code()), "message", failure.code()));
    }
    @ExceptionHandler(ActionJournal.ActionConflictException.class)
    public ResponseEntity<?> conflict() {
        return ResponseEntity.badRequest().body(object("decision", "ERROR", "reasonCodes", List.of("INVALID_REQUEST"), "message", "INVALID_REQUEST"));
    }
    private ActorRef actor(HttpServletRequest http, SimulationAccess.Operation op, UUID workflow) {
        try {
            ActorRef actor = actors.authorize(http, op, workflow);
            if (actor == null) throw SimulationFailure.unauthenticated();
            SimulationSpec.synthetic(actor.actorId());
            return actor;
        } catch (SimulationFailure fixed) { throw fixed; }
        catch (IllegalArgumentException malformed) { throw SimulationFailure.forbidden(); }
        catch (RuntimeException unavailable) { throw SimulationFailure.unavailable(); }
    }
    private static ResponseEntity<?> ok(Object body) { return ResponseEntity.ok(body); }
    private static UUID action(HttpServletRequest http) {
        var headers = Collections.list(http.getHeaders("Idempotency-Key"));
        if (headers.size() != 1) throw SimulationFailure.invalid();
        return uuid(headers.get(0));
    }
    private static UUID uuid(String text) {
        if (text == null || !text.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) throw SimulationFailure.invalid();
        return UUID.fromString(text);
    }
    private static String text(Map<String, Object> body, String key) {
        if (!(body.get(key) instanceof String text)) throw SimulationFailure.invalid(); return text;
    }
    private static int integer(Map<String, Object> body, String key) {
        if (!(body.get(key) instanceof Integer number)) throw SimulationFailure.invalid(); return number;
    }
    private static List<String> strings(Object value) {
        if (!(value instanceof List<?> list) || list.stream().anyMatch(v -> !(v instanceof String))) throw SimulationFailure.invalid();
        return list.stream().map(String.class::cast).toList();
    }
    private static List<UUID> uuidList(Object value) { return strings(value).stream().map(SimulationApiController::uuid).toList(); }
    private static void closed(Map<String, Object> body, Set<String> keys) {
        if (body == null || !body.keySet().equals(keys)) throw SimulationFailure.invalid();
    }
    @SuppressWarnings("unchecked") private static Map<String, Object> nested(Map<String, Object> body, String key) {
        if (!(body.get(key) instanceof Map<?, ?> value) || value.keySet().stream().anyMatch(k -> !(k instanceof String))) throw SimulationFailure.invalid();
        return (Map<String, Object>) value;
    }
}
