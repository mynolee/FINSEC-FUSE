package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Public KYC DTO bridge only. It never reads prompts, service tokens, environment values, or opens HTTP. */
public final class VirtualAgentBridge {
    private final VirtualWorkflowService workflows;
    public VirtualAgentBridge(VirtualWorkflowService workflows) { this.workflows = Objects.requireNonNull(workflows); }

    /** An explicit caller can inspect input when present; a DENY receipt has no input and must not be dispatched. */
    public Map<String, Object> prepare(ActorRef actor, UUID action, UUID workflow) {
        return workflows.prepareKyc(actor, action, workflow);
    }

    public Map<String, Object> prepare(ActorRef actor, UUID action, UUID workflow, UUID expectedJobId, int expectedGeneration) {
        return workflows.prepareKyc(actor, action, workflow, expectedJobId, expectedGeneration);
    }

    /** Call only after strict JSON decoding. All public fields are closed and correlation is checked by the service. */
    public Map<String, Object> accept(ActorRef actor, UUID action, Map<String, Object> response) {
        closed(response, Set.of("requestId", "workflowId", "generation", "runId", "inputSnapshotHash", "proposal", "modelMetadata"));
        Map<String, Object> proposal = nested(response, "proposal");
        closed(proposal, Set.of("status", "evidenceIds", "explanation"));
        String explanation = text(proposal, "explanation");
        if (explanation.isEmpty() || explanation.codePointCount(0, explanation.length()) > 2000) throw SimulationFailure.invalid();
        Map<String, Object> metadata = nested(response, "modelMetadata");
        closed(metadata, Set.of("model", "promptVersion"));
        if (text(metadata, "model").isBlank() || text(metadata, "model").codePointCount(0, text(metadata, "model").length()) > 160
                || !"KYC-PROMPT-1".equals(text(metadata, "promptVersion"))) throw SimulationFailure.invalid();
        if (!(response.get("generation") instanceof Integer generation)) throw SimulationFailure.invalid();
        Object rawEvidence = proposal.get("evidenceIds");
        if (!(rawEvidence instanceof List<?> ids) || ids.size() > 10) throw SimulationFailure.invalid();
        List<UUID> evidence = ids.stream().map(VirtualAgentBridge::uuid).toList();
        SimulationSpec.KycStatus status;
        try { status = SimulationSpec.KycStatus.valueOf(text(proposal, "status")); }
        catch (IllegalArgumentException invalid) { throw SimulationFailure.invalid(); }
        // Explanation and model text never enter workflow state, public trace, or exporter inputs.
        return workflows.observeKyc(actor, action, new SimulationSpec.Observation(uuid(response.get("requestId")),
                uuid(response.get("workflowId")), generation, uuid(response.get("runId")),
                text(response, "inputSnapshotHash"), status, evidence));
    }

    private static UUID uuid(Object value) {
        if (!(value instanceof String text) || !text.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
            throw SimulationFailure.invalid();
        return UUID.fromString(text);
    }
    private static String text(Map<String, Object> map, String key) {
        if (!(map.get(key) instanceof String text)) throw SimulationFailure.invalid(); return text;
    }
    private static void closed(Map<String, Object> map, Set<String> keys) {
        if (map == null || !map.keySet().equals(keys)) throw SimulationFailure.invalid();
    }
    @SuppressWarnings("unchecked") private static Map<String, Object> nested(Map<String, Object> map, String key) {
        if (!(map.get(key) instanceof Map<?, ?> value) || value.keySet().stream().anyMatch(k -> !(k instanceof String))) throw SimulationFailure.invalid();
        return (Map<String, Object>) value;
    }
}
