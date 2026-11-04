package com.finsec.fuse.reimplementation.simulation;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;
import static org.junit.jupiter.api.Assertions.*;

final class VirtualAgentBridgeTest {
    private Map<String, Object> response(Map<String, Object> input) {
        return object("requestId", input.get("requestId"), "workflowId", input.get("workflowId"), "generation", input.get("generation"),
                "runId", input.get("runId"), "inputSnapshotHash", input.get("inputSnapshotHash"),
                "proposal", object("status", "VERIFIED", "evidenceIds", List.of(ID_FACT.toString(), FACE_FACT.toString()),
                        "explanation", "synthetic model text is not authority"),
                "modelMetadata", object("model", "synthetic-model", "promptVersion", "KYC-PROMPT-1"));
    }
    @Test void publicAgentShapeConnectsToAuthoritativeVirtualChecksWithoutLeakingModelText() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var bridge = new VirtualAgentBridge(f.workflows);
        var input = f.input(workflow);
        assertEquals("WAIT_APPROVAL", bridge.accept(ACTOR, f.id(), response(input)).get("state"));
        String trace = f.workflows.trace(ACTOR, workflow).toString();
        assertFalse(trace.contains("synthetic model text")); assertFalse(trace.contains("synthetic-model")); assertFalse(trace.contains("synthetic source 한글"));
    }
    @Test void unknownResponseFieldsOrWrongProtocolVersionCannotReachResults() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var bridge = new VirtualAgentBridge(f.workflows);
        var input = f.input(workflow); var raw = new LinkedHashMap<>(response(input)); raw.put("allowPayment", true);
        assertThrows(SimulationFailure.class, () -> bridge.accept(ACTOR, f.id(), raw));
        var wrong = new LinkedHashMap<>(response(input));
        wrong.put("modelMetadata", object("model", "synthetic-model", "promptVersion", "UNREGISTERED"));
        assertThrows(SimulationFailure.class, () -> bridge.accept(ACTOR, f.id(), wrong));
        assertEquals(0, f.rows(VirtualWorkflowService.RESULTS));
    }
}
