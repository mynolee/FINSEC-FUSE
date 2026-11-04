package com.finsec.fuse.reimplementation.simulation;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static org.junit.jupiter.api.Assertions.*;

/** Prospective typed readiness is an informational capability, not a legacy HTTP grant. */
final class VirtualTypedWorkflowResumeCapabilityTest {
    @Test void oldRunHoldCanRemainActiveWhileIndependentNextGenerationReadinessIsTypedOnly() {
        var f = new VirtualGrantContinuationFixture();
        var prepared = f.prepareCurrent();
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, prepared.status());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                f.consume(1, prepared.receipt().inputSnapshotHash(), 82501).status());
        var quarantine = f.hold(new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.RUN,
                Map.of("runId", f.oldRootCommand.identity().targetRunId().toString())));
        var reads = VirtualTypedWorkflowReadProjectionTest.reader(f, f.continuationCatalog,
                (actor, operation, workflow, customer) -> true);
        var before = f.store.snapshot();
        var dto = reads.get(SimulationFixture.ACTOR, f.scope(1).workflowId());
        assertEquals(22, dto.size());
        assertEquals("BLOCKED", dto.get("state"));
        assertEquals(Boolean.TRUE, dto.get("canResume"));
        assertEquals("TYPED_READINESS_ONLY", dto.get("resumeCapability"));
        assertTrue(((List<?>) dto.get("activeQuarantines")).contains(quarantine.toString()));
        assertEquals(before, f.store.snapshot()); assertEquals(0, reads.observed.puts);
        assertEquals(1, f.workflow().get("generation")); // GET did not perform continuation.
        assertFalse(dto.containsKey("executionAuthorityGranted"));
        for (String key : List.of("documentId", "documentVersion", "typedStageAgents", "canonicalInput",
                "bindingBytes", "inputSnapshotHash", "token", "grantReceipt")) assertFalse(dto.containsKey(key));
        var page = reads.list(SimulationFixture.ACTOR, 0, 10);
        assertEquals(List.of(dto), page.get("items")); assertEquals(0, reads.observed.puts);
        assertEquals(before, f.store.snapshot());
        var advanced = f.advance(f.firstCommand());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, advanced.status());
        var next = reads.get(SimulationFixture.ACTOR, f.scope(1).workflowId());
        assertEquals(22, next.size()); assertEquals(2, next.get("generation"));
        assertEquals(Boolean.FALSE, next.get("canResume"));
        assertEquals("TYPED_READINESS_ONLY", next.get("resumeCapability"));
        assertFalse(((List<?>) next.get("activeQuarantines")).contains(quarantine.toString()));
        assertEquals("ACTIVE", f.store.snapshot().get("virtual_quarantines").get(quarantine.toString()).get("status"));
    }
}
