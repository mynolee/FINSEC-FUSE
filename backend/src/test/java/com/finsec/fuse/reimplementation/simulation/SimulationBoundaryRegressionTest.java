package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowResumeBoundary;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static org.junit.jupiter.api.Assertions.*;

final class SimulationBoundaryRegressionTest {
    @Test void unsafeSourceCannotQueueAnUnusableResumeJob() {
        var f = new SimulationFixture();
        var unsafe = new SimulationSpec.Source(DOCUMENT, 1, "synthetic unreviewed source",
                SimulationSpec.rawHash("synthetic unreviewed source"), false);
        var app = new SimulationSpec.Application("synthetic-unreviewed", "synthetic-unreviewed-ref", "synthetic-customer-1",
                1000L, ACCOUNT, 5000L, 10000L, true, unsafe);
        var service = new VirtualWorkflowService(f.store, new SimulationSpec.Catalog(List.of(app), List.of()),
                new SimulationSpec.RiskTerms("SYNTHETIC-POLICY-1", 1, 2, 3, 20, 5, 2, Duration.ofMinutes(5)),
                f.access, f.clock, f::id);
        UUID workflow = service.start(new WorkflowStartBoundary.Command(ACTOR, f.id(), app.request())).workflowId();
        var result = service.resume(new WorkflowResumeBoundary.Command(ACTOR, f.id(), workflow,
                new WorkflowResumeBoundary.Request(1, "synthetic unchanged source")));
        assertEquals("DENY", result.decision().name()); assertEquals(1, result.generation());
        assertEquals(false, service.get(ACTOR, workflow).get("canResume")); assertEquals(0, f.rows(VirtualWorkflowService.JOBS));
    }
    @Test void evidenceExpiryDisablesApprovalPreviewAndDisplayedAction() {
        var f = new SimulationFixture(); UUID workflow = f.ready(); f.clock.advance(Duration.ofHours(2));
        assertEquals(false, f.workflows.get(ACTOR, workflow).get("canApprove"));
        assertThrows(SimulationFailure.class, () -> f.workflows.approvalPreview(ACTOR, workflow));
    }
    @Test void laterPaymentIsNotLabeledAsExistingBeforeQuarantine() {
        var f = new SimulationFixture(); UUID workflow = f.start();
        UUID quarantine = UUID.fromString((String) f.quarantine(workflow).get("quarantineId"));
        f.release(quarantine);
        f.workflows.resume(new WorkflowResumeBoundary.Command(ACTOR, f.id(), workflow,
                new WorkflowResumeBoundary.Request(1, "synthetic recovery")));
        f.workflows.observeKyc(ACTOR, f.id(), f.observation(f.input(workflow), List.of(ID_FACT, FACE_FACT)));
        f.approve(workflow); UUID reservation = f.reserve(workflow); f.workflows.commitPayment(ACTOR, f.id(), workflow, reservation);
        var impact = f.quarantines.impact(ACTOR, quarantine);
        assertEquals(false, impact.get("paidBeforeQuarantine")); assertEquals(List.of(), impact.get("currentAffectedWorkflowIds"));
        assertEquals(1000L, ((Map<?, ?>) impact.get("actual")).get("paidAmountKrw"));
    }
    @Test void replayOfContainmentAlsoRequiresCurrentPerWorkflowAuthority() {
        var allowScope = new java.util.concurrent.atomic.AtomicBoolean(true);
        var f = new SimulationFixture(20, (actor, operation, workflow, customer) ->
                operation != SimulationAccess.Operation.QUARANTINE || workflow == null || allowScope.get());
        UUID workflow = f.start(), action = f.id();
        var target = new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.WORKFLOW,
                SimulationSpec.object("workflowId", workflow.toString()));
        f.quarantines.create(ACTOR, action, target, "SYNTHETIC_SCOPE", "");
        allowScope.set(false);
        assertEquals(403, assertThrows(SimulationFailure.class, () ->
                f.quarantines.create(ACTOR, action, target, "SYNTHETIC_SCOPE", "")).status());
        assertEquals(1, f.rows(VirtualWorkflowService.QUARANTINES));
    }
}
