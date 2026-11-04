package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowResumeBoundary;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;
import static com.finsec.fuse.reimplementation.simulation.VirtualWorkflowService.*;
import static org.junit.jupiter.api.Assertions.*;

final class VirtualQuarantineServiceTest {
    @Test void mutableTargetCannotRetargetStoredContainmentOrItsActionReplay() {
        var f = new SimulationFixture(); UUID first = f.start();
        UUID second = f.workflows.start(new WorkflowStartBoundary.Command(ACTOR, f.id(), f.second.request())).workflowId();
        var fields = new java.util.LinkedHashMap<String, Object>();
        fields.put("workflowId", first.toString());
        var target = new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.WORKFLOW, fields);
        fields.put("workflowId", second.toString());
        UUID action = f.id();
        var created = f.quarantines.create(ACTOR, action, target, "SYNTHETIC_CONTAINMENT", "");
        assertEquals(object("workflowId", first.toString()), created.get("target"));
        assertEquals("BLOCKED", f.workflows.get(ACTOR, first).get("state"));
        assertEquals("KYC_PENDING", f.workflows.get(ACTOR, second).get("state"));
        assertThrows(UnsupportedOperationException.class, () -> target.fields().put("workflowId", second.toString()));
        var before = f.store.snapshot();
        assertThrows(com.finsec.fuse.reimplementation.persistence.ActionJournal.ActionConflictException.class,
                () -> f.quarantines.create(ACTOR, action,
                        new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.WORKFLOW, fields),
                        "SYNTHETIC_CONTAINMENT", ""));
        assertEquals(before, f.store.snapshot());
        assertEquals(true, f.quarantines.create(ACTOR, action, target, "SYNTHETIC_CONTAINMENT", "").get("replayed"));
        assertEquals(before, f.store.snapshot());
    }

    @Test void duplicateActiveContainmentAndSecondReleaseCannotRepeatStateTransitions() {
        var f = new SimulationFixture(); UUID workflow = f.start();
        UUID quarantine = UUID.fromString((String) f.quarantine(workflow).get("quarantineId"));
        var active = f.store.snapshot();
        assertThrows(SimulationFailure.class, () -> f.quarantine(workflow));
        assertEquals(active, f.store.snapshot());
        var evidence = new java.util.ArrayList<>(List.of(ID_FACT));
        var remediation = new VirtualQuarantineService.Remediation(DOCUMENT, 2, evidence, "", null, null);
        evidence.clear(); evidence.add(FOREIGN_FACT);
        assertEquals(List.of(ID_FACT), remediation.checkEvidenceIds());
        UUID releaseAction = f.id();
        f.quarantines.release(ACTOR, releaseAction, quarantine, remediation);
        var released = f.store.snapshot();
        assertEquals(true, f.quarantines.release(ACTOR, releaseAction, quarantine, remediation).get("replayed"));
        assertEquals(released, f.store.snapshot());
        assertThrows(SimulationFailure.class, () -> f.quarantines.release(ACTOR, f.id(), quarantine, remediation));
        assertEquals(released, f.store.snapshot());
    }

    @Test void targetIsClosedAndVersionsAreStrictIntegers() {
        assertThrows(SimulationFailure.class, () -> new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.RUN,
                object("runId", DOCUMENT.toString(), "workflowId", ACCOUNT.toString())));
        assertThrows(SimulationFailure.class, () -> new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.SOURCE_VERSION,
                object("documentId", DOCUMENT.toString(), "documentVersion", 1.0)));
    }
    @Test void sourceHoldBeforeAnyRunBlocksNewWorkflowWithoutFabricatingLineage() {
        var f = new SimulationFixture();
        var q = f.quarantines.create(ACTOR, f.id(), new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.SOURCE_VERSION,
                object("documentId", DOCUMENT.toString(), "documentVersion", 1)), "SYNTHETIC_SOURCE", "");
        UUID workflow = f.start(); var impact = f.quarantines.impact(ACTOR, UUID.fromString((String) q.get("quarantineId")));
        assertEquals("BLOCKED", f.workflows.get(ACTOR, workflow).get("state")); assertEquals(0, f.rows(RUNS)); assertEquals(0, f.rows(JOBS));
        assertEquals(List.of(workflow.toString()), impact.get("policyHeldWorkflowIds")); assertEquals(List.of(), impact.get("historicalRunIds"));
        assertNull(((Map<?, ?>) impact.get("potential")).get("totalAmountKrw"));
    }
    @Test void futureLoanAndPaymentAgentHoldsPreventCreationBeforeThoseRunsExist() {
        for (String agent : List.of("synthetic-loan", "synthetic-payment")) {
            var f = new SimulationFixture();
            f.quarantines.create(ACTOR, f.id(), new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.AGENT_VERSION,
                    object("agentId", agent, "agentVersion", 1)), "SYNTHETIC_AGENT", "");
            UUID workflow = f.start(); assertEquals("BLOCKED", f.workflows.get(ACTOR, workflow).get("state"));
            assertEquals(0, f.rows(RUNS)); assertEquals(0, f.rows(RESERVATIONS));
        }
    }
    @Test void selectedSourceVersionDoesNotAffectAnotherVersion() {
        var f = new SimulationFixture(); UUID first = f.start();
        UUID second = f.workflows.start(new WorkflowStartBoundary.Command(ACTOR, f.id(), f.second.request())).workflowId();
        f.quarantines.create(ACTOR, f.id(), new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.SOURCE_VERSION,
                object("documentId", DOCUMENT.toString(), "documentVersion", 1)), "SYNTHETIC_SOURCE", "");
        assertEquals("BLOCKED", f.workflows.get(ACTOR, first).get("state"));
        assertEquals("KYC_PENDING", f.workflows.get(ACTOR, second).get("state"));
    }
    @Test void completedVirtualPaymentRemainsImmutableAfterContainment() {
        var f = new SimulationFixture(); UUID workflow = f.ready(); f.approve(workflow); UUID reservation = f.reserve(workflow);
        f.workflows.commitPayment(ACTOR, f.id(), workflow, reservation);
        var before = f.store.snapshot().get(PAYMENTS);
        var q = f.quarantine(workflow);
        assertEquals("PAID", f.workflows.get(ACTOR, workflow).get("state")); assertEquals(before, f.store.snapshot().get(PAYMENTS));
        var impact = f.quarantines.impact(ACTOR, UUID.fromString((String) q.get("quarantineId")));
        assertEquals(true, impact.get("paidBeforeQuarantine"));
        assertEquals(1000L, ((Map<?, ?>) impact.get("actual")).get("paidAmountKrw"));
        assertEquals(0L, ((Map<?, ?>) impact.get("actual")).get("atRiskPendingAmountKrw"));
    }
    @Test void verifiedReleaseKeepsBlockedStateUntilExplicitResume() {
        var f = new SimulationFixture(); UUID workflow = f.ready();
        UUID q = UUID.fromString((String) f.quarantine(workflow).get("quarantineId"));
        f.remediationVerified.set(false);
        assertThrows(SimulationFailure.class, () -> f.release(q));
        assertEquals("BLOCKED", f.workflows.get(ACTOR, workflow).get("state"));
        f.remediationVerified.set(true); f.release(q);
        var after = f.workflows.get(ACTOR, workflow);
        assertEquals("BLOCKED", after.get("state")); assertEquals(1, after.get("generation")); assertNull(after.get("activeJob"));
        var resume = f.workflows.resume(new WorkflowResumeBoundary.Command(ACTOR, f.id(), workflow,
                new WorkflowResumeBoundary.Request(1, "synthetic explicit resume")));
        assertEquals(2, resume.generation());
        var request = f.input(workflow);
        assertEquals(2, ((Map<?, ?>) ((List<?>) request.get("documents")).get(0)).get("documentVersion"));
        assertEquals(3, f.workflows.get(ACTOR, workflow).get("usedRisk"));
    }
    @Test void releaseRequiresCheckReferencesForUnpaidWorkflowAndKnownSafeAgentIsNotInvented() {
        var f = new SimulationFixture(); UUID workflow = f.start();
        UUID q = UUID.fromString((String) f.quarantine(workflow).get("quarantineId"));
        assertThrows(SimulationFailure.class, () -> f.quarantines.release(ACTOR, f.id(), q,
                new VirtualQuarantineService.Remediation(DOCUMENT, 2, List.of(), "", null, null)));
        var agent = f.quarantines.create(ACTOR, f.id(), new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.AGENT_VERSION,
                object("agentId", "synthetic-kyc", "agentVersion", 1)), "SYNTHETIC_AGENT", "");
        var unavailable = assertThrows(SimulationFailure.class, () -> f.quarantines.release(ACTOR, f.id(),
                UUID.fromString((String) agent.get("quarantineId")), new VirtualQuarantineService.Remediation(DOCUMENT, 2, List.of(ID_FACT), "",
                        "synthetic-kyc", 2)));
        assertEquals(503, unavailable.status());
    }
    @Test void deniedPerWorkflowScopeRollsBackWholeContainmentCommand() {
        var f = new SimulationFixture(20, (actor, operation, workflow, customer) ->
                !(operation == SimulationAccess.Operation.QUARANTINE && workflow != null));
        UUID workflow = f.start(); var before = f.store.snapshot();
        assertThrows(SimulationFailure.class, () -> f.quarantine(workflow));
        assertEquals(before, f.store.snapshot()); assertEquals(0, f.rows(QUARANTINES));
    }
    @Test void oldGenerationRunHoldIsHistoricalAndDoesNotBlockIndependentCurrentGeneration() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var oldInput = f.input(workflow);
        f.workflows.observeKyc(ACTOR, f.id(), f.observation(oldInput, List.of(ID_FACT)));
        f.workflows.resume(new WorkflowResumeBoundary.Command(ACTOR, f.id(), workflow,
                new WorkflowResumeBoundary.Request(1, "synthetic next generation")));
        var q = f.quarantines.create(ACTOR, f.id(), new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.RUN,
                object("runId", oldInput.get("runId"))), "SYNTHETIC_OLD_RUN", "");
        assertEquals("KYC_PENDING", f.workflows.get(ACTOR, workflow).get("state"));
        var impact = f.quarantines.impact(ACTOR, UUID.fromString((String) q.get("quarantineId")));
        assertEquals(List.of(oldInput.get("runId")), impact.get("historicalRunIds"));
        assertEquals(List.of(), impact.get("currentAffectedWorkflowIds"));
    }

    @Test void impactRefusesAggregateWhenAffectedCustomerReadScopeIsRevoked() {
        var allowCustomerRead = new java.util.concurrent.atomic.AtomicBoolean(true);
        var f = new SimulationFixture(20, (actor, operation, workflow, customer) ->
                operation != SimulationAccess.Operation.READ || workflow == null
                        || (allowCustomerRead.get() && "synthetic-customer-1".equals(customer)));
        UUID workflow = f.ready(); UUID quarantine = UUID.fromString((String) f.quarantine(workflow).get("quarantineId"));
        var visible = f.quarantines.impact(ACTOR, quarantine);
        assertEquals(1L, ((Map<?, ?>) visible.get("actual")).get("customerCount"));
        allowCustomerRead.set(false);
        var before = f.store.snapshot();
        var denied = assertThrows(SimulationFailure.class, () -> f.quarantines.impact(ACTOR, quarantine));
        assertEquals(403, denied.status()); assertEquals(before, f.store.snapshot());
        // Broad READ still passes: denial comes from the affected workflow/customer check.
        f.access.require(ACTOR, SimulationAccess.Operation.READ, null, null);
    }

    @Test void releaseVerifierFailureRollsBackQuarantineWorkflowAndActionReceipt() {
        var f = new SimulationFixture(); UUID workflow = f.ready();
        UUID quarantine = UUID.fromString((String) f.quarantine(workflow).get("quarantineId"));
        var releases = new VirtualQuarantineService(f.store, f.catalog, f.access, f.workflows,
                (actor, target, remediation) -> { throw new IllegalStateException("synthetic dependency failure"); },
                f.clock, f::id);
        var remediation = new VirtualQuarantineService.Remediation(DOCUMENT, 2, List.of(ID_FACT), "", null, null);
        var before = f.store.snapshot(); UUID action = f.id();
        var failure = assertThrows(SimulationFailure.class, () -> releases.release(ACTOR, action, quarantine, remediation));
        assertEquals(503, failure.status()); assertEquals("DEPENDENCY_UNAVAILABLE", failure.getMessage());
        assertNull(failure.getCause()); assertEquals(before, f.store.snapshot());
        // The failed transaction must not reserve the action or leave a released hold.
        assertEquals("RELEASED", f.quarantines.release(ACTOR, action, quarantine, remediation).get("state"));
    }

    @Test void releaseReplayRechecksCurrentAffectedWorkflowCustomerAuthority() {
        var allowRelease = new java.util.concurrent.atomic.AtomicBoolean(true);
        var f = new SimulationFixture(20, (actor, operation, workflow, customer) ->
                operation != SimulationAccess.Operation.RELEASE || workflow == null
                        || (allowRelease.get() && "synthetic-customer-1".equals(customer)));
        UUID workflow = f.ready(); UUID quarantine = UUID.fromString((String) f.quarantine(workflow).get("quarantineId"));
        UUID action = f.id();
        var remediation = new VirtualQuarantineService.Remediation(DOCUMENT, 2, List.of(ID_FACT), "", null, null);
        assertEquals(false, f.quarantines.release(ACTOR, action, quarantine, remediation).get("replayed"));
        assertEquals(true, f.quarantines.release(ACTOR, action, quarantine, remediation).get("replayed"));
        var before = f.store.snapshot(); allowRelease.set(false);
        var denied = assertThrows(SimulationFailure.class, () -> f.quarantines.release(ACTOR, action, quarantine, remediation));
        assertEquals(403, denied.status()); assertEquals(before, f.store.snapshot());
        f.access.require(ACTOR, SimulationAccess.Operation.RELEASE, null, null);
    }
}
