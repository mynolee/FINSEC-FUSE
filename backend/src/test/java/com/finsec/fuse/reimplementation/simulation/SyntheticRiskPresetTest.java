package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowResumeBoundary;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static com.finsec.fuse.reimplementation.simulation.VirtualWorkflowService.*;
import static org.junit.jupiter.api.Assertions.*;

/** New synthetic contract cases, not historical policy recovery or measured execution results. */
final class SyntheticRiskPresetTest {
    private SimulationFixture demo() {
        return new SimulationFixture(SyntheticRiskPresets.demonstrationV2(), null);
    }

    @Test void explicitPresetHasExactValuesAndLegacyFixtureRemainsTwentyPlusFive() {
        var terms = SyntheticRiskPresets.demonstrationV2();
        assertEquals("SYNTHETIC-DEMO-2", terms.policyVersion());
        assertEquals(1, terms.kycPoints()); assertEquals(2, terms.loanPoints()); assertEquals(3, terms.payPoints());
        assertEquals(3, terms.baseLimit()); assertEquals(3, terms.additionalApprovalLimit());
        assertEquals(2, terms.maxAutomaticKycRuns()); assertEquals(Duration.ofMinutes(5), terms.approvalLifetime());
        var f = new SimulationFixture(); UUID workflow = f.ready();
        assertEquals(20, f.workflows.get(ACTOR, workflow).get("riskLimit"));
        var approval = f.approve(workflow);
        assertEquals(5, approval.get("extraRiskLimit")); assertEquals(25, approval.get("riskLimit"));
        var inputFixture = new SimulationFixture();
        assertEquals("SYNTHETIC-POLICY-1", inputFixture.input(inputFixture.start()).get("policyVersion"));
    }

    @Test void baseBudgetReachesReviewAndHumanApprovalFundsOnePaymentOnly() {
        var f = demo(); UUID workflow = f.ready();
        var row = f.workflows.get(ACTOR, workflow);
        assertEquals("WAIT_APPROVAL", row.get("state"));
        assertEquals(3, row.get("usedRisk")); assertEquals(3, row.get("riskLimit"));
        assertEquals(0, f.rows(APPROVALS)); assertEquals(0, f.rows(PAYMENTS));
        var approval = f.approve(workflow);
        assertEquals(3, approval.get("extraRiskLimit")); assertEquals(6, approval.get("riskLimit"));
        UUID reservation = f.reserve(workflow), action = f.id();
        assertEquals(3, f.workflows.get(ACTOR, workflow).get("reservedRisk"));
        assertEquals("PAID", f.workflows.commitPayment(ACTOR, action, workflow, reservation).get("state"));
        assertEquals(true, f.workflows.commitPayment(ACTOR, action, workflow, reservation).get("replayed"));
        assertEquals(1, f.rows(PAYMENTS));
        assertEquals(6, f.workflows.get(ACTOR, workflow).get("usedRisk"));
        assertEquals(0, f.workflows.get(ACTOR, workflow).get("reservedRisk"));
    }

    @Test void approvalLifetimeStartsAtCreationAndPaymentWorksImmediatelyBeforeExpiry() {
        var f = demo(); UUID workflow = f.ready();
        f.clock.advance(Duration.ofMinutes(7));
        Instant created = f.clock.instant(); var receipt = f.approve(workflow);
        var approval = f.store.snapshot().get(APPROVALS).get((String) receipt.get("approvalId"));
        assertEquals(created.toString(), approval.get("createdAt"));
        assertEquals(created.plus(Duration.ofMinutes(5)).toString(), approval.get("expiresAt"));
        f.clock.advance(Duration.ofMinutes(5).minusNanos(1));
        UUID reservation = f.reserve(workflow);
        assertEquals("PAID", f.workflows.commitPayment(ACTOR, f.id(), workflow, reservation).get("state"));
        assertEquals(1, f.rows(PAYMENTS));
    }

    @Test void exactExpiryReleasesReservationWithoutConsumingPaymentBudget() {
        var f = demo(); UUID workflow = f.ready(); f.approve(workflow);
        UUID reservation = f.reserve(workflow); f.clock.advance(Duration.ofMinutes(5));
        assertEquals("DENY", f.workflows.commitPayment(ACTOR, f.id(), workflow, reservation).get("decision"));
        assertEquals(0, f.rows(PAYMENTS));
        assertEquals(3, f.workflows.get(ACTOR, workflow).get("usedRisk"));
        assertEquals(0, f.workflows.get(ACTOR, workflow).get("reservedRisk"));
        assertEquals("RELEASED", f.store.snapshot().get(RESERVATIONS).get(reservation.toString()).get("status"));
    }

    @Test void presetDoesNotBypassReviewAuthorityAndRejectionAddsNoBudget() {
        var f = demo(); UUID workflow = f.ready();
        String snapshot = (String) f.workflows.approvalPreview(ACTOR, workflow).get("reviewSnapshotHash");
        var before = f.store.snapshot(); f.permitted.set(false);
        assertEquals(403, assertThrows(SimulationFailure.class, () ->
                f.workflows.approve(ACTOR, f.id(), workflow, true, snapshot, "synthetic denied")).status());
        assertEquals(before, f.store.snapshot());
        f.permitted.set(true);
        var receipt = f.workflows.approve(ACTOR, f.id(), workflow, false, snapshot, "synthetic rejected");
        assertEquals("REJECTED", receipt.get("state")); assertEquals(3, receipt.get("riskLimit"));
        assertEquals(0, receipt.get("extraRiskLimit")); assertNull(receipt.get("payJobId"));
        assertEquals(0, f.rows(PAYMENTS));
    }

    @Test void resumePreservesFirstChargeAndCapsThirdAutomaticKycUnderDemo() {
        var f = demo(); UUID workflow = f.start();
        f.workflows.observeKyc(ACTOR, f.id(), f.observation(f.input(workflow), List.of(ID_FACT)));
        var resumed = f.workflows.resume(new WorkflowResumeBoundary.Command(ACTOR, f.id(), workflow,
                new WorkflowResumeBoundary.Request(1, "synthetic retry")));
        assertEquals(2, resumed.generation());
        f.workflows.observeKyc(ACTOR, f.id(), f.observation(f.input(workflow), List.of(ID_FACT)));
        var denied = f.workflows.resume(new WorkflowResumeBoundary.Command(ACTOR, f.id(), workflow,
                new WorkflowResumeBoundary.Request(2, "synthetic third retry")));
        assertEquals("ON_HOLD", denied.state().name()); assertEquals(2, denied.generation());
        assertEquals(2, f.workflows.get(ACTOR, workflow).get("kycRuns"));
        assertEquals(1, f.workflows.get(ACTOR, workflow).get("usedRisk")); assertEquals(0, f.rows(PAYMENTS));
    }
}
