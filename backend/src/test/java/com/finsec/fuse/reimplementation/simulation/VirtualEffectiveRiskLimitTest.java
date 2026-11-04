package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowResumeBoundary;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static com.finsec.fuse.reimplementation.simulation.VirtualWorkflowService.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * New regressions for preserved UI semantics: current effective limit differs
 * from the immutable historical approval used by an already completed payment.
 * Values 20/5 are explicit existing synthetic terms, not recovered policy defaults.
 */
final class VirtualEffectiveRiskLimitTest {
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> approvals(SimulationFixture f, UUID workflow) {
        return (List<Map<String, Object>>) f.workflows.trace(ACTOR, workflow).get("approvals");
    }

    @Test void persistedApprovalRecordsItsOwnAmountLimitExtraAndCreationTime() {
        var f = new SimulationFixture(); UUID workflow = f.ready();
        assertEquals(20, f.workflows.get(ACTOR, workflow).get("riskLimit"));
        var receipt = f.approve(workflow);
        assertEquals(25, receipt.get("riskLimit")); assertEquals(25, f.workflows.get(ACTOR, workflow).get("riskLimit"));
        var saved = approvals(f, workflow).get(0);
        assertEquals(1000L, saved.get("amountKrw")); assertEquals(25, saved.get("riskLimit"));
        assertEquals(5, saved.get("extraRisk")); assertEquals(f.clock.instant().toString(), saved.get("createdAt"));
        assertEquals(receipt.get("approvalId"), saved.get("approvalId"));
    }

    @Test void acceptedRejectionDoesNotCreateAnEffectiveAdditionalLimit() {
        var f = new SimulationFixture(); UUID workflow = f.ready();
        var rejected = f.workflows.approve(ACTOR, f.id(), workflow, false,
                (String) f.workflows.approvalPreview(ACTOR, workflow).get("reviewSnapshotHash"), "");
        assertEquals("ALLOW", rejected.get("decision")); assertEquals("REJECTED", rejected.get("state"));
        assertEquals(20, rejected.get("riskLimit")); assertEquals(20, f.workflows.get(ACTOR, workflow).get("riskLimit"));
        var history = approvals(f, workflow).get(0);
        assertEquals(20, history.get("riskLimit")); assertEquals(0, history.get("extraRisk"));
    }

    @Test void expiryRecalculatesCurrentLimitWithoutRewritingRecordedApproval() {
        var f = new SimulationFixture(); UUID workflow = f.ready(); f.approve(workflow);
        var original = approvals(f, workflow).get(0);
        f.clock.advance(Duration.ofMinutes(6));
        assertEquals(20, f.workflows.get(ACTOR, workflow).get("riskLimit"));
        var afterRead = approvals(f, workflow).get(0);
        assertEquals(25, afterRead.get("riskLimit")); assertEquals(original.get("createdAt"), afterRead.get("createdAt"));
        assertEquals(original.get("expiresAt"), afterRead.get("expiresAt")); assertEquals(original.get("amountKrw"), afterRead.get("amountKrw"));
        assertEquals(0, f.rows(PAYMENTS));
    }

    @Test void paidWorkflowSeparatesHistoricalLimitFromCurrentAuthority() {
        var f = new SimulationFixture(); UUID workflow = f.ready(); f.approve(workflow);
        UUID reservation = f.reserve(workflow); f.workflows.commitPayment(ACTOR, f.id(), workflow, reservation);
        var current = f.workflows.get(ACTOR, workflow);
        assertEquals("PAID", current.get("state")); assertEquals(20, current.get("riskLimit"));
        assertEquals(25, current.get("historicalApprovedRiskLimit"));
        var history = approvals(f, workflow).get(0);
        assertEquals("CONSUMED", history.get("status")); assertEquals(25, history.get("riskLimit"));
        assertEquals(1000L, history.get("amountKrw")); assertEquals(5, history.get("extraRisk"));
    }

    @Test void revocationAndExplicitResumeDoNotCarryPreviousAdditionalLimitIntoNewKyc() {
        var f = new SimulationFixture(); UUID workflow = f.ready(); f.approve(workflow);
        UUID incident = UUID.fromString((String) f.quarantine(workflow).get("quarantineId"));
        assertEquals(20, f.workflows.get(ACTOR, workflow).get("riskLimit"));
        f.release(incident);
        var resume = f.workflows.resume(new WorkflowResumeBoundary.Command(ACTOR, f.id(), workflow,
                new WorkflowResumeBoundary.Request(1, "synthetic explicit recovery")));
        assertEquals(2, resume.generation());
        var current = f.workflows.get(ACTOR, workflow);
        assertEquals(20, current.get("riskLimit")); assertEquals(3, current.get("usedRisk"));
        assertEquals(25, approvals(f, workflow).get(0).get("riskLimit"));
    }

    @Test void approvalWithBrokenCurrentBindingDoesNotIncreaseDisplayedLimit() {
        var f = new SimulationFixture(); UUID workflow = f.ready();
        UUID approval = UUID.fromString((String) f.approve(workflow).get("approvalId"));
        f.store.transaction(tx -> {
            var corrupted = new LinkedHashMap<>(tx.get(APPROVALS, approval.toString()));
            corrupted.put("payoutAccountId", new UUID(9, 9).toString());
            tx.put(APPROVALS, approval.toString(), corrupted);
            return null;
        });
        assertEquals(20, f.workflows.get(ACTOR, workflow).get("riskLimit"));
        assertEquals(25, approvals(f, workflow).get(0).get("riskLimit"));
    }

    @Test void historicalPaidLimitComesFromPaymentBoundApprovalRatherThanAnUnrelatedLaterRow() {
        var f = new SimulationFixture(); UUID workflow = f.ready(); f.approve(workflow);
        UUID reservation = f.reserve(workflow); f.workflows.commitPayment(ACTOR, f.id(), workflow, reservation);
        var real = approvals(f, workflow).get(0); UUID unrelated = f.id();
        f.store.transaction(tx -> {
            var other = new LinkedHashMap<>(real); other.put("approvalId", unrelated.toString());
            other.put("riskLimit", 999); other.put("riskLimitAfterApproval", 999);
            tx.put(APPROVALS, unrelated.toString(), other); return null;
        });
        assertEquals(25, f.workflows.get(ACTOR, workflow).get("historicalApprovedRiskLimit"));
        assertEquals(20, f.workflows.get(ACTOR, workflow).get("riskLimit"));
    }
}
