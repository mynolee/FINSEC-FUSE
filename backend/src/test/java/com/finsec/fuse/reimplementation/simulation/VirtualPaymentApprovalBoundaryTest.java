package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static com.finsec.fuse.reimplementation.simulation.VirtualWorkflowService.*;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic actor, subject and payment replay boundaries; no real authority or money. */
final class VirtualPaymentApprovalBoundaryTest {
    @Test void approvalActionCannotBeReusedByAnotherActorOrChangedDecision() {
        var f = new SimulationFixture(); UUID workflow = f.ready(), action = f.id();
        String snapshot = (String) f.workflows.approvalPreview(ACTOR, workflow).get("reviewSnapshotHash");
        f.workflows.approve(ACTOR, action, workflow, true, snapshot, "synthetic review");
        var before = f.store.snapshot();
        var otherActor = new WorkflowStartBoundary.ActorRef("synthetic-second-reviewer");
        assertThrows(ActionJournal.ActionConflictException.class, () ->
                f.workflows.approve(otherActor, action, workflow, true, snapshot, "synthetic review"));
        assertThrows(ActionJournal.ActionConflictException.class, () ->
                f.workflows.approve(ACTOR, action, workflow, false, snapshot, "synthetic review"));
        assertEquals(before, f.store.snapshot());
        assertEquals(1, f.rows(APPROVALS));
    }

    @Test void foreignWorkflowReservationCannotConsumeEitherApproval() {
        var f = new SimulationFixture(); UUID first = f.ready(); f.approve(first);
        UUID reservation = f.reserve(first);
        UUID second = f.workflows.start(new WorkflowStartBoundary.Command(ACTOR, f.id(), f.second.request())).workflowId();
        f.workflows.observeKyc(ACTOR, f.id(), f.observation(f.input(second), List.of(ID_FACT, FACE_FACT)));
        f.approve(second); f.reserve(second);
        var before = f.store.snapshot();
        assertThrows(SimulationFailure.class, () ->
                f.workflows.commitPayment(ACTOR, f.id(), second, reservation));
        assertEquals(before, f.store.snapshot());
        assertEquals(0, f.rows(PAYMENTS));
    }

    @Test void oldGenerationReservationCannotCancelNewWorkOrPoisonItsCommitAction() {
        for (boolean reserveCurrentFirst : new boolean[] {false, true}) {
            var f = new SimulationFixture(); UUID workflow = f.ready(); f.approve(workflow);
            UUID oldReservation = f.reserve(workflow);
            UUID hold = UUID.fromString((String) f.quarantine(workflow).get("quarantineId"));
            f.release(hold);
            f.workflows.resume(new com.finsec.fuse.reimplementation.WorkflowResumeBoundary.Command(
                    ACTOR, f.id(), workflow,
                    new com.finsec.fuse.reimplementation.WorkflowResumeBoundary.Request(1, "synthetic independent remediation")));
            UUID currentReservation = null;
            if (reserveCurrentFirst) {
                f.workflows.observeKyc(ACTOR, f.id(), f.observation(f.input(workflow), List.of(ID_FACT, FACE_FACT)));
                f.approve(workflow); currentReservation = f.reserve(workflow);
            }
            assertEquals(2, f.workflows.get(ACTOR, workflow).get("generation"));
            assertEquals(reserveCurrentFirst ? "PAYMENT_RESERVED" : "KYC_PENDING",
                    f.workflows.get(ACTOR, workflow).get("state"));
            UUID action = f.id();
            var before = f.store.snapshot();
            var stale = assertThrows(SimulationFailure.class,
                    () -> f.workflows.commitPayment(ACTOR, action, workflow, oldReservation));
            assertEquals(400, stale.status());
            // Includes workflow/job/approval/risk and journal; stale input cannot cancel or cache a denial.
            assertEquals(before, f.store.snapshot());
            assertEquals(0, f.rows(PAYMENTS));
            assertEquals("RELEASED", f.store.snapshot().get(RESERVATIONS)
                    .get(oldReservation.toString()).get("status"));
            if (!reserveCurrentFirst) {
                f.workflows.observeKyc(ACTOR, f.id(), f.observation(f.input(workflow), List.of(ID_FACT, FACE_FACT)));
                f.approve(workflow); currentReservation = f.reserve(workflow);
            }
            var committed = f.workflows.commitPayment(ACTOR, action, workflow, currentReservation);
            assertEquals("PAID", committed.get("state")); assertEquals("ALLOW", committed.get("decision"));
            assertEquals(1, f.rows(PAYMENTS));
            assertEquals("COMMITTED", f.store.snapshot().get(RESERVATIONS)
                    .get(currentReservation.toString()).get("status"));
            long consumed = f.store.snapshot().get(RISK).values().stream()
                    .filter(row -> "CONSUME".equals(row.get("eventType"))).count();
            assertEquals(1L, consumed);
        }
    }

    @Test void changedPaymentSubjectAfterReservationCannotBePaid() {
        for (String field : List.of("customerId", "amountKrw", "payoutAccountId")) {
            var f = new SimulationFixture(); UUID workflow = f.ready(); f.approve(workflow);
            UUID reservation = f.reserve(workflow);
            f.store.transaction(tx -> {
                var changed = new LinkedHashMap<>(tx.get(WORKFLOWS, workflow.toString()));
                Object replacement = switch (field) {
                    case "customerId" -> "synthetic-changed-customer";
                    case "amountKrw" -> 2000L;
                    case "payoutAccountId" -> new UUID(9, 9).toString();
                    default -> throw new AssertionError();
                };
                changed.put(field, replacement); tx.put(WORKFLOWS, workflow.toString(), changed);
                return null;
            });
            var denied = f.workflows.commitPayment(ACTOR, f.id(), workflow, reservation);
            assertEquals("DENY", denied.get("decision"));
            assertEquals(0, f.rows(PAYMENTS));
            assertEquals("RELEASED", f.store.snapshot().get(RESERVATIONS).get(reservation.toString()).get("status"));
            assertEquals(0, f.workflows.get(ACTOR, workflow).get("reservedRisk"));
        }
    }

    @Test void cachedCommitStillRequiresCurrentAuthorityAndCannotPayTwice() {
        var f = new SimulationFixture(); UUID workflow = f.ready(); f.approve(workflow);
        UUID reservation = f.reserve(workflow), action = f.id();
        var committed = f.workflows.commitPayment(ACTOR, action, workflow, reservation);
        var beforeReplay = f.store.snapshot();
        assertEquals(true, f.workflows.commitPayment(ACTOR, action, workflow, reservation).get("replayed"));
        assertEquals(beforeReplay, f.store.snapshot());
        f.permitted.set(false);
        var denied = assertThrows(SimulationFailure.class, () ->
                f.workflows.commitPayment(ACTOR, action, workflow, reservation));
        assertEquals(403, denied.status());
        assertEquals(beforeReplay, f.store.snapshot());
        f.permitted.set(true);
        var secondAction = f.workflows.commitPayment(ACTOR, f.id(), workflow, reservation);
        assertEquals("DENY", secondAction.get("decision"));
        assertEquals(1, f.rows(PAYMENTS));
        assertEquals(committed.get("paymentId"), f.store.snapshot().get(PAYMENTS).values().iterator().next().get("paymentId"));
        long consumed = f.store.snapshot().get(RISK).values().stream()
                .filter(row -> "CONSUME".equals(row.get("eventType"))).count();
        assertEquals(1L, consumed);
    }
}
