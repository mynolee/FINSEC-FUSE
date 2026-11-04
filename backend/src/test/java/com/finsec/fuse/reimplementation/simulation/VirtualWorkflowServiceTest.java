package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowResumeBoundary;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;
import static com.finsec.fuse.reimplementation.simulation.VirtualWorkflowService.*;
import static org.junit.jupiter.api.Assertions.*;

final class VirtualWorkflowServiceTest {
    @Test void sameStartReplaysOneWorkflowAndOneJob() {
        var f = new SimulationFixture(); UUID action = f.id();
        var command = new WorkflowStartBoundary.Command(ACTOR, action, f.app.request());
        var first = f.workflows.start(command); var replay = f.workflows.start(command);
        assertEquals(first.workflowId(), replay.workflowId()); assertFalse(first.replayed()); assertTrue(replay.replayed());
        assertEquals(1, f.rows(WORKFLOWS)); assertEquals(1, f.rows(JOBS));
        assertThrows(ActionJournal.ActionConflictException.class, () -> f.workflows.start(
                new WorkflowStartBoundary.Command(ACTOR, action, f.second.request())));
    }
    @Test void startBoundaryCannotCreateWhenAuthorityChangesAfterPrecheck() {
        var calls = new java.util.concurrent.atomic.AtomicInteger();
        var f = new SimulationFixture(20, (actor, operation, workflow, customer) ->
                operation != SimulationAccess.Operation.START || calls.incrementAndGet() == 1);
        var boundary = new WorkflowStartBoundary(command -> {
            var result = f.workflows.start(command);
            return new WorkflowStartBoundary.Result(result.requestId(), result.workflowId(), result.generation(),
                    result.state().name(), result.decision().name(), result.reasonCodes(), result.message(), result.replayed());
        });
        var before = f.store.snapshot();
        var denied = assertThrows(SimulationFailure.class,
                () -> boundary.start(ACTOR, f.id(), f.app.request()));
        assertEquals(403, denied.status());
        assertEquals(2, calls.get());
        assertEquals(before, f.store.snapshot());
        assertEquals(0, f.rows(WORKFLOWS)); assertEquals(0, f.rows(JOBS));
    }

    @Test void resumeBoundaryDoesNotInheritRunOrResultHoldAlreadyActiveBeforeResume() {
        for (var scope : List.of(VirtualQuarantineService.Scope.RUN, VirtualQuarantineService.Scope.RESULT)) {
            var f = new SimulationFixture(); UUID workflow = f.ready();
            var oldResult = f.store.snapshot().get(RESULTS).values().stream()
                    .filter(row -> "KYC".equals(row.get("role"))).findFirst().orElseThrow();
            Map<String, Object> target = scope == VirtualQuarantineService.Scope.RUN
                    ? object("runId", oldResult.get("runId")) : object("resultId", oldResult.get("resultId"));
            f.quarantines.create(ACTOR, f.id(), new VirtualQuarantineService.Target(scope, target),
                    "SYNTHETIC_PRIOR_GENERATION", "");
            assertEquals("BLOCKED", f.workflows.get(ACTOR, workflow).get("state"));
            assertEquals(true, f.workflows.get(ACTOR, workflow).get("canResume"));
            var boundary = new WorkflowResumeBoundary(command -> {
                var result = f.workflows.resume(command);
                return new WorkflowStartBoundary.Result(result.requestId(), result.workflowId(), result.generation(),
                        result.state().name(), result.decision().name(), result.reasonCodes(), result.message(), result.replayed());
            });
            UUID action = f.id();
            var resumed = boundary.resume(ACTOR, action, workflow,
                    new WorkflowResumeBoundary.Request(1, "synthetic independent resume"));
            assertEquals(action, resumed.requestId()); assertEquals(workflow, resumed.workflowId());
            assertEquals(2, resumed.generation()); assertEquals("KYC_PENDING", resumed.state());
            assertEquals("ALLOW", resumed.decision());
            assertEquals(3, f.workflows.get(ACTOR, workflow).get("usedRisk"));
            assertEquals(1, f.workflows.get(ACTOR, workflow).get("kycRuns"));
            var fresh = f.input(workflow);
            assertEquals(2, fresh.get("generation")); assertNotEquals(oldResult.get("runId"), fresh.get("runId"));
            assertEquals(0, f.rows(APPROVALS)); assertEquals(0, f.rows(PAYMENTS));
        }
    }

    @Test void replayRechecksCurrentAuthority() {
        var f = new SimulationFixture(); UUID workflow = f.ready(), action = f.id();
        String snapshot = (String) f.workflows.approvalPreview(ACTOR, workflow).get("reviewSnapshotHash");
        f.workflows.approve(ACTOR, action, workflow, true, snapshot, "");
        f.permitted.set(false);
        var denied = assertThrows(SimulationFailure.class, () -> f.workflows.approve(ACTOR, action, workflow, true, snapshot, ""));
        assertEquals(403, denied.status()); assertEquals(1, f.rows(APPROVALS));
    }
    @Test void kycInputPreservesPythonDtoOrderAndRawUnicodeHash() {
        var f = new SimulationFixture(); var input = f.input(f.start());
        assertEquals(List.of("requestId", "workflowId", "generation", "runId", "customerId", "policyVersion",
                "inputSnapshotHash", "evidenceFacts", "documents"), List.copyOf(input.keySet()));
        var canonical = new LinkedHashMap<String, Object>(input); canonical.remove("inputSnapshotHash");
        assertEquals(CanonicalJson.orderedSha256(canonical), input.get("inputSnapshotHash"));
        String encoded = CanonicalJson.orderedWrite(canonical);
        assertTrue(encoded.contains("synthetic source 한글")); assertTrue(encoded.contains("\"generation\":1"));
        assertEquals(SimulationSpec.rawHash(encoded), input.get("inputSnapshotHash"));
    }
    @Test void mismatchedObservationRollsBackAndValidObservationStillWorks() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var input = f.input(workflow);
        var good = f.observation(input, List.of(ID_FACT, FACE_FACT));
        var bad = new SimulationSpec.Observation(good.requestId(), good.workflowId(), good.generation(), good.runId(),
                "0".repeat(64), good.status(), good.evidenceIds());
        int before = f.rows(AUDIT);
        assertThrows(SimulationFailure.class, () -> f.workflows.observeKyc(ACTOR, f.id(), bad));
        assertEquals(0, f.rows(RESULTS)); assertEquals(before, f.rows(AUDIT));
        assertEquals("WAIT_APPROVAL", f.workflows.observeKyc(ACTOR, f.id(), good).get("state"));
    }
    @Test void modelVerifiedWithoutBothTrustedKindsCannotApprove() {
        var f = new SimulationFixture(); UUID workflow = f.start();
        assertEquals("BLOCKED", f.workflows.observeKyc(ACTOR, f.id(),
                f.observation(f.input(workflow), List.of(ID_FACT))).get("state"));
        assertEquals(0, f.rows(APPROVALS)); assertEquals(0, f.rows(RESULTS));
    }
    @Test void foreignOrExpiredEvidenceCannotBecomeAuthoritative() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var input = f.input(workflow);
        assertEquals("BLOCKED", f.workflows.observeKyc(ACTOR, f.id(),
                f.observation(input, List.of(ID_FACT, FOREIGN_FACT))).get("state"));
        var expired = new SimulationFixture(); UUID other = expired.start(); var captured = expired.input(other);
        expired.clock.advance(Duration.ofHours(2));
        assertEquals("BLOCKED", expired.workflows.observeKyc(ACTOR, expired.id(),
                expired.observation(captured, List.of(ID_FACT, FACE_FACT))).get("state"));
    }
    @Test void observationReplayCreatesOneImmutableResultPerRun() {
        var f = new SimulationFixture(); UUID workflow = f.start(), action = f.id(); var observation = f.observation(f.input(workflow), List.of(ID_FACT, FACE_FACT));
        f.workflows.observeKyc(ACTOR, action, observation);
        assertEquals(true, f.workflows.observeKyc(ACTOR, action, observation).get("replayed"));
        assertEquals(2, f.rows(RESULTS)); assertEquals(2, f.rows(RUNS));
        var late = f.workflows.observeKyc(ACTOR, f.id(), observation);
        assertEquals(List.of("LATE_RESULT_DISCARDED"), late.get("reasonCodes")); assertEquals(2, f.rows(RESULTS));
    }
    @Test void staleSnapshotCannotApproveAndAcceptedRejectionKeepsRiskCap() {
        var f = new SimulationFixture(); UUID workflow = f.ready();
        assertThrows(SimulationFailure.class, () -> f.workflows.approve(ACTOR, f.id(), workflow, true, "0".repeat(64), ""));
        String snapshot = (String) f.workflows.approvalPreview(ACTOR, workflow).get("reviewSnapshotHash");
        var receipt = f.workflows.approve(ACTOR, f.id(), workflow, false, snapshot, "");
        assertEquals("ALLOW", receipt.get("decision")); assertEquals("REJECTED", receipt.get("state")); assertNull(receipt.get("payJobId"));
        assertEquals(0, receipt.get("extraRiskLimit")); assertEquals(20, receipt.get("riskLimit"));
    }
    @Test void paymentReservationAndCommitAreSeparateAndReplayCommitsOnce() {
        var f = new SimulationFixture(); UUID workflow = f.ready(); f.approve(workflow); UUID reservation = f.reserve(workflow);
        assertEquals(0, f.rows(PAYMENTS)); assertEquals(3, f.workflows.get(ACTOR, workflow).get("reservedRisk"));
        UUID action = f.id(); var first = f.workflows.commitPayment(ACTOR, action, workflow, reservation);
        var second = f.workflows.commitPayment(ACTOR, action, workflow, reservation);
        assertEquals("PAID", first.get("state")); assertEquals(true, second.get("replayed")); assertEquals(1, f.rows(PAYMENTS));
        var row = f.workflows.get(ACTOR, workflow); assertEquals(6, row.get("usedRisk")); assertEquals(0, row.get("reservedRisk"));
    }
    @Test void containmentBetweenReservationAndCommitReleasesRiskAndBlocksPayment() {
        var f = new SimulationFixture(); UUID workflow = f.ready(); f.approve(workflow); UUID reservation = f.reserve(workflow);
        f.quarantine(workflow);
        var blocked = f.workflows.commitPayment(ACTOR, f.id(), workflow, reservation);
        assertEquals("DENY", blocked.get("decision")); assertEquals(0, f.rows(PAYMENTS));
        assertEquals(0, f.workflows.get(ACTOR, workflow).get("reservedRisk"));
        assertEquals("RELEASED", f.store.snapshot().get(RESERVATIONS).get(reservation.toString()).get("status"));
    }
    @Test void expiryAfterReservationReleasesRiskRatherThanPaying() {
        var f = new SimulationFixture(); UUID workflow = f.ready(); f.approve(workflow); UUID reservation = f.reserve(workflow);
        f.clock.advance(Duration.ofMinutes(6));
        assertEquals("DENY", f.workflows.commitPayment(ACTOR, f.id(), workflow, reservation).get("decision"));
        assertEquals(0, f.rows(PAYMENTS)); assertEquals(0, f.workflows.get(ACTOR, workflow).get("reservedRisk"));
    }
    @Test void invalidResumeCannotRewriteRejectionOrStrandAnActiveReservation() {
        var f = new SimulationFixture(); UUID workflow = f.ready();
        f.workflows.approve(ACTOR, f.id(), workflow, false,
                (String) f.workflows.approvalPreview(ACTOR, workflow).get("reviewSnapshotHash"), "");
        var before = f.store.snapshot();
        assertThrows(SimulationFailure.class, () -> f.workflows.resume(new WorkflowResumeBoundary.Command(ACTOR, f.id(), workflow,
                new WorkflowResumeBoundary.Request(1, "synthetic retry"))));
        assertEquals(before, f.store.snapshot());
        var g = new SimulationFixture(); UUID paid = g.ready(); g.approve(paid); g.reserve(paid);
        var reserved = g.store.snapshot();
        assertThrows(SimulationFailure.class, () -> g.workflows.resume(new WorkflowResumeBoundary.Command(ACTOR, g.id(), paid,
                new WorkflowResumeBoundary.Request(1, "synthetic invalid retry"))));
        assertEquals(reserved, g.store.snapshot());
    }
    @Test void resumeKeepsUsedRiskAndAutomaticRunCountAndCapsThirdKyc() {
        var f = new SimulationFixture(); UUID workflow = f.start();
        f.workflows.observeKyc(ACTOR, f.id(), f.observation(f.input(workflow), List.of(ID_FACT)));
        var resumed = f.workflows.resume(new WorkflowResumeBoundary.Command(ACTOR, f.id(), workflow,
                new WorkflowResumeBoundary.Request(1, "synthetic remediation")));
        assertEquals(2, resumed.generation()); assertEquals(1, f.workflows.get(ACTOR, workflow).get("usedRisk"));
        f.workflows.observeKyc(ACTOR, f.id(), f.observation(f.input(workflow), List.of(ID_FACT)));
        var denied = f.workflows.resume(new WorkflowResumeBoundary.Command(ACTOR, f.id(), workflow,
                new WorkflowResumeBoundary.Request(2, "synthetic third attempt")));
        assertEquals("ON_HOLD", denied.state().name()); assertEquals("DENY", denied.decision().name()); assertEquals(2, denied.generation());
        assertEquals(2, f.workflows.get(ACTOR, workflow).get("kycRuns")); assertEquals(1, f.workflows.get(ACTOR, workflow).get("usedRisk"));
    }
    @Test void explicitRiskLimitCanHoldBeforeLoanAndNeverCreatesPayment() {
        var f = new SimulationFixture(2, null); UUID workflow = f.start();
        assertEquals("ON_HOLD", f.workflows.observeKyc(ACTOR, f.id(), f.observation(f.input(workflow), List.of(ID_FACT, FACE_FACT))).get("state"));
        assertEquals(1, f.rows(RESULTS)); assertEquals(0, f.rows(PAYMENTS)); assertEquals(1, f.workflows.get(ACTOR, workflow).get("usedRisk"));
    }

    @Test void activeWorkflowSourceAndAgentHoldsPreventResumeWithoutAdvancingGeneration() {
        for (var scope : List.of(VirtualQuarantineService.Scope.WORKFLOW,
                VirtualQuarantineService.Scope.SOURCE_VERSION, VirtualQuarantineService.Scope.AGENT_VERSION)) {
            var f = new SimulationFixture(); UUID workflow = f.ready();
            Map<String, Object> target = switch (scope) {
                case WORKFLOW -> object("workflowId", workflow.toString());
                case SOURCE_VERSION -> object("documentId", DOCUMENT.toString(), "documentVersion", 1);
                case AGENT_VERSION -> object("agentId", "synthetic-kyc", "agentVersion", 1);
                default -> throw new AssertionError("Unexpected synthetic scope");
            };
            f.quarantines.create(ACTOR, f.id(), new VirtualQuarantineService.Target(scope, target), "SYNTHETIC_ACTIVE_SCOPE", "");
            int jobs = f.rows(JOBS), runs = f.rows(RUNS);
            assertEquals(false, f.workflows.get(ACTOR, workflow).get("canResume"));
            var denied = f.workflows.resume(new WorkflowResumeBoundary.Command(ACTOR, f.id(), workflow,
                    new WorkflowResumeBoundary.Request(1, "synthetic active hold")));
            assertEquals("DENY", denied.decision().name()); assertEquals("ON_HOLD", denied.state().name());
            assertEquals(1, denied.generation()); assertEquals(jobs, f.rows(JOBS)); assertEquals(runs, f.rows(RUNS));
            assertEquals(3, f.workflows.get(ACTOR, workflow).get("usedRisk"));
            assertEquals(0, f.rows(APPROVALS)); assertEquals(0, f.rows(PAYMENTS));
        }
    }

    @Test void resumeReadinessFailsClosedWhenNoNextIntegerGenerationExists() {
        var f = new SimulationFixture(); UUID workflow = f.ready();
        f.quarantine(workflow);
        f.store.transaction(tx -> {
            var row = new LinkedHashMap<String, Object>(tx.get(WORKFLOWS, workflow.toString()));
            row.put("generation", Integer.MAX_VALUE);
            tx.put(WORKFLOWS, workflow.toString(), row);
            return null;
        });
        var before = f.store.snapshot();
        assertEquals(false, f.workflows.get(ACTOR, workflow).get("canResume"));
        assertEquals(before, f.store.snapshot());
    }

    @Test void independentResumeDoesNotReuseOrInheritHistoricalRunOrResultHolds() {
        for (var scope : List.of(VirtualQuarantineService.Scope.RUN, VirtualQuarantineService.Scope.RESULT)) {
            var f = new SimulationFixture(); UUID workflow = f.ready();
            var oldResult = f.store.snapshot().get(RESULTS).values().stream()
                    .filter(row -> "KYC".equals(row.get("role"))).findFirst().orElseThrow();
            UUID hold = UUID.fromString((String) f.quarantine(workflow).get("quarantineId"));
            f.release(hold);
            f.workflows.resume(new WorkflowResumeBoundary.Command(ACTOR, f.id(), workflow,
                    new WorkflowResumeBoundary.Request(1, "synthetic independent generation")));
            Map<String, Object> target = scope == VirtualQuarantineService.Scope.RUN
                    ? object("runId", oldResult.get("runId")) : object("resultId", oldResult.get("resultId"));
            f.quarantines.create(ACTOR, f.id(), new VirtualQuarantineService.Target(scope, target), "SYNTHETIC_HISTORICAL_SCOPE", "");
            var current = f.workflows.get(ACTOR, workflow);
            assertEquals("KYC_PENDING", current.get("state")); assertEquals(2, current.get("generation"));
            assertEquals(3, current.get("usedRisk")); assertEquals(1, current.get("kycRuns"));
            var freshInput = f.input(workflow);
            assertEquals(2, freshInput.get("generation")); assertNotEquals(oldResult.get("runId"), freshInput.get("runId"));
            f.workflows.observeKyc(ACTOR, f.id(), f.observation(freshInput, List.of(ID_FACT, FACE_FACT)));
            assertEquals("WAIT_APPROVAL", f.workflows.get(ACTOR, workflow).get("state"));
            assertEquals(0, f.rows(APPROVALS)); assertEquals(0, f.rows(PAYMENTS));
        }
    }
    @Test void typedRecordingKeepsAgentAndPaymentDomainsSeparateAndReplayUnchanged() {
        var f = new SimulationFixture(); UUID workflow = f.start();
        var input = f.input(workflow); UUID observationAction = f.id();
        var observation = f.observation(input, List.of(ID_FACT, FACE_FACT));
        f.workflows.observeKyc(ACTOR, observationAction, observation);
        var afterObservation = f.store.snapshot();
        for (var result : afterObservation.get(RESULTS).values()) {
            assertEquals(java.util.Set.of("resultId", "runId", "workflowId", "generation", "role", "body",
                    "resultHash", "evidenceBundleHash"), result.keySet());
            assertEquals(CanonicalJson.sha256(result.get("body")), result.get("resultHash"));
            assertFalse(result.containsKey("status"));
        }
        assertEquals(2, f.rows(RESULTS));
        assertEquals(true, f.workflows.observeKyc(ACTOR, observationAction, observation).get("replayed"));
        assertEquals(afterObservation, f.store.snapshot());
        f.approve(workflow); UUID reservation = f.reserve(workflow), paymentAction = f.id();
        f.workflows.commitPayment(ACTOR, paymentAction, workflow, reservation);
        var afterPayment = f.store.snapshot();
        var payment = afterPayment.get(PAYMENTS).values().iterator().next();
        assertEquals(java.util.Set.of("paymentId", "workflowId", "generation", "reservationId", "approvalId", "runId",
                "actionId", "customerId", "amountKrw", "payoutAccountId", "createdAt", "executionMode"), payment.keySet());
        assertEquals(paymentAction.toString(), payment.get("actionId"));
        assertEquals(2, f.rows(RESULTS));
        assertEquals(true, f.workflows.commitPayment(ACTOR, paymentAction, workflow, reservation).get("replayed"));
        assertEquals(afterPayment, f.store.snapshot());
        assertEquals(List.of(), f.workflows.trace(ACTOR, workflow).get("grants"));
    }

    @Test void typedRecordingMismatchRollsBackObservationAndPaymentCallbacks() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var input = f.input(workflow);
        UUID runId = UUID.fromString((String) input.get("runId"));
        f.store.transaction(tx -> {
            var row = new LinkedHashMap<String, Object>(tx.get(RUNS, runId.toString()));
            row.put("role", "PAYMENT"); tx.put(RUNS, runId.toString(), row); return null;
        });
        var before = f.store.snapshot(); UUID action = f.id();
        assertThrows(SimulationFailure.class, () -> f.workflows.observeKyc(ACTOR, action,
                f.observation(input, List.of(ID_FACT, FACE_FACT))));
        assertEquals(before, f.store.snapshot());
        assertEquals(0, f.rows(RESULTS));

        var g = new SimulationFixture(); UUID paidWorkflow = g.ready(); g.approve(paidWorkflow);
        UUID reservation = g.reserve(paidWorkflow);
        g.store.transaction(tx -> {
            String paymentRun = (String) tx.get(RESERVATIONS, reservation.toString()).get("runId");
            var row = new LinkedHashMap<String, Object>(tx.get(RUNS, paymentRun));
            row.put("role", "LOAN"); tx.put(RUNS, paymentRun, row); return null;
        });
        var paymentBefore = g.store.snapshot();
        assertThrows(SimulationFailure.class, () -> g.workflows.commitPayment(ACTOR, g.id(), paidWorkflow, reservation));
        assertEquals(paymentBefore, g.store.snapshot()); assertEquals(0, g.rows(PAYMENTS));
    }

}
