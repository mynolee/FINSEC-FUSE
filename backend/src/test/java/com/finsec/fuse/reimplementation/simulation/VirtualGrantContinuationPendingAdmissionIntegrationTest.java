package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.auth.SyntheticGrantV2Codec;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.RootInputs;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Actual supported virtual payment producer; no seeded successful ledger or real authority. */
class VirtualGrantContinuationPendingAdmissionIntegrationTest {
    private static UUID id(long n) { return VirtualGrantWorkflowBridgeTest.id(n); }

    private static ContinuationCommand command(VirtualGrantApprovalControlBoundaryTest.Scenario scenario) {
        var app = scenario.f.app; var old = app.root; var oldClaims = old.inputs().claims();
        var application = old.workflowPlan().application();
        var action = new SyntheticGrantV2Codec.Action(id(61001), oldClaims.workflowId(), 2,
                AllowedAction.EVALUATE_KYC, application.customerId(), application.amountKrw(), application.payoutAccountId(),
                id(61002), null, oldClaims.evidenceBundleHash(), null, app.terms.policyVersion());
        var payload = new LinkedHashMap<String, Object>();
        payload.put("actionId", action.actionId().toString()); payload.put("workflowId", action.workflowId().toString());
        payload.put("generation", action.generation()); payload.put("allowedAction", action.allowedAction().name());
        payload.put("customerId", action.customerId()); payload.put("amountKrw", action.amountKrw());
        payload.put("payoutAccountId", action.payoutAccountId().toString()); payload.put("targetRunId", action.targetRunId().toString());
        payload.put("sourceResultId", null); payload.put("evidenceBundleHash", action.evidenceBundleHash());
        payload.put("approvalId", null); payload.put("policyVersion", action.policyVersion());
        var claims = new SyntheticGrantV2Codec.Claims(oldClaims.format(), oldClaims.algorithm(), oldClaims.kid(), id(61003),
                oldClaims.workflowId(), 2, oldClaims.rootAuthorizationId(), oldClaims.principalId(), oldClaims.originIntent(),
                oldClaims.issuer(), oldClaims.sourceAgent(), oldClaims.targetAgent(), null, action.targetRunId(),
                action.allowedAction(), action.customerId(), action.amountKrw(), action.payoutAccountId(), null,
                action.evidenceBundleHash(), null, 1, action.actionId(), CanonicalJson.sha256(payload), action.policyVersion(),
                id(61004), null, oldClaims.issuedAt(), oldClaims.expiresAt());
        var root = new RootInputs(old.inputs().profile(), claims, action,
                SyntheticGrantV2Codec.prepare(old.inputs().profile(), claims, action));
        var i = old.identity();
        var identity = new CommandIdentity(i.actorId(), id(61005), "synthetic-continuation-pending",
                i.canonicalizationVersion(), i.canonicalBodyDigest(), claims.grantId(), action.actionId(), action.targetRunId(),
                i.workflowId(), 2, i.customerId());
        var prior = new OriginalGenerationOne(new VirtualWorkflowLane.Scope(i.workflowId(), 1, i.customerId()),
                i.grantId(), i.globalRequestId(), i.targetRunId(), 0);
        return new ContinuationCommand(identity, prior, root, application, app.terms, old.workflowPlan().laneReference(),
                old.workflowPlan().stageAgents(), Instant.ofEpochSecond(150));
    }

    @Test void coherentSupportedReviewAndReserveProducerRefusesContinuationBeforeResolutionWithoutPublication() {
        // Scenario's constructor actually provisions root, prepares/consumes KYC,
        // issues/consumes LOAN and reviews approval. No raw successful row is seeded.
        var scenario = new VirtualGrantApprovalControlBoundaryTest.Scenario();
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, scenario.f.issue(scenario.f.proof()).status());
        var reserved = scenario.plans.reserve(scenario.f.reviewer, scenario.reservation);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, reserved.status());
        assertEquals(SyntheticMockPaymentPlanBinding.PlanOperation.RESERVE, reserved.receipt().purpose());
        assertEquals(scenario.f.app.terms.payPoints(), scenario.workflow().get("reservedRisk"));
        assertEquals(SyntheticMockPaymentPlanBinding.ApprovalPlanState.RESERVED, reserved.receipt().approval().state());
        assertTrue(scenario.f.app.seed.f.store.snapshot().getOrDefault("virtual_grant_profile_payments", Map.of()).isEmpty());

        var store = scenario.f.app.seed.f.store;
        var liability = store.snapshot();
        var control = scenario.f.app.seed.f.quarantines;
        var quarantine = control.create(SimulationFixture.ACTOR, scenario.f.app.seed.f.id(),
                new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.WORKFLOW,
                        Map.of("workflowId", scenario.f.child.workflowId().toString())), "SYNTHETIC_PENDING_CONTROL", "");
        UUID quarantineId = UUID.fromString((String) quarantine.get("quarantineId"));
        control.release(SimulationFixture.ACTOR, scenario.f.app.seed.f.id(), quarantineId,
                new VirtualQuarantineService.Remediation(SimulationFixture.DOCUMENT, 2, List.of(SimulationFixture.ID_FACT),
                        "synthetic checked", null, null));
        // Supported C hold/release changes eligibility to BLOCKED but preserves
        // the historical reserved liability; no raw workflow state is seeded.
        assertEquals("BLOCKED", scenario.workflow().get("state"));
        assertEquals(scenario.f.app.terms.payPoints(), scenario.workflow().get("reservedRisk"));
        assertEquals(liability.get("virtual_grant_profile_payment_plans"), store.snapshot().get("virtual_grant_profile_payment_plans"));
        assertEquals(liability.get("virtual_grant_profile_review_approvals"), store.snapshot().get("virtual_grant_profile_review_approvals"));
        for (var request : List.of(scenario.reservation.identity().globalRequestId(), scenario.f.approval.reviewRequestId(),
                scenario.f.command.identity().globalRequestId())) {
            assertEquals(liability.get(ActionJournal.TABLE).get(request.toString()),
                    store.snapshot().get(ActionJournal.TABLE).get(request.toString()));
        }
        var c = command(scenario); var journal = scenario.f.app.journal;
        var before = store.snapshot();
        // Observe the actual same-Tx producer classification. Its own reservation is
        // verified/excluded by Journal, not manually omitted from a fake inventory.
        AtomicReference<CurrentBindings> reached = new AtomicReference<>();
        var preview = journal.continueWorkflow(c, tx -> {
            assertNull(tx.lookupExactContinuation(c)); tx.admitFreshContinuation(c);
            var ticket = tx.readContinuationBindings(c); reached.set(ticket);
            throw OwnedGrantTransactionPort.stop(Status.REFUSED_BEFORE_ADMISSION);
        });
        assertEquals(Status.REFUSED_BEFORE_ADMISSION, preview.status());
        assertNotNull(reached.get(), "preview refused before reaching the actual pending producer");
        assertEquals(PendingDisposition.COHERENT_NONEMPTY, reached.get().pendingDisposition());
        assertEquals(scenario.f.app.terms.payPoints(), reached.get().counters().reservedRisk());
        assertSame(before, store.snapshot());
        assertFalse(store.snapshot().get(ActionJournal.TABLE).containsKey(c.identity().globalRequestId().toString()));

        AtomicInteger checks = new AtomicInteger(), resolutions = new AtomicInteger();
        var context = new SyntheticTypedContinuationService.ContinuationServerContext() {
            public String actorId() { return scenario.f.app.seed.context.actorId(); }
            public String subjectId() { return scenario.f.app.seed.context.subjectId(); }
        };
        var facts = new SyntheticTypedContinuationService.CurrentContinuationFactResolver() {
            public Gate current(SyntheticTypedContinuationService.ContinuationServerContext actor, ContinuationCommand input,
                                OwnedTypedContinuationPort.OwnedContinuationTx tx) {
                checks.incrementAndGet();
                if (!actor.actorId().equals(context.actorId()) || !actor.subjectId().equals(context.subjectId()) || !input.equals(c))
                    return Gate.REFUSED;
                var time = new com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.TemporalFacts(
                        input.observedAt().getEpochSecond(), input.newRoot().claims().issuedAt(), input.newRoot().claims().expiresAt(),
                        com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null);
                return com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.assess(time,
                        scenario.f.app.seed.facts.rev()).blockers().isEmpty() ? Gate.CLEAR : Gate.UNKNOWN;
            }
            public ResolvedContinuation resolve(SyntheticTypedContinuationService.ContinuationServerContext actor,
                    ContinuationCommand input, CurrentBindings bindings, OwnedTypedContinuationPort.OwnedContinuationTx tx) {
                resolutions.incrementAndGet(); throw new AssertionError("pending liability reached root resolution");
            }
        };
        var service = new SyntheticTypedContinuationService(journal, facts, scenario.f.app.seed.f.catalog);
        var result = service.continueWorkflow(context, c);
        assertEquals(Status.REFUSED_BEFORE_ADMISSION, result.status()); assertNull(result.receipt());
        assertEquals(ContinuationEffect.NO_NEW_CONTINUATION_ATTEMPT_THIS_INVOCATION, result.effectKnowledge());
        assertFalse(result.actualAuthority()); assertFalse(result.durable());
        assertEquals(1, checks.get()); assertEquals(0, resolutions.get());
        assertSame(before, store.snapshot());
        assertFalse(store.snapshot().get(ActionJournal.TABLE).containsKey(c.identity().globalRequestId().toString()));
        assertTrue(store.snapshot().getOrDefault("virtual_grant_profile_current_heads", Map.of()).isEmpty());
        assertEquals(1, scenario.workflow().get("generation"));
        assertEquals(scenario.f.app.terms.payPoints(), scenario.workflow().get("reservedRisk"));
        // The approved reservation remains an exact replay; refusal did not cancel/refund or poison it.
        var replay = scenario.plans.reserve(scenario.f.reviewer, scenario.reservation);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS, replay.status());
        assertEquals(reserved.receipt(), replay.receipt()); assertEquals(before, store.snapshot());
    }
}
