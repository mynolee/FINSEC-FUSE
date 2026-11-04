package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion;
import com.finsec.fuse.reimplementation.auth.SyntheticMockPaymentReceiptCodec;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.GrantStageTransactionServiceTest.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit synthetic lane ownership; no application bootstrap or durable authority. */
final class VirtualGrantTransactionLaneTest {
    private static final String WORKFLOWS = "virtual_workflows", LANES = "virtual_workflow_lanes";
    private static final class LaneFixture {
        final VirtualTransactionalStore store = new VirtualTransactionalStore();
        final AtomicInteger tokens = new AtomicInteger(1000);
        final GrantSnapshot root = new GrantSnapshot(id(10), id(11), id(12), id(13), 1,
                "synthetic-customer", AllowedAction.EVALUATE_KYC, GrantState.ISSUED);
        final Facts facts = new Facts();
        final VirtualGrantTransactionJournal journal;
        final GrantStageTransactionService service;
        final ServerContext actor = () -> "synthetic-actor";
        LaneFixture() {
            // Explicit test-only reference seeding precedes any actual-workflow fixture row.
            VirtualGrantTransactionJournal.detachedReference(store, () -> id(tokens.incrementAndGet()), 65536)
                    .seedSyntheticRoot(root);
            journal = new VirtualGrantTransactionJournal(store, () -> id(tokens.incrementAndGet()), 65536);
            service = new GrantStageTransactionService(journal, facts);
        }
        VirtualWorkflowLane.Scope scope() { return new VirtualWorkflowLane.Scope(root.workflowId(), 1, root.customerId()); }
        Map<String, Object> workflow() { return Map.of("workflowId", root.workflowId().toString(),
                "generation", 1, "customerId", root.customerId()); }
        Map<String, Object> lane() { var row = new LinkedHashMap<>(workflow()); row.put("lane", "TYPED"); return row; }
        void put(Map<String, Object> workflow, Map<String, Object> lane) {
            store.transaction(tx -> {
                if (workflow != null) tx.put(WORKFLOWS, root.workflowId().toString(), workflow);
                if (lane != null) tx.put(LANES, root.workflowId().toString(), lane);
                return null;
            });
        }
        void typed() {
            store.transaction(tx -> {
                VirtualWorkflowLane.registerTyped(tx, scope());
                tx.put(WORKFLOWS, root.workflowId().toString(), workflow());
                VirtualWorkflowLane.requireTyped(tx, scope());
                return null;
            });
        }
        StageOutcome complete(long request) {
            return service.completeStage(actor, command(request, root), prepared(30, BusinessConclusion.POSITIVE));
        }
    }
    private static void denied(StageOutcome outcome) {
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION, outcome.status());
        assertNull(outcome.receipt()); assertFalse(outcome.actualAuthority()); assertFalse(outcome.durable());
    }

    @Test void applicationRequiresBothActualWorkflowAndTypedLaneEvenWhenGrantExists() {
        for (int shape = 0; shape < 3; shape++) {
            var f = new LaneFixture();
            f.put(shape == 1 ? f.workflow() : null, shape == 2 ? f.lane() : null);
            var before = f.store.snapshot(); denied(f.complete(20));
            assertEquals(before, f.store.snapshot()); assertEquals(0, f.facts.resolutions);
        }
    }

    @Test void exactTypedRegistrationAndWorkflowInSameTransactionAllowAgentAndExplicitSuccessor() {
        var f = new LaneFixture(); f.typed();
        var completed = f.complete(20); assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, completed.status());
        assertFalse(completed.actualAuthority()); assertFalse(completed.durable());
        var child = new GrantSnapshot(id(40), id(41), id(42), f.root.workflowId(), 1, f.root.customerId(),
                AllowedAction.CREATE_LOAN_RECOMMENDATION, GrantState.ISSUED);
        var issued = f.service.issueSuccessor(f.actor, command(50, child), f.root.grantId(), child);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, issued.status());
        assertEquals(2, f.store.snapshot().get("virtual_grant_profile_grants").size());
        assertEquals(f.lane(), f.store.snapshot().get(LANES).get(f.root.workflowId().toString()));
    }

    @Test void legacyWorkflowCannotUseTypedWritesWithAnotherRequestUuid() {
        var f = new LaneFixture(); f.put(f.workflow(), null); var before = f.store.snapshot();
        denied(f.complete(20)); denied(f.complete(21));
        assertEquals(before, f.store.snapshot()); assertEquals(0, f.facts.resolutions);
        f.store.transaction(tx -> { VirtualWorkflowLane.requireLegacy(tx, f.scope()); return null; });
    }

    @Test void typedWorkflowCannotUseLegacyWriterGuardWithAnotherRequestUuid() {
        var f = new LaneFixture(); f.typed(); f.complete(20); var before = f.store.snapshot();
        for (long request : List.of(90L, 91L)) {
            assertThrows(RuntimeException.class, () -> new ActionJournal(f.store).execute("synthetic-actor", id(request),
                    "synthetic-legacy-write", "a".repeat(64), tx -> {
                        VirtualWorkflowLane.requireLegacy(tx, f.scope());
                        tx.put("synthetic_legacy_effect", "effect", Map.of("written", true)); return Map.of("ok", true);
                    }));
            assertEquals(before, f.store.snapshot());
        }
    }

    @Test void malformedOrMismatchedActualAndLaneScopesCannotBeRepairedByJournal() {
        for (int field = 0; field < 9; field++) {
            var f = new LaneFixture(); var workflow = new LinkedHashMap<>(f.workflow()); var lane = new LinkedHashMap<>(f.lane());
            switch (field) {
                case 0 -> lane.put("lane", "LEGACY");
                case 1 -> lane.put("lane", "UNKNOWN");
                case 2 -> lane.put("generation", 2);
                case 3 -> lane.put("generation", 1L);
                case 4 -> lane.put("customerId", "synthetic-other");
                case 5 -> lane.put("workflowId", id(999).toString());
                case 6 -> lane.put("extra", true);
                case 7 -> workflow.put("generation", 2);
                case 8 -> workflow.put("customerId", "synthetic-other");
                default -> throw new AssertionError();
            }
            f.put(workflow, lane); var before = f.store.snapshot(); denied(f.complete(20));
            assertEquals(before, f.store.snapshot()); assertEquals(0, f.facts.resolutions);
        }
    }

    @Test void detachedContextRefusesAnyPresentApplicationOrLaneRowIncludingReplay() {
        for (int shape = 0; shape < 3; shape++) {
            var f = new LaneFixture();
            var reference = VirtualGrantTransactionJournal.detachedReference(f.store, () -> id(f.tokens.incrementAndGet()), 65536);
            var service = new GrantStageTransactionService(reference, f.facts);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                    service.completeStage(f.actor, command(20, f.root), prepared(30, BusinessConclusion.POSITIVE)).status());
            f.put(shape == 0 ? Map.of("malformed", true) : f.workflow(), shape == 2 ? f.lane() : null);
            var before = f.store.snapshot();
            denied(service.completeStage(f.actor, command(20, f.root), null));
            denied(service.completeStage(f.actor, command(21, f.root), prepared(31, BusinessConclusion.POSITIVE)));
            assertEquals(before, f.store.snapshot()); assertEquals(1, f.facts.resolutions);
        }
    }

    @Test void applicationConstructorCannotUseReferenceSeedApis() {
        var f = new LaneFixture(); var before = f.store.snapshot();
        var error = assertThrows(IllegalStateException.class, () -> f.journal.seedSyntheticRoot(f.root));
        assertEquals("OWNED_GRANT_REFERENCE_FIXTURE_ONLY", error.getMessage());
        assertThrows(IllegalStateException.class, () -> f.journal.seedSyntheticPaymentDomain(null));
        assertEquals(before, f.store.snapshot());
    }

    @Test void registerTypedDoesNotBackfillAnExistingLegacyWorkflowOrHalfCommitOnFailure() {
        var f = new LaneFixture(); f.put(f.workflow(), null); var before = f.store.snapshot();
        assertThrows(RuntimeException.class, () -> f.store.transaction(tx -> {
            VirtualWorkflowLane.registerTyped(tx, f.scope()); return null;
        }));
        assertEquals(before, f.store.snapshot());
        var g = new LaneFixture(); var empty = g.store.snapshot();
        assertThrows(IllegalStateException.class, () -> g.store.transaction(tx -> {
            VirtualWorkflowLane.registerTyped(tx, g.scope());
            tx.put(WORKFLOWS, g.root.workflowId().toString(), g.workflow());
            throw new IllegalStateException("synthetic-abort");
        }));
        assertEquals(empty, g.store.snapshot());
    }

    @Test void typedLaneDoesNotCreateAnotherGlobalRequestNamespace() {
        var f = new LaneFixture(); f.typed();
        new ActionJournal(f.store).execute("synthetic-actor", id(20), "synthetic-other-operation", "b".repeat(64),
                tx -> Map.of("requestId", id(20).toString(), "synthetic", "already-completed"));
        var before = f.store.snapshot(); var outcome = f.complete(20);
        assertEquals(Status.IDENTITY_CONFLICT, outcome.status()); assertNull(outcome.receipt());
        assertEquals(before, f.store.snapshot()); assertEquals(0, f.facts.resolutions);
    }

    @Test void exactTypedPaymentUsesStrictJournalAndCannotReplayAfterLaneBecomesLegacy() {
        // Build an unrelated detached synthetic chain/plan, then attach explicit application rows.
        var f = new LaneFixture();
        var reference = VirtualGrantTransactionJournal.detachedReference(f.store, () -> id(f.tokens.incrementAndGet()), 65536);
        var stages = new GrantStageTransactionService(reference, f.facts);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                stages.completeStage(f.actor, command(20, f.root), prepared(30, BusinessConclusion.POSITIVE)).status());
        var loan = new GrantSnapshot(id(40), id(41), id(42), f.root.workflowId(), 1, f.root.customerId(),
                AllowedAction.CREATE_LOAN_RECOMMENDATION, GrantState.ISSUED);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, stages.issueSuccessor(f.actor, command(50, loan), f.root.grantId(), loan).status());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, stages.completeStage(f.actor, command(51, loan), prepared(52, BusinessConclusion.POSITIVE)).status());
        var payment = new GrantSnapshot(id(60), id(61), id(62), f.root.workflowId(), 1, f.root.customerId(),
                AllowedAction.EXECUTE_MOCK_PAYMENT, GrantState.ISSUED);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, stages.issueSuccessor(f.actor, command(70, payment), loan.grantId(), payment).status());
        var domain = new PaymentDomain(payment.grantId(), payment.actionId(), id(83), payment.targetRunId(), id(81), id(82),
                payment.workflowId(), 1, payment.customerId(), id(80), 1000L, id(84), "synthetic-payment-policy",
                ReservationState.RESERVED, ApprovalState.RESERVED);
        reference.seedSyntheticPaymentDomain(domain);
        var stage = command(71, payment); var i = stage.identity();
        var digest = new DigestBinding(i.canonicalBodyDigest(), "synthetic-algorithm", new byte[] {1, 2});
        var input = new SyntheticMockPaymentReceiptCodec.Input(i.globalRequestId(), i.actorId(), i.operation(),
                i.canonicalizationVersion(), digest.algorithm(), digest.bytes(), payment.grantId(), payment.actionId(),
                domain.paymentId(), payment.targetRunId(), domain.approvalId(), domain.reservationId(), payment.workflowId(),
                1, payment.customerId(), domain.applicationId(), domain.amountKrw(), domain.payoutAccountId(),
                domain.securityPolicyVersion(), "EXECUTE_MOCK_PAYMENT", "COMMITTED", "CONSUMED");
        var command = new PaymentCommand(stage, digest, input);
        var resolved = new ResolvedPayment(domain, digest, input, List.of());
        PaymentFactResolver facts = new PaymentFactResolver() {
            public Gate current(ServerContext actor, PaymentCommand c, OwnedTx tx) { return Gate.CLEAR; }
            public ResolvedPayment resolve(ServerContext actor, PaymentCommand c, OwnedTx tx) { return resolved; }
        };
        f.typed();
        var service = new SyntheticMockPaymentTransactionService(f.journal, facts);
        var outcome = service.completePayment(f.actor, command);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, outcome.status());
        assertFalse(outcome.actualAuthority()); assertFalse(outcome.durable());
        var lane = new LinkedHashMap<>(f.lane()); lane.put("lane", "LEGACY"); f.put(null, lane);
        var before = f.store.snapshot(); denied(service.completePayment(f.actor, command));
        assertEquals(before, f.store.snapshot());
        assertEquals(1, f.store.snapshot().get("virtual_grant_profile_payments").size());
    }
}
