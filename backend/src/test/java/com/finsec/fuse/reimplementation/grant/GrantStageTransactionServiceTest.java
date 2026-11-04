package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.RunStatus;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.ResultStatus;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static org.junit.jupiter.api.Assertions.*;

/** Supplied synthetic reference mechanics only; no authenticated or durable store facts. */
class GrantStageTransactionServiceTest {
    static UUID id(long value) { return new UUID(7, value); }
    static CommandIdentity identity(long request, GrantSnapshot grant) {
        return new CommandIdentity("synthetic-actor", id(request), "synthetic-complete",
                "supplied-profile", "supplied-command-digest", grant.grantId(), grant.actionId(),
                grant.targetRunId(), grant.workflowId(), grant.generation(), grant.customerId());
    }
    static StageCommand command(long request, GrantSnapshot grant) {
        return new StageCommand(identity(request, grant), grant.action());
    }
    static OutsidePreparedResult prepared(long value, BusinessConclusion conclusion) {
        return new OutsidePreparedResult(id(value), conclusion, "AGENT_RESULT_BINDING_RECORD_1",
                new byte[] {1, 2}, new byte[] {3, 4});
    }
    static class Facts implements CurrentFactResolver {
        Gate gate = Gate.CLEAR, issuance = Gate.CLEAR;
        int checks, resolutions, issuances;
        RunStatus run = RunStatus.VALIDATED;
        ResultStatus result = ResultStatus.VALIDATED;
        final List<OwnedTx> contexts = new ArrayList<>();
        public Gate current(ServerContext context, StageCommand command, OwnedTx tx) {
            checks++; contexts.add(tx); return gate;
        }
        public ResolvedStage resolve(ServerContext context, StageCommand command,
                                     OutsidePreparedResult prepared, OwnedTx tx) {
            resolutions++; contexts.add(tx);
            return new ResolvedStage(tx.grant(command.identity().grantId()), prepared, run, result,
                    List.of(new DomainWrite(id(900 + resolutions), Map.of("business", prepared.businessConclusion().name()))));
        }
        public Gate checkIssuance(ServerContext context, StageCommand command, UUID parent,
                                  GrantSnapshot child, OwnedTx tx) {
            issuances++; contexts.add(tx); return issuance;
        }
    }
    static class Fixture {
        final TransactionalStore store;
        final Facts facts = new Facts();
        final VirtualGrantTransactionJournal journal;
        final GrantStageTransactionService service;
        final GrantSnapshot root = new GrantSnapshot(id(10), id(11), id(12), id(13), 1,
                "synthetic-customer", AllowedAction.EVALUATE_KYC, GrantState.ISSUED);
        final StageCommand command = command(20, root);
        final OutsidePreparedResult prepared = prepared(30, BusinessConclusion.POSITIVE);
        final ServerContext context = () -> "synthetic-actor";
        Fixture() { this(new VirtualTransactionalStore()); }
        Fixture(TransactionalStore supplied) {
            store = supplied;
            AtomicInteger tokens = new AtomicInteger(100);
            journal = VirtualGrantTransactionJournal.detachedReference(store, () -> id(tokens.incrementAndGet()), 65536);
            service = new GrantStageTransactionService(journal, facts);
            journal.seedSyntheticRoot(root);
        }
        StageOutcome complete() { return service.completeStage(context, command, prepared); }
        GrantSnapshot child(long n, AllowedAction action) {
            return new GrantSnapshot(id(n), id(n + 1), id(n + 2), root.workflowId(), root.generation(),
                    root.customerId(), action, GrantState.ISSUED);
        }
    }

    @Test void exactReplayDoesNotResolveConsumeOrCreateChildAgain() {
        Fixture f = new Fixture(); StageOutcome first = f.complete();
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, first.status());
        var before = f.store.snapshot();
        StageOutcome replay = f.service.completeStage(f.context, f.command, null);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS, replay.status());
        assertEquals(first.receipt(), replay.receipt());
        assertEquals(1, f.facts.resolutions); assertEquals(0, f.facts.issuances);
        assertEquals(before, f.store.snapshot());
        assertFalse(first.actualAuthority()); assertFalse(first.durable());
        assertFalse(replay.actualAuthority()); assertFalse(replay.durable());
        assertSame(f.facts.contexts.get(0), f.facts.contexts.get(1));
        assertEquals(1, f.store.snapshot().get("virtual_grant_profile_grants").size());
    }

    @Test void currentRefusedOrUnknownPrecedesCommittedReceiptDisclosure() {
        for (Gate gate : List.of(Gate.REFUSED, Gate.UNKNOWN)) {
            Fixture f = new Fixture(); f.complete(); var before = f.store.snapshot(); f.facts.gate = gate;
            StageOutcome outcome = f.service.reconcile(f.context, f.command);
            assertEquals(gate == Gate.REFUSED ? Status.REFUSED_BEFORE_ADMISSION : Status.UNCONFIRMED_BEFORE_ADMISSION, outcome.status());
            assertNull(outcome.receipt()); assertEquals(before, f.store.snapshot());
            assertEquals(1, f.facts.resolutions);
        }
    }

    @Test void mismatchedContextActorCannotUseEvenAnExactCompletedIdentity() {
        Fixture f = new Fixture(); f.complete(); int checks = f.facts.checks;
        StageOutcome denied = f.service.completeStage(() -> "synthetic-other", f.command, f.prepared);
        assertEquals(Status.REFUSED_BEFORE_ADMISSION, denied.status());
        assertNull(denied.receipt()); assertEquals(checks, f.facts.checks);
    }

    @Test void eachOfElevenIdentityFieldsCannotReplaceCommittedBinding() {
        for (int field = 0; field < 11; field++) {
            Fixture f = new Fixture(); f.complete(); CommandIdentity i = f.command.identity();
            CommandIdentity changed = new CommandIdentity(field == 0 ? "other-actor" : i.actorId(),
                    field == 1 ? id(200) : i.globalRequestId(), field == 2 ? "other-operation" : i.operation(),
                    field == 3 ? "other-profile" : i.canonicalizationVersion(),
                    field == 4 ? "other-digest" : i.canonicalBodyDigest(), field == 5 ? id(201) : i.grantId(),
                    field == 6 ? id(202) : i.actionId(), field == 7 ? id(203) : i.targetRunId(),
                    field == 8 ? id(204) : i.workflowId(), field == 9 ? 2 : i.generation(),
                    field == 10 ? "other-customer" : i.customerId());
            var before = f.store.snapshot();
            StageOutcome result = f.service.completeStage(changed::actorId,
                    new StageCommand(changed, AllowedAction.EVALUATE_KYC), f.prepared);
            assertEquals(Status.IDENTITY_CONFLICT, result.status(), "identity field " + field);
            assertNull(result.receipt()); assertEquals(before, f.store.snapshot());
        }
    }

    @Test void negativeValidatedBusinessCommitsExactlyOnceWithoutSuccessor() {
        Fixture f = new Fixture(); var negative = prepared(31, BusinessConclusion.NEGATIVE);
        StageOutcome first = f.service.completeStage(f.context, f.command, negative);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, first.status());
        assertEquals(BusinessConclusion.NEGATIVE, first.receipt().result().businessConclusion());
        assertEquals(1, f.store.snapshot().get("virtual_grant_profile_results").size());
        assertEquals(1, f.store.snapshot().get("virtual_grant_profile_grants").size());
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS, f.service.completeStage(f.context, f.command, negative).status());
        assertEquals(1, f.facts.resolutions); assertEquals(0, f.facts.issuances);
    }

    @Test void unconfirmedBusinessRollsBackReservationAndDomainWrites() {
        Fixture f = new Fixture(); var before = f.store.snapshot();
        StageOutcome refusal = f.service.completeStage(f.context, f.command, prepared(32, BusinessConclusion.UNCONFIRMED));
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION, refusal.status());
        assertEquals(before, f.store.snapshot());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, f.complete().status());
    }

    @Test void successorRequiresSeparateCommandAndOnlyOneParentSlot() {
        Fixture f = new Fixture(); f.complete();
        GrantSnapshot loan = f.child(40, AllowedAction.CREATE_LOAN_RECOMMENDATION);
        StageCommand issue = command(50, loan);
        StageOutcome issued = f.service.issueSuccessor(f.context, issue, f.root.grantId(), loan);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, issued.status());
        assertEquals(ReceiptKind.ISSUANCE, issued.receipt().kind()); assertNull(issued.receipt().result());
        var before = f.store.snapshot();
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS, f.service.issueSuccessor(f.context, issue, f.root.grantId(), loan).status());
        assertEquals(1, f.facts.issuances); assertEquals(before, f.store.snapshot());
        GrantSnapshot duplicate = f.child(60, AllowedAction.CREATE_LOAN_RECOMMENDATION);
        assertEquals(Status.IDENTITY_CONFLICT, f.service.issueSuccessor(f.context, command(70, duplicate), f.root.grantId(), duplicate).status());
        assertEquals(before, f.store.snapshot());
    }

    @Test void loanMayIssuePaymentButPaymentCompletionDoesNotFabricateAgentFinality() {
        Fixture f = new Fixture(); f.complete();
        GrantSnapshot loan = f.child(40, AllowedAction.CREATE_LOAN_RECOMMENDATION);
        f.service.issueSuccessor(f.context, command(50, loan), f.root.grantId(), loan);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, f.service.completeStage(f.context, command(51, loan), prepared(52, BusinessConclusion.POSITIVE)).status());
        GrantSnapshot payment = f.child(60, AllowedAction.EXECUTE_MOCK_PAYMENT);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, f.service.issueSuccessor(f.context, command(70, payment), loan.grantId(), payment).status());
        var before = f.store.snapshot();
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION, f.service.completeStage(f.context, command(71, payment), prepared(72, BusinessConclusion.POSITIVE)).status());
        assertEquals(before, f.store.snapshot());
    }

    @Test void unknownIssuanceGateCannotCreateOrConsumeAChild() {
        Fixture f = new Fixture(); f.complete(); f.facts.issuance = Gate.UNKNOWN;
        var before = f.store.snapshot(); var child = f.child(40, AllowedAction.CREATE_LOAN_RECOMMENDATION);
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION, f.service.issueSuccessor(f.context, command(50, child), f.root.grantId(), child).status());
        assertEquals(before, f.store.snapshot());
    }

    @Test void bindingArraysAndNestedDomainValuesAreDetachedAndDiagnosticsRedacted() {
        byte[] bytes = {1}, digest = {2};
        var result = new OutsidePreparedResult(id(1), BusinessConclusion.POSITIVE, "synthetic-private-marker", bytes, digest);
        bytes[0] = 9; digest[0] = 9; result.bindingBytes()[0] = 8;
        assertArrayEquals(new byte[] {1}, result.bindingBytes()); assertArrayEquals(new byte[] {2}, result.bindingDigest());
        var nested = new java.util.LinkedHashMap<String, Object>(); var values = new ArrayList<>(List.of("original"));
        nested.put("values", values); DomainWrite write = new DomainWrite(id(2), nested); values.add("late");
        assertEquals(List.of("original"), write.value().get("values"));
        assertThrows(UnsupportedOperationException.class, () -> write.value().put("extra", "value"));
        assertFalse(result.toString().contains("synthetic-private-marker"));
    }
    @Test void bothValidationStatusesAndExactPreparedBindingAreRequired() {
        for (boolean badRun : List.of(false, true)) {
            Fixture f = new Fixture(); var before = f.store.snapshot();
            if (badRun) f.facts.run = RunStatus.PROPOSED; else f.facts.result = ResultStatus.PROPOSED;
            assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION, f.complete().status());
            assertEquals(before, f.store.snapshot());
        }
        Fixture f = new Fixture(); var before = f.store.snapshot();
        var unsupported = new OutsidePreparedResult(id(33), BusinessConclusion.POSITIVE,
                "other-profile", new byte[] {1}, new byte[] {2});
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,
                f.service.completeStage(f.context, f.command, unsupported).status());
        assertEquals(before, f.store.snapshot());
    }

    @Test void resolverCannotReplaceTheSuppliedPreparedResultBeforeConsumption() {
        Fixture f = new Fixture(); var before = f.store.snapshot();
        Facts changedResult = new Facts() {
            @Override public ResolvedStage resolve(ServerContext context, StageCommand command,
                                                  OutsidePreparedResult prepared, OwnedTx tx) {
                ResolvedStage resolved = super.resolve(context, command, prepared, tx);
                var different = new OutsidePreparedResult(id(999), prepared.businessConclusion(),
                        prepared.bindingProfile(), prepared.bindingBytes(), prepared.bindingDigest());
                return new ResolvedStage(resolved.grant(), different, resolved.runStatus(),
                        resolved.resultStatus(), resolved.domainWrites());
            }
        };
        StageOutcome result = new GrantStageTransactionService(f.journal, changedResult)
                .completeStage(f.context, f.command, f.prepared);
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION, result.status());
        assertEquals(EffectKnowledge.NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION, result.effectKnowledge());
        assertNull(result.receipt()); assertEquals(1, changedResult.resolutions);
        assertEquals(before, f.store.snapshot());
    }

}
