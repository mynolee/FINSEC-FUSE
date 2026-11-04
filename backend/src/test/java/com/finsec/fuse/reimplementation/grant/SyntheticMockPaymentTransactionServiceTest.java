package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion;
import com.finsec.fuse.reimplementation.auth.SyntheticMockPaymentReceiptCodec;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.GrantStageTransactionServiceTest.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real in-memory reference composition, not real payment or durable authority. */
final class SyntheticMockPaymentTransactionServiceTest {
    private static final String PLANS = "virtual_grant_profile_payment_plans", PAYMENTS = "virtual_grant_profile_payments";
    private static final class PaymentFacts implements PaymentFactResolver {
        Gate gate = Gate.CLEAR;
        int checks, resolutions;
        ResolvedPayment resolved;
        final List<OwnedTx> contexts = new ArrayList<>();
        public Gate current(ServerContext context, PaymentCommand command, OwnedTx tx) {
            checks++; contexts.add(tx); return gate;
        }
        public ResolvedPayment resolve(ServerContext context, PaymentCommand command, OwnedTx tx) {
            resolutions++; contexts.add(tx); return resolved;
        }
    }
    private static final class PaymentFixture {
        final Fixture chain;
        final PaymentFacts facts = new PaymentFacts();
        final GrantSnapshot loan, payment;
        final PaymentDomain domain;
        final PaymentCommand command;
        final SyntheticMockPaymentTransactionService service;
        PaymentFixture() { this(new VirtualTransactionalStore()); }
        PaymentFixture(TransactionalStore store) {
            chain = new Fixture(store);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, chain.complete().status());
            loan = chain.child(40, AllowedAction.CREATE_LOAN_RECOMMENDATION);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                    chain.service.issueSuccessor(chain.context, command(50, loan), chain.root.grantId(), loan).status());
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                    chain.service.completeStage(chain.context, command(51, loan), prepared(52, BusinessConclusion.POSITIVE)).status());
            payment = chain.child(60, AllowedAction.EXECUTE_MOCK_PAYMENT);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                    chain.service.issueSuccessor(chain.context, command(70, payment), loan.grantId(), payment).status());
            domain = new PaymentDomain(payment.grantId(), payment.actionId(), id(83), payment.targetRunId(), id(81), id(82),
                    payment.workflowId(), 1, payment.customerId(), id(80), 1000L, id(84), "synthetic-payment-policy",
                    ReservationState.RESERVED, ApprovalState.RESERVED);
            chain.journal.seedSyntheticPaymentDomain(domain);
            var stage = command(71, payment); var identity = stage.identity();
            var digest = new DigestBinding(identity.canonicalBodyDigest(), "synthetic-explicit-command-algorithm", new byte[] {1, 2, 3});
            var input = new SyntheticMockPaymentReceiptCodec.Input(identity.globalRequestId(), identity.actorId(), identity.operation(),
                    identity.canonicalizationVersion(), digest.algorithm(), digest.bytes(), payment.grantId(), payment.actionId(),
                    domain.paymentId(), payment.targetRunId(), domain.approvalId(), domain.reservationId(), payment.workflowId(),
                    1, payment.customerId(), domain.applicationId(), domain.amountKrw(), domain.payoutAccountId(),
                    domain.securityPolicyVersion(), "EXECUTE_MOCK_PAYMENT", "COMMITTED", "CONSUMED");
            command = new PaymentCommand(stage, digest, input);
            facts.resolved = new ResolvedPayment(domain, digest, input,
                    List.of(new DomainWrite(id(910), Map.of("synthetic-payment-reference", "completed"))));
            service = new SyntheticMockPaymentTransactionService(chain.journal, facts);
        }
        StageOutcome complete() { return service.completePayment(chain.context, command); }
    }
    @SuppressWarnings("unchecked")
    private static <T extends Record> T changed(T original, String field, Object replacement) throws Exception {
        RecordComponent[] fields = original.getClass().getRecordComponents();
        var types = new Class<?>[fields.length]; var values = new Object[fields.length]; boolean found = false;
        for (int i = 0; i < fields.length; i++) {
            types[i] = fields[i].getType(); values[i] = fields[i].getAccessor().invoke(original);
            if (fields[i].getName().equals(field)) { values[i] = replacement; found = true; }
        }
        assertTrue(found);
        try { return (T) original.getClass().getConstructor(types).newInstance(values); }
        catch (InvocationTargetException wrapped) {
            if (wrapped.getCause() instanceof RuntimeException failure) throw failure;
            throw wrapped;
        }
    }
    private static void referenceOnly(StageOutcome outcome) {
        assertFalse(outcome.actualAuthority()); assertFalse(outcome.durable());
    }
    private static PaymentCommand newRequest(PaymentFixture f) throws Exception {
        CommandIdentity identity = changed(f.command.stage().identity(), "globalRequestId", id(999));
        return new PaymentCommand(new StageCommand(identity, AllowedAction.EXECUTE_MOCK_PAYMENT), f.command.admittedCommandDigest(),
                changed(f.command.expectedReceipt(), "globalRequestId", identity.globalRequestId()));
    }
    private static String fingerprint(CommandIdentity i) {
        return CanonicalJson.sha256(Map.ofEntries(Map.entry("actorId", i.actorId()),
                Map.entry("globalRequestId", i.globalRequestId().toString()), Map.entry("operation", i.operation()),
                Map.entry("canonicalizationVersion", i.canonicalizationVersion()), Map.entry("canonicalBodyDigest", i.canonicalBodyDigest()),
                Map.entry("grantId", i.grantId().toString()), Map.entry("actionId", i.actionId().toString()),
                Map.entry("targetRunId", i.targetRunId().toString()), Map.entry("workflowId", i.workflowId().toString()),
                Map.entry("generation", i.generation()), Map.entry("customerId", i.customerId())));
    }

    @Test void admittedPaymentStoresExactMp22AndReplaysWithoutAnyAdditionalDomainEffects() {
        var f = new PaymentFixture(); var outcome = f.complete(); referenceOnly(outcome);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, outcome.status());
        assertEquals(ReceiptKind.CONSUMPTION, outcome.receipt().kind());
        assertEquals(f.domain.paymentId(), outcome.receipt().result().resultId());
        assertEquals(BusinessConclusion.POSITIVE, outcome.receipt().result().businessConclusion());
        assertEquals(RECEIPT_BINDING_PROFILE, outcome.receipt().result().bindingProfile());
        var codec = SyntheticMockPaymentReceiptCodec.prepare(f.command.expectedReceipt());
        assertArrayEquals(codec.canonicalBytes(), outcome.receipt().result().bindingBytes());
        assertArrayEquals(codec.receiptDigest(), outcome.receipt().result().bindingDigest());
        var before = f.chain.store.snapshot(); var row = before.get(PAYMENTS).get(f.domain.paymentId().toString());
        assertEquals(7, row.size()); assertEquals(22, ((Map<?, ?>) row.get("input")).size());
        assertEquals(HexFormat.of().formatHex(codec.canonicalBytes()), row.get("canonicalBytes"));
        assertEquals("COMMITTED", before.get(PLANS).get(f.domain.reservationId().toString()).get("reservationState"));
        assertEquals("CONSUMED", before.get(PLANS).get(f.domain.reservationId().toString()).get("approvalState"));
        var replay = f.complete(); referenceOnly(replay);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS, replay.status()); assertEquals(outcome.receipt(), replay.receipt());
        assertEquals(1, f.facts.resolutions); assertEquals(2, f.facts.checks); assertEquals(before, f.chain.store.snapshot());
        assertSame(f.facts.contexts.get(0), f.facts.contexts.get(1));
    }

    @Test void currentGateRunsBeforeLookupAndCanDenyEvenCorruptCachedReceipt() {
        var f = new PaymentFixture(); f.complete();
        f.chain.store.transaction(tx -> {
            var row = new java.util.LinkedHashMap<>(tx.get(PAYMENTS, f.domain.paymentId().toString()));
            row.put("canonicalBytes", "00"); tx.put(PAYMENTS, f.domain.paymentId().toString(), row); return null;
        });
        var before = f.chain.store.snapshot();
        for (Gate gate : List.of(Gate.REFUSED, Gate.UNKNOWN)) {
            f.facts.gate = gate; var result = f.service.reconcile(f.chain.context, f.command); referenceOnly(result);
            assertEquals(gate == Gate.REFUSED ? Status.REFUSED_BEFORE_ADMISSION : Status.UNCONFIRMED_BEFORE_ADMISSION, result.status());
            assertNull(result.receipt()); assertEquals(before, f.chain.store.snapshot());
        }
        f.facts.gate = Gate.CLEAR;
        assertEquals(Status.TRANSACTION_INVARIANT_UNCONFIRMED, f.service.reconcile(f.chain.context, f.command).status());
        assertEquals(1, f.facts.resolutions);
    }

    @Test void foreignActorRefusesBeforeResolverAndCannotDiscloseReceipt() {
        var f = new PaymentFixture(); f.complete(); var before = f.chain.store.snapshot(); int checks = f.facts.checks;
        var denied = f.service.completePayment(() -> "synthetic-foreign", f.command); referenceOnly(denied);
        assertEquals(Status.REFUSED_BEFORE_ADMISSION, denied.status()); assertNull(denied.receipt());
        assertEquals(checks, f.facts.checks); assertEquals(1, f.facts.resolutions); assertEquals(before, f.chain.store.snapshot());
    }

    @Test void changedResolvedReceiptOrStoredPlanMismatchRollsBackGlobalAdmission() throws Exception {
        var f = new PaymentFixture(); var before = f.chain.store.snapshot();
        f.facts.resolved = new ResolvedPayment(f.domain, f.command.admittedCommandDigest(),
                changed(f.command.expectedReceipt(), "amountKrw", 1001L), List.of());
        var mismatch = f.complete(); referenceOnly(mismatch);
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION, mismatch.status()); assertNull(mismatch.receipt());
        assertEquals(before, f.chain.store.snapshot()); assertEquals(1, f.facts.resolutions);
        var g = new PaymentFixture();
        g.chain.store.transaction(tx -> {
            var row = new java.util.LinkedHashMap<>(tx.get(PLANS, g.domain.reservationId().toString()));
            row.put("amountKrw", 1001L); tx.put(PLANS, g.domain.reservationId().toString(), row); return null;
        });
        var drifted = g.chain.store.snapshot(); var refused = g.complete();
        assertEquals(Status.IDENTITY_CONFLICT, refused.status()); assertEquals(drifted, g.chain.store.snapshot());
        assertNull(refused.receipt()); referenceOnly(refused);
    }

    @Test void failureAfterPaymentRowsBeforeGenericDomainCommitPreservesWholeSnapshot() {
        var store = new VirtualGrantTransactionJournalTest.FaultStore(); var f = new PaymentFixture(store);
        var before = store.snapshot(); store.failOnDomain = true;
        var outcome = f.complete(); referenceOnly(outcome);
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION, outcome.status()); assertNull(outcome.receipt());
        assertEquals(before, store.snapshot()); assertFalse(store.snapshot().containsKey(PAYMENTS));
        assertEquals(1, f.facts.resolutions);
    }

    @Test void exactPendingGlobalIdentityIsUnknownAndOtherOperationIsConflictBeforeResolve() {
        for (boolean exact : List.of(true, false)) {
            var f = new PaymentFixture(); var i = f.command.stage().identity();
            new ActionJournal(f.chain.store).reservedTransaction(tx -> {
                tx.reserve(new ActionJournal.ActionIdentity(i.actorId(), i.globalRequestId(),
                        exact ? i.operation() : "SYNTHETIC_OTHER", exact ? fingerprint(i) : "f".repeat(64)), id(980));
                return null;
            });
            var before = f.chain.store.snapshot(); var outcome = f.complete(); referenceOnly(outcome);
            assertEquals(exact ? Status.RECONCILIATION_UNCONFIRMED : Status.IDENTITY_CONFLICT, outcome.status());
            assertNull(outcome.receipt()); assertEquals(1, f.facts.checks); assertEquals(0, f.facts.resolutions);
            assertEquals(before, f.chain.store.snapshot());
        }
    }

    @Test void newRequestForAlreadyConsumedPaymentCannotCreateAnotherConsumption() throws Exception {
        var f = new PaymentFixture(); f.complete(); var before = f.chain.store.snapshot();
        var conflict = f.service.completePayment(f.chain.context, newRequest(f)); referenceOnly(conflict);
        assertEquals(Status.IDENTITY_CONFLICT, conflict.status()); assertNull(conflict.receipt());
        assertEquals(before, f.chain.store.snapshot()); assertEquals(1, f.chain.store.snapshot().get(PAYMENTS).size());
    }

    @Test void postCommitUncertaintyBlocksAlternateRequestUntilExactReconciliation() throws Exception {
        var store = new VirtualGrantTransactionJournalTest.FaultStore(); var f = new PaymentFixture(store);
        store.failAfterCommit = true; var uncertain = f.complete(); referenceOnly(uncertain);
        assertEquals(Status.COMMIT_UNKNOWN, uncertain.status()); assertEquals(EffectKnowledge.UNKNOWN, uncertain.effectKnowledge());
        assertNull(uncertain.receipt()); assertEquals(1, store.snapshot().get(PAYMENTS).size());
        var committed = store.snapshot();
        var blocked = f.service.completePayment(f.chain.context, newRequest(f));
        assertEquals(Status.RECONCILIATION_UNCONFIRMED, blocked.status()); assertEquals(EffectKnowledge.UNKNOWN, blocked.effectKnowledge());
        assertEquals(1, f.facts.resolutions); assertEquals(committed, store.snapshot());
        var replay = f.service.reconcile(f.chain.context, f.command); referenceOnly(replay);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS, replay.status()); assertEquals(1, f.facts.resolutions);
        assertEquals(committed, store.snapshot());
    }

    @Test void prePublicationFailureRemainsUnknownAcrossJournalInstancesWithoutRetry() {
        var store = new VirtualGrantTransactionJournalTest.FaultStore(); var f = new PaymentFixture(store);
        var before = store.snapshot(); store.failBeforeCommit = true;
        var uncertain = f.complete(); assertEquals(Status.COMMIT_UNKNOWN, uncertain.status()); referenceOnly(uncertain);
        assertEquals(before, store.snapshot());
        var replacement = new SyntheticMockPaymentTransactionService(VirtualGrantTransactionJournal.detachedReference(store, () -> id(990), 65536), f.facts);
        var blocked = replacement.completePayment(f.chain.context, f.command);
        assertEquals(Status.RECONCILIATION_UNCONFIRMED, blocked.status()); assertEquals(EffectKnowledge.UNKNOWN, blocked.effectKnowledge());
        assertNull(blocked.receipt()); assertEquals(1, f.facts.resolutions); assertEquals(before, store.snapshot());
        assertEquals(Status.RECONCILIATION_UNCONFIRMED, replacement.reconcile(f.chain.context, f.command).status());
    }

    @Test void paymentCannotUseNegativeAgentResultOrAutomaticallyAcquireAnotherChild() {
        var f = new PaymentFixture(); var before = f.chain.store.snapshot();
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,
                f.chain.service.completeStage(f.chain.context, f.command.stage(), prepared(940, BusinessConclusion.NEGATIVE)).status());
        assertEquals(before, f.chain.store.snapshot());
        var paid = f.complete(); referenceOnly(paid);
        assertEquals(BusinessConclusion.POSITIVE, paid.receipt().result().businessConclusion());
        assertEquals(RECEIPT_BINDING_PROFILE, paid.receipt().result().bindingProfile());
        var committed = f.chain.store.snapshot();
        assertFalse(committed.get("virtual_grant_profile_results").get(f.domain.paymentId().toString()).containsKey("status"));
        var extra = f.chain.child(950, AllowedAction.EXECUTE_MOCK_PAYMENT);
        assertEquals(Status.IDENTITY_CONFLICT,
                f.chain.service.issueSuccessor(f.chain.context, command(960, extra), f.payment.grantId(), extra).status());
        assertEquals(committed, f.chain.store.snapshot());
        assertEquals(3, committed.get("virtual_grant_profile_grants").size());
        assertEquals(2, committed.get("virtual_grant_profile_successors").size());
    }
}
