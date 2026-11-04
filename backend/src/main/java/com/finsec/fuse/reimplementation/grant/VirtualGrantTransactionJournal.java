package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane;
import com.finsec.fuse.reimplementation.simulation.VirtualGrantWorkflowControl;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.PreparationCommand;
import com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.PreparedInput;
import com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.PreparationReceipt;
import com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.PreparationOutcome;
import com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.PreparationEffect;
import com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.FreshBindings;
import com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.ResolvedPreparation;
import com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.Refusal;
import com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.Decision;
import com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.SourceCoordinate;
import com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.ContinuationCommand;
import com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.ContinuationReceipt;
import com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.ContinuationOutcome;
import com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.ContinuationEffect;
import com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.ContinuationKind;
import com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.ResolvedContinuation;
import com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.PriorExpectation;
import com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.ExistingHead;
import com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.OriginalGenerationOne;
import com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.PendingDisposition;
import com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.ResumeReadiness;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;
import com.finsec.fuse.reimplementation.auth.SyntheticMockPaymentReceiptCodec;

/**
 * Explicit in-process reference only. Shares the supplied store's actual ActionJournal
 * namespace. No durable outcome, restart recovery or actual current trust is provided.
 */
public final class VirtualGrantTransactionJournal implements OwnedTypedContinuationPort {
    private static final String GRANTS = "virtual_grant_profile_grants", RECEIPTS = "virtual_grant_profile_receipts",
            RESULTS = "virtual_grant_profile_results", DOMAIN = "virtual_grant_profile_domain",
            BY_GRANT = "virtual_grant_profile_by_grant", BY_ACTION = "virtual_grant_profile_by_action",
            BY_TARGET = "virtual_grant_profile_by_target", DOMAIN_LINKS = "virtual_grant_profile_domain_links", SUCCESSORS = "virtual_grant_profile_successors";
    private static final String PLAN_RECEIPTS = "virtual_grant_profile_plan_receipts", PLAN_APPROVALS = "virtual_grant_profile_review_approvals";
    private static final String EVALUATION_REFUSALS = "virtual_grant_profile_evaluation_refusals";
    private static final String PREPARATION_RECEIPTS = "virtual_grant_profile_preparation_receipts";
    private static final String PAYMENT_RISK = "virtual_grant_profile_payment_risk_reservations";
    private static final String TARGET_BINDINGS = "virtual_grant_profile_target_bindings";
    private static final String ROOT_RECEIPTS = "virtual_grant_profile_root_receipts", ROOT_MATERIAL = "virtual_grant_profile_root_material";
    private static final String MP_PLANS = "virtual_grant_profile_payment_plans", MP_PAYMENTS = "virtual_grant_profile_payments";
    private final TransactionalStore store;
    private final ActionJournal journal;
    private final Supplier<UUID> tokens;
    private final int maxReceiptBytes;
    private enum Context { APPLICATION, DETACHED_REFERENCE }
    private final Context context;
    private static final Map<TransactionalStore, EpochState> EPOCHS = new java.util.IdentityHashMap<>();
    private record UnknownBinding(StageCommand command, UUID parent) { }
    private record PlanAttempt(com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity identity,
                               PlanOperation purpose, UUID approvalId, UUID reservationId) { }
    private static final class EpochState {
        final Map<UUID, UnknownBinding> attempts = new LinkedHashMap<>();
        final Map<UUID, RootCommand> rootAttempts = new LinkedHashMap<>();
        final Map<UUID, PlanAttempt> planAttempts = new LinkedHashMap<>();
        final Map<UUID, ContinuationCommand> continuationAttempts = new LinkedHashMap<>();
        boolean active;
    }

    // Shared negative-only barrier for this exact in-process store object. The actual
    // command namespace remains ActionJournal's table, not these uncertainty sets.
    private final EpochState epoch;

    public VirtualGrantTransactionJournal(TransactionalStore store, Supplier<UUID> tokens, int maxReceiptBytes) {
        this(store, tokens, maxReceiptBytes, Context.APPLICATION);
    }

    /** Explicit isolated reference namespace, never eligibility for an actual application workflow. */
    public static VirtualGrantTransactionJournal detachedReference(TransactionalStore store,
                                                                   Supplier<UUID> tokens, int maxReceiptBytes) {
        return new VirtualGrantTransactionJournal(store, tokens, maxReceiptBytes, Context.DETACHED_REFERENCE);
    }

    private VirtualGrantTransactionJournal(TransactionalStore store, Supplier<UUID> tokens,
                                           int maxReceiptBytes, Context context) {
        this.context = Objects.requireNonNull(context);
        this.store = Objects.requireNonNull(store); this.tokens = Objects.requireNonNull(tokens);
        if (!VirtualTransactionalStore.MODE.equals(store.mode()) || maxReceiptBytes < 1)
            throw new IllegalArgumentException("INVALID_GRANT_COMMAND");
        this.maxReceiptBytes = maxReceiptBytes; this.journal = new ActionJournal(store);
        synchronized (EPOCHS) { this.epoch = EPOCHS.computeIfAbsent(store, ignored -> new EpochState()); }
    }

    /** Structural construction context only; never authentication or current authority. */
    public void requireApplicationContext() {
        if (context != Context.APPLICATION) throw new IllegalStateException("OWNED_GRANT_APPLICATION_CONTEXT_REQUIRED");
    }

    private void requireReferenceFixture() {
        if (context != Context.DETACHED_REFERENCE)
            throw new IllegalStateException("OWNED_GRANT_REFERENCE_FIXTURE_ONLY");
    }

    private void requireBusinessLane(TransactionalStore.Tx tx, UUID workflowId, int generation, String customerId) {
        var scope = new VirtualWorkflowLane.Scope(workflowId, generation, customerId);
        if (context == Context.APPLICATION) {
            VirtualWorkflowLane.requireTyped(tx, scope);
            VirtualGrantWorkflowControl.requireCurrent(tx, scope);
        } else if (tx.get("virtual_workflows", workflowId.toString()) != null
                || tx.get("virtual_workflow_lanes", workflowId.toString()) != null) {
            throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
        }
    }

    private void requireHistoricalLane(TransactionalStore.Tx tx, StageCommand command) {
        var i = command.identity();
        if (context != Context.APPLICATION) { requireBusinessLane(tx, command); return; }
        VirtualGrantGenerationHistory.validate(tx, new VirtualWorkflowLane.Scope(i.workflowId(), i.generation(), i.customerId()));
        var current = tx.get("virtual_workflows", i.workflowId().toString());
        if (current == null || !(current.get("generation") instanceof Integer generation)
                || !i.customerId().equals(current.get("customerId"))) throw stop(Status.RECONCILIATION_UNCONFIRMED);
        VirtualGrantGenerationHistory.requireCurrent(tx,
                new VirtualWorkflowLane.Scope(i.workflowId(), generation, i.customerId()));
    }
    private void requireHistoricalArtifact(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope, UUID target, UUID result) {
        if (context == Context.APPLICATION) VirtualGrantWorkflowControl.requireHistoricalDisclosure(tx, scope, target, result);
    }
    private static void requireWorkflowDisclosure(TransactionalStore.Tx tx, UUID workflowId) {
        for (var hold : tx.rows("virtual_quarantines").values()) if ("ACTIVE".equals(hold.get("status"))) {
            var target = new com.finsec.fuse.reimplementation.simulation.VirtualQuarantineService.Target(
                    com.finsec.fuse.reimplementation.simulation.VirtualQuarantineService.Scope.valueOf((String)hold.get("scope")),
                    castMap(hold.get("target")));
            if (target.scope() == com.finsec.fuse.reimplementation.simulation.VirtualQuarantineService.Scope.WORKFLOW
                    && workflowId.toString().equals(target.fields().get("workflowId"))) throw stop(Status.REFUSED_BEFORE_ADMISSION);
        }
    }
    private void requireHistoricalResult(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope, UUID result) {
        if (context != Context.APPLICATION) return;
        TypedReference found = null;
        for (var reference : typedReferences(tx)) if (result.equals(reference.resultId())) {
            if (found != null || !reference.workflowId().equals(scope.workflowId()) || reference.generation()!=scope.generation()
                    || !reference.customerId().equals(scope.customerId())) throw stop(Status.RECONCILIATION_UNCONFIRMED);
            found = reference;
        }
        if (found == null) throw stop(Status.RECONCILIATION_UNCONFIRMED);
        requireHistoricalArtifact(tx,scope,found.targetRunId(),result);
    }

    private void requireBusinessLane(TransactionalStore.Tx tx, StageCommand command) {
        var i = command.identity();
        requireBusinessLane(tx, i.workflowId(), i.generation(), i.customerId());
    }

    private void requireFreshLane(TransactionalStore.Tx tx, StageCommand command) {
        var workflowId = command.identity().workflowId();
        if (epoch.continuationAttempts.values().stream().anyMatch(previous -> previous.identity().workflowId().equals(workflowId))
                || epoch.attempts.values().stream().anyMatch(previous -> previous.command().identity().workflowId().equals(workflowId))
                || epoch.planAttempts.values().stream().anyMatch(previous -> previous.identity().workflowId().equals(workflowId))
                || epoch.rootAttempts.values().stream().anyMatch(previous -> previous.identity().workflowId().equals(workflowId)))
            throw stop(Status.RECONCILIATION_UNCONFIRMED);
        requireBusinessLane(tx, command);
        if (context == Context.APPLICATION) {
            var i = command.identity();
            VirtualGrantWorkflowControl.requireFreshBusiness(tx,
                    new VirtualWorkflowLane.Scope(i.workflowId(), i.generation(), i.customerId()));
        }
    }

    /** Explicit synthetic fixture admission, never real issuance or an automatic seed. */
    public void seedSyntheticRoot(GrantSnapshot grant) {
        requireReferenceFixture();
        Objects.requireNonNull(grant);
        if (grant.state() != GrantState.ISSUED || grant.action() != AllowedAction.EVALUATE_KYC)
            throw new IllegalArgumentException("INVALID_GRANT_COMMAND");
        synchronized (epoch) {
            if (epoch.active) throw new IllegalStateException("OWNED_GRANT_TRANSACTION_UNAVAILABLE");
            store.transaction(tx -> {
                requireBusinessLane(tx, grant.workflowId(), grant.generation(), grant.customerId());
                uniqueGrant(tx, grant); tx.put(GRANTS, grant.grantId().toString(), grantMap(grant)); return null;
            });
        }
    }

    /** Explicit synthetic reserved-domain fixture only; never real payment state. */
    public void seedSyntheticPaymentDomain(PaymentDomain domain) {
        requireReferenceFixture();
        Objects.requireNonNull(domain);
        if (domain.reservationState() != ReservationState.RESERVED || domain.approvalState() != ApprovalState.RESERVED)
            throw SyntheticMockPaymentTransactionBinding.invalid();
        synchronized (epoch) {
            if (epoch.active) throw new IllegalStateException("OWNED_GRANT_TRANSACTION_UNAVAILABLE");
            store.transaction(tx -> {
                requireBusinessLane(tx, domain.workflowId(), domain.generation(), domain.customerId());
                var row = tx.get(GRANTS, domain.grantId().toString());
                if (row == null) throw SyntheticMockPaymentTransactionBinding.invalid();
                GrantSnapshot grant = decodeGrant(row);
                if (grant.action() != AllowedAction.EXECUTE_MOCK_PAYMENT || grant.state() != GrantState.ISSUED
                        || !domain.actionId().equals(grant.actionId()) || !domain.targetRunId().equals(grant.targetRunId())
                        || !domain.workflowId().equals(grant.workflowId()) || domain.generation() != grant.generation()
                        || !domain.customerId().equals(grant.customerId()) || tx.get(MP_PLANS, domain.reservationId().toString()) != null
                        || tx.rows(MP_PLANS).values().stream().anyMatch(plan -> domain.paymentId().toString().equals(plan.get("paymentId"))
                            || domain.approvalId().toString().equals(plan.get("approvalId")))) throw SyntheticMockPaymentTransactionBinding.invalid();
                tx.put(MP_PLANS, domain.reservationId().toString(), paymentDomainMap(domain)); return null;
            });
        }
    }

    @Override public StageOutcome transact(StageCommand command, Work work) {
        Objects.requireNonNull(command); Objects.requireNonNull(work);
        synchronized (epoch) {
            if (epoch.active) return StageOutcome.of(Status.UNCONFIRMED_BEFORE_ADMISSION, null,
                    EffectKnowledge.NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION);
            epoch.active = true;
            try { return ownedTransaction(command, work); }
            finally { epoch.active = false; }
        }
    }
    private StageOutcome ownedTransaction(StageCommand command, Work work) {
        boolean[] callbackReturned = {false};
        Facade[] observed = {null};
        try {
            return journal.reservedTransaction(tx -> {
                Facade owned = new Facade(tx, command); observed[0] = owned;
                try {
                    StageOutcome result = Objects.requireNonNull(work.apply(owned));
                    if (result.receipt() != null && result.receipt() != owned.emitted
                            || result.evaluationRefusal() != null && result.evaluationRefusal() != owned.emittedRefusal)
                        throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
                    if (owned.emittedRefusal != null) {
                        if (result.status() != Status.REFUSED_BEFORE_ADMISSION || result.receipt() != null
                                || result.evaluationRefusal() != owned.emittedRefusal
                                || result.effectKnowledge() != EffectKnowledge.NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION
                                || !(owned.completed || owned.replayed)) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
                    } else if ((owned.completed && (result.status() != Status.VIRTUAL_COMMITTED_IN_PROCESS
                                || result.receipt() != owned.emitted || result.effectKnowledge() != EffectKnowledge.COMMITTED_IN_PROCESS))
                            || (owned.replayed && (result.status() != Status.VIRTUAL_REPLAYED_IN_PROCESS
                                || result.receipt() != owned.emitted || result.effectKnowledge() != EffectKnowledge.COMMITTED_IN_PROCESS))
                            || (result.status() == Status.VIRTUAL_COMMITTED_IN_PROCESS && !owned.completed)
                            || (result.status() == Status.VIRTUAL_REPLAYED_IN_PROCESS && !owned.replayed)
                            || (owned.admitted && !owned.completed)) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
                    callbackReturned[0] = true;
                    return result;
                } finally { owned.open = false; }
            });
        } catch (RuntimeException failure) {
            if (callbackReturned[0] && observed[0] != null && observed[0].completed) {
                epoch.attempts.put(command.identity().globalRequestId(),
                        new UnknownBinding(command, observed[0] == null ? null : observed[0].parentAttempt));
                return StageOutcome.of(Status.COMMIT_UNKNOWN, null, EffectKnowledge.UNKNOWN);
            }
            if (callbackReturned[0])
                return StageOutcome.of(Status.RECONCILIATION_UNCONFIRMED, null, EffectKnowledge.UNKNOWN);
            if (failure instanceof Stop stopped) return StageOutcome.of(stopped.status, null,
                    (stopped.status == Status.RECONCILIATION_UNCONFIRMED || stopped.status == Status.TRANSACTION_INVARIANT_UNCONFIRMED)
                            ? EffectKnowledge.UNKNOWN
                            : EffectKnowledge.NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION);
            if (failure instanceof ActionJournal.ActionConflictException)
                return StageOutcome.of(Status.IDENTITY_CONFLICT, null, EffectKnowledge.NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION);
            if (failure instanceof ActionJournal.PendingActionException)
                return StageOutcome.of(Status.RECONCILIATION_UNCONFIRMED, null, EffectKnowledge.UNKNOWN);
            return StageOutcome.of(Status.UNCONFIRMED_BEFORE_ADMISSION, null,
                    EffectKnowledge.NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION);
        }
    }

    @Override public ContinuationOutcome continueWorkflow(ContinuationCommand command, ContinuationWork work) {
        Objects.requireNonNull(command); Objects.requireNonNull(work);
        if (context != Context.APPLICATION) return continuationFailure(Status.UNCONFIRMED_BEFORE_ADMISSION, false);
        synchronized (epoch) {
            if (epoch.active) return continuationFailure(Status.UNCONFIRMED_BEFORE_ADMISSION, false);
            epoch.active = true;
            boolean[] returned = {false}; ContinuationFacade[] observed = {null};
            try {
                return journal.reservedTransaction(tx -> {
                    var owned = new ContinuationFacade(tx, command); observed[0] = owned;
                    try {
                        var result = Objects.requireNonNull(work.apply(owned));
                        if (result.receipt() != owned.emitted
                                || owned.completed && (result.status() != Status.VIRTUAL_COMMITTED_IN_PROCESS
                                    || result.effectKnowledge() != ContinuationEffect.COMMITTED_IN_PROCESS)
                                || owned.replayed && (result.status() != Status.VIRTUAL_REPLAYED_IN_PROCESS
                                    || result.effectKnowledge() != ContinuationEffect.COMMITTED_IN_PROCESS)
                                || result.status() == Status.VIRTUAL_COMMITTED_IN_PROCESS && !owned.completed
                                || result.status() == Status.VIRTUAL_REPLAYED_IN_PROCESS && !owned.replayed
                                || owned.admitted && !owned.completed) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
                        if (!owned.completed) throw new ContinuationRead(result);
                        returned[0] = true; return result;
                    } finally { owned.open = false; }
                });
            } catch (RuntimeException failure) {
                if (failure instanceof ContinuationRead read) return read.outcome;
                if (returned[0] && observed[0] != null && observed[0].completed) {
                    epoch.continuationAttempts.put(command.identity().globalRequestId(), command);
                    return continuationFailure(Status.COMMIT_UNKNOWN, true);
                }
                if (returned[0]) return continuationFailure(Status.RECONCILIATION_UNCONFIRMED, true);
                if (failure instanceof Stop stopped) return continuationFailure(stopped.status,
                        stopped.status == Status.RECONCILIATION_UNCONFIRMED || stopped.status == Status.TRANSACTION_INVARIANT_UNCONFIRMED
                        || stopped.status == Status.COMMIT_UNKNOWN || stopped.status == Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH);
                if (failure instanceof ActionJournal.ActionConflictException) return continuationFailure(Status.IDENTITY_CONFLICT, false);
                if (failure instanceof ActionJournal.PendingActionException) return continuationFailure(Status.RECONCILIATION_UNCONFIRMED, true);
                return continuationFailure(Status.UNCONFIRMED_BEFORE_ADMISSION, false);
            } finally { epoch.active = false; }
        }
    }
    private static final class ContinuationRead extends RuntimeException {
        private final ContinuationOutcome outcome;
        private ContinuationRead(ContinuationOutcome outcome) { super("CONTINUATION_READ_ONLY",null,false,false);this.outcome=outcome; }
    }
    private static ContinuationOutcome continuationFailure(Status status, boolean uncertain) {
        if (status == Status.VIRTUAL_COMMITTED_IN_PROCESS || status == Status.VIRTUAL_REPLAYED_IN_PROCESS) {
            status = Status.UNCONFIRMED_BEFORE_ADMISSION; uncertain = false;
        }
        return new ContinuationOutcome(status, null, uncertain ? ContinuationEffect.UNKNOWN
                : ContinuationEffect.NO_NEW_CONTINUATION_ATTEMPT_THIS_INVOCATION);
    }
    private static StageCommand continuationStage(ContinuationCommand c) {
        return new StageCommand(c.identity(), AllowedAction.EVALUATE_KYC);
    }
    private static Map<String,Object> continuationPrior(PriorExpectation prior) {
        var scope = prior.scope();
        var row = map("kind", prior instanceof ExistingHead ? "EXISTING_HEAD" : "ORIGINAL_GENERATION_ONE",
                "workflowId", scope.workflowId().toString(), "generation", scope.generation(), "customerId", scope.customerId(),
                "rootGrantId", prior.rootGrantId().toString(), "revision", prior.revision());
        if (prior instanceof OriginalGenerationOne original) {
            row.put("rootRequestId", original.rootRequestId().toString());
            row.put("rootTargetRunId", original.rootTargetRunId().toString());
        }
        return row;
    }
    private static Map<String,Object> continuationRootOrigin(ContinuationCommand c) {
        var p = c.newRoot().profile(); var prepared = c.newRoot().prepared(); var a = c.application();
        var d = a.source(); var r = c.originalTerms(); var agents = new LinkedHashMap<String,Object>();
        for (var entry : c.stageAgents().entrySet()) agents.put(entry.getKey().name(),
                map("agentId", entry.getValue().agentId(), "agentVersion", entry.getValue().version()));
        var material = map("profile", map("claimsMaxUtf8Bytes", p.claimsMaxUtf8Bytes(), "actionMaxUtf8Bytes", p.actionMaxUtf8Bytes(),
                "jsonDepthMax", p.jsonDepthMax(), "fieldsPerObjectMax", p.fieldsPerObjectMax(),
                "stringMaxUtf16CodeUnits", p.stringMaxUtf16CodeUnits(), "ttlSecondsMax", p.ttlSecondsMax()),
                "claimsBytes", HexFormat.of().formatHex(prepared.claimsBytes()), "actionBytes", HexFormat.of().formatHex(prepared.actionBytes()),
                "unsignedFrame", HexFormat.of().formatHex(prepared.unsignedFrame()), "payloadSha256", prepared.payloadSha256());
        var safePlan = map("workflowId", c.identity().workflowId().toString(), "generation", c.identity().generation(),
                "laneReference", c.laneReference(), "targetRunId", c.identity().targetRunId().toString(), "stageAgents", agents,
                "application", map("fixtureId", a.fixtureId(), "businessReference", a.businessReference(), "customerId", a.customerId(),
                    "amountKrw", a.amountKrw(), "payoutAccountId", a.payoutAccountId().toString(), "monthlyIncomeKrw", a.monthlyIncomeKrw(),
                    "maxLoanAmountKrw", a.maxLoanAmountKrw(), "ownsActiveAccount", a.ownsActiveAccount(),
                    "source", map("documentId", d.documentId().toString(), "documentVersion", d.documentVersion(),
                        "contentHash", d.contentHash(), "reviewedSafe", d.reviewedSafe())),
                "riskTerms", map("policyVersion", r.policyVersion(), "kycPoints", r.kycPoints(), "loanPoints", r.loanPoints(),
                    "payPoints", r.payPoints(), "baseLimit", r.baseLimit(), "additionalApprovalLimit", r.additionalApprovalLimit(),
                    "maxAutomaticKycRuns", r.maxAutomaticKycRuns(), "approvalLifetime", r.approvalLifetime().toString()));
        return map("recordVersion", 1, "recordProfile", "VIRTUAL_TYPED_CONTINUATION_ROOT_1",
                "identity", identityMap(c.identity()), "unsignedRootMaterial", material, "workflowPlan", safePlan);
    }
    private static String continuationFingerprint(ContinuationCommand c) {
        return CanonicalJson.sha256(map("purpose", "TYPED_CONTINUATION", "rootOrigin", continuationRootOrigin(c),
                "prior", continuationPrior(c.prior()), "observedAt", c.observedAt().toString()));
    }
    private static ActionJournal.ActionIdentity continuationIdentity(ContinuationCommand c) {
        var i = c.identity(); return new ActionJournal.ActionIdentity(i.actorId(), i.globalRequestId(), i.operation(), continuationFingerprint(c));
    }
    private static Map<String,Object> continuationReceiptMap(ContinuationCommand c, ContinuationKind kind) {
        var origin = continuationRootOrigin(c); origin.put("commandFingerprint", continuationFingerprint(c));
        return map("recordVersion", 1, "recordProfile", "VIRTUAL_TYPED_CONTINUATION_RECEIPT_1", "kind", kind.name(),
                "identity", identityMap(c.identity()), "prior", continuationPrior(c.prior()), "observedAt", c.observedAt().toString(),
                "requestedRoot", continuationRootOrigin(c), "rootOrigin", kind == ContinuationKind.ADVANCED ? origin : null,
                "committedGeneration", kind == ContinuationKind.ADVANCED ? c.identity().generation() : c.prior().scope().generation(),
                "publishedHeadRevision", kind == ContinuationKind.ADVANCED ? c.nextRevision() : null);
    }

    private final class ContinuationFacade implements OwnedContinuationTx {
        private final ActionJournal.ReservedTx tx; private final ContinuationCommand command;
        private final Thread owner = Thread.currentThread();
        private boolean open = true, lookedUp, admitted, completed, replayed;
        private UUID token; private ContinuationReceipt emitted;
        private SyntheticTypedContinuationBinding.CurrentBindings ticket;
        ContinuationFacade(ActionJournal.ReservedTx tx, ContinuationCommand command) { this.tx=tx; this.command=command; }
        private void bound(ContinuationCommand value) {
            if (!open || owner != Thread.currentThread()) throw new IllegalStateException("OWNED_CONTINUATION_TRANSACTION_UNAVAILABLE");
            if (!command.equals(value)) throw stop(Status.IDENTITY_CONFLICT);
        }
        private void pending() {
            if (!admitted || completed) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            tx.requirePending(continuationIdentity(command), token);
        }
        @Override public ContinuationReceipt lookupExactContinuation(ContinuationCommand c) {
            bound(c); if (admitted || completed) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION); lookedUp=true;
            var saved=tx.completed(continuationIdentity(c));
            var local=tx.get("virtual_grant_profile_continuation_receipts",c.identity().globalRequestId().toString());
            if (saved==null) {
                if (local!=null || epoch.continuationAttempts.containsKey(c.identity().globalRequestId()))
                    throw stop(Status.RECONCILIATION_UNCONFIRMED);
                return null;
            }
            var payload=new LinkedHashMap<String,Object>(saved);
            if (!c.identity().globalRequestId().toString().equals(payload.remove("requestId"))
                    || !(payload.remove("replayed") instanceof Boolean) || !payload.equals(local)) throw stop(Status.IDENTITY_CONFLICT);
            ContinuationKind kind;
            try { kind=ContinuationKind.valueOf((String)payload.get("kind")); }
            catch (RuntimeException invalid) { throw stop(Status.RECONCILIATION_UNCONFIRMED); }
            if (!continuationReceiptMap(c,kind).equals(payload)) throw stop(Status.IDENTITY_CONFLICT);
            var workflow=tx.get("virtual_workflows",c.identity().workflowId().toString());
            if(workflow==null || !c.identity().workflowId().toString().equals(workflow.get("workflowId"))
                    || !c.identity().customerId().equals(workflow.get("customerId"))
                    || !(workflow.get("generation") instanceof Integer actualGeneration) || actualGeneration<1)
                throw stop(Status.RECONCILIATION_UNCONFIRMED);
            VirtualGrantGenerationHistory.requireCurrent(tx,new VirtualWorkflowLane.Scope(c.identity().workflowId(),
                    actualGeneration,c.identity().customerId()));
            var historical=VirtualGrantGenerationHistory.validate(tx,kind==ContinuationKind.ADVANCED?c.requestedScope():c.prior().scope());
            if (kind==ContinuationKind.ADVANCED && (!historical.rootGrantId().equals(c.identity().grantId())
                    || !historical.rootRequestId().equals(c.identity().globalRequestId()))) throw stop(Status.RECONCILIATION_UNCONFIRMED);
            if (kind==ContinuationKind.ADVANCED) requireHistoricalArtifact(tx,c.requestedScope(),c.identity().targetRunId(),null);
            else requireWorkflowDisclosure(tx,c.identity().workflowId());
            epoch.continuationAttempts.remove(c.identity().globalRequestId());
            replayed=true; emitted=new ContinuationReceipt(1,kind,c); return emitted;
        }
        @Override public void admitFreshContinuation(ContinuationCommand c) {
            bound(c); if (!lookedUp || admitted || completed || replayed) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            for (var previous:epoch.continuationAttempts.values()) if (previous.identity().workflowId().equals(c.identity().workflowId()))
                throw stop(Status.RECONCILIATION_UNCONFIRMED);
            for (var previous:epoch.attempts.values()) if (previous.command().identity().workflowId().equals(c.identity().workflowId()))
                throw stop(Status.RECONCILIATION_UNCONFIRMED);
            for (var previous:epoch.planAttempts.values()) if (previous.identity().workflowId().equals(c.identity().workflowId()))
                throw stop(Status.RECONCILIATION_UNCONFIRMED);
            for (var previous:epoch.rootAttempts.values()) if (previous.identity().workflowId().equals(c.identity().workflowId()))
                throw stop(Status.RECONCILIATION_UNCONFIRMED);
            current(c); uniqueGrant(tx,new GrantSnapshot(c.identity().grantId(),c.identity().actionId(),c.identity().targetRunId(),
                    c.identity().workflowId(),c.identity().generation(),c.identity().customerId(),AllowedAction.EVALUATE_KYC,GrantState.ISSUED));
            if (tx.get(ROOT_RECEIPTS,c.identity().globalRequestId().toString())!=null
                    || tx.get(ROOT_MATERIAL,c.identity().grantId().toString())!=null) throw stop(Status.IDENTITY_CONFLICT);
            token=Objects.requireNonNull(tokens.get());
            if (tx.reserve(continuationIdentity(c),token).status()!=ActionJournal.ReservationStatus.RESERVED)
                throw stop(Status.RECONCILIATION_UNCONFIRMED);
            admitted=true;
        }
        private VirtualGrantGenerationHistory.GenerationRecord current(ContinuationCommand c) {
            var old=c.prior().scope(); var origin=VirtualGrantGenerationHistory.requireCurrent(tx,old);
            var head=VirtualGrantGenerationHistory.readHead(tx,old.workflowId());
            if (c.prior() instanceof ExistingHead e) {
                if (!e.expected().equals(head)) throw stop(Status.IDENTITY_CONFLICT);
            } else if (c.prior() instanceof OriginalGenerationOne g) {
                if (head!=null || origin.observedAt()!=null || !g.rootRequestId().equals(origin.rootRequestId())
                        || !g.rootTargetRunId().equals(origin.rootTargetRunId())) throw stop(Status.IDENTITY_CONFLICT);
            } else throw stop(Status.IDENTITY_CONFLICT);
            if (!origin.rootGrantId().equals(c.prior().rootGrantId()) || !origin.terms().equals(c.originalTerms()))
                throw stop(Status.IDENTITY_CONFLICT);
            VirtualGrantWorkflowControl.requireContinuationClear(tx,old,c.application().source().documentId(),
                    c.application().source().documentVersion(),c.stageAgents());
            return origin;
        }
        private SyntheticTypedContinuationBinding.CurrentBindings observe(ContinuationCommand c) {
            var origin=current(c);var old=c.prior().scope();var row=tx.get("virtual_workflows",old.workflowId().toString());
            if (row==null || !("BLOCKED".equals(row.get("state")) || "ON_HOLD".equals(row.get("state"))))
                throw stop(Status.REFUSED_BEFORE_ADMISSION);
            for (var domain:committedPaymentDomains(tx)) if (domain.workflowId().equals(old.workflowId()))
                throw stop(Status.REFUSED_BEFORE_ADMISSION);
            var counters=VirtualGrantHistoricalAccounting.readAggregate(tx,old);
            var disposition=observePending(c,counters);
            var readiness=(row.get("activeJobId")!=null || !c.application().source().reviewedSafe()
                    || counters.kycRuns()>=origin.terms().maxAutomaticKycRuns())
                    ?ResumeReadiness.KNOWN_NOT_READY:ResumeReadiness.READY;
            return new SyntheticTypedContinuationBinding.CurrentBindings(origin,VirtualGrantGenerationHistory.readHead(tx,old.workflowId()),
                    new SourceCoordinate(uuid(row,"documentId"),(Integer)row.get("documentVersion")),(String)row.get("businessReference"),
                    (Long)row.get("amountKrw"),uuid(row,"payoutAccountId"),(String)row.get("state"),
                    row.get("activeJobId")==null?null:uuid(row,"activeJobId"),counters,disposition,readiness);
        }
        @Override public SyntheticTypedContinuationBinding.CurrentBindings readContinuationBindings(ContinuationCommand c) {
            bound(c);pending();if(ticket==null)ticket=observe(c);
            if(ticket.pendingDisposition()==PendingDisposition.UNCONFIRMED)throw stop(Status.RECONCILIATION_UNCONFIRMED);
            return ticket;
        }
        private PendingDisposition observePending(ContinuationCommand c,VirtualGrantEvaluationAccounting.Counters counters) {
            pending();var own=continuationIdentity(c);boolean ownFound=false;
            for(var identity:tx.pendingIdentities()) {
                if(identity.equals(own)) { if(ownFound)throw stop(Status.RECONCILIATION_UNCONFIRMED);ownFound=true; }
                else return PendingDisposition.UNCONFIRMED;
            }
            if(!ownFound)return PendingDisposition.UNCONFIRMED;
            var groups=new LinkedHashMap<VirtualWorkflowLane.Scope,java.util.ArrayList<PaymentDomain>>();
            for(var entry:tx.rows(MP_PLANS).entrySet()) {
                var plan=decodePaymentDomain(entry.getValue());
                if(!entry.getKey().equals(plan.reservationId().toString()))throw stop(Status.RECONCILIATION_UNCONFIRMED);
                if(!plan.workflowId().equals(c.identity().workflowId()))continue;
                if(plan.reservationState()==ReservationState.COMMITTED)throw stop(Status.REFUSED_BEFORE_ADMISSION);
                if(plan.reservationState()!=ReservationState.RESERVED||plan.approvalState()!=ApprovalState.RESERVED)
                    return PendingDisposition.UNCONFIRMED;
                var scope=new VirtualWorkflowLane.Scope(plan.workflowId(),plan.generation(),plan.customerId());
                if(!scope.customerId().equals(c.identity().customerId()))return PendingDisposition.UNCONFIRMED;
                groups.computeIfAbsent(scope,ignored->new java.util.ArrayList<>()).add(plan);
            }
            long total=0;boolean nonempty=false;
            for(var group:groups.entrySet()) {
                var scope=group.getKey();var terms=VirtualGrantGenerationHistory.validate(tx,scope).terms();
                var evidence=new java.util.ArrayList<TypedContinuationPendingAdmission.ReservationEvidence>();
                var risks=new java.util.ArrayList<TypedContinuationPendingAdmission.RiskReservation>();
                var producers=new java.util.ArrayList<TypedContinuationPendingAdmission.ProducerObservation>();
                int subtotal=0;
                for(var plan:group.getValue()) {
                    requireAccountingReservation(tx,plan.reservationId());
                    if(tx.get(MP_PAYMENTS,plan.paymentId().toString())!=null||tx.get(BY_GRANT,plan.grantId().toString())!=null)
                        return PendingDisposition.UNCONFIRMED;
                    Map<String,Object> reserveRow=null;
                    for(var row:tx.rows(PLAN_RECEIPTS).values())if("RESERVE".equals(row.get("purpose"))&&paymentDomainMap(plan).equals(row.get("domain"))) {
                        if(reserveRow!=null)return PendingDisposition.UNCONFIRMED;reserveRow=row;
                    }
                    if(reserveRow==null)return PendingDisposition.UNCONFIRMED;
                    var reserve=accountingPlanOrigin(tx,reserveRow);var approval=decodeApproval(tx.get(PLAN_APPROVALS,plan.approvalId().toString()));
                    var reviewRow=tx.get(PLAN_RECEIPTS,approval.reviewRequestId().toString());var review=accountingPlanOrigin(tx,reviewRow);
                    var loan=grantRow(tx,review.identity().grantId());var loanIndex=tx.get(BY_GRANT,loan.grantId().toString());
                    if(loanIndex==null)return PendingDisposition.UNCONFIRMED;
                    var loanReceipt=decodeLocal(tx.get(RECEIPTS,(String)loanIndex.get("requestId")));
                    var paymentGrant=grantRow(tx,plan.grantId());var paymentReference=decodeTarget(tx.get(TARGET_BINDINGS,plan.targetRunId().toString()));
                    var loanReference=decodeTarget(tx.get(TARGET_BINDINGS,loan.targetRunId().toString()));
                    var rfp=(String)reviewRow.get("commandFingerprint");var sfp=(String)reserveRow.get("commandFingerprint");
                    evidence.add(new TypedContinuationPendingAdmission.ReservationEvidence(
                        new TypedContinuationPendingAdmission.LocalPlanRecord(review,rfp),
                        new TypedContinuationPendingAdmission.GlobalPlanRecord(review.identity(),rfp,review,TypedContinuationPendingAdmission.GlobalState.COMPLETED),
                        new TypedContinuationPendingAdmission.LocalPlanRecord(reserve,sfp),
                        new TypedContinuationPendingAdmission.GlobalPlanRecord(reserve.identity(),sfp,reserve,TypedContinuationPendingAdmission.GlobalState.COMPLETED),
                        approval,plan,paymentGrant,paymentReference,loan,loanReceipt,loanReference));
                    risks.add(new TypedContinuationPendingAdmission.RiskReservation(plan.reservationId(),plan.paymentId(),plan.approvalId(),
                        plan.grantId(),plan.actionId(),plan.targetRunId(),scope,plan.securityPolicyVersion(),terms.payPoints(),TypedContinuationPendingAdmission.RiskState.RESERVED));
                    producers.add(new TypedContinuationPendingAdmission.ProducerObservation(plan.reservationId(),
                        TypedContinuationPendingAdmission.ProducerState.NO_EXECUTION_OBSERVED,null));
                    subtotal=Math.addExact(subtotal,terms.payPoints());
                }
                int bound=Math.addExact(Math.multiplyExact(evidence.size(),3),1);
                var assessment=TypedContinuationPendingAdmission.assess(new TypedContinuationPendingAdmission.Profile(maxReceiptBytes,bound),
                    TypedContinuationPendingAdmission.Use.FRESH_ADMISSION,new TypedContinuationPendingAdmission.Snapshot(scope,terms,subtotal,evidence,risks,producers,List.of()));
                if(assessment.outcome()!=TypedContinuationPendingAdmission.Outcome.REFUSE_NO_MUTATION)return PendingDisposition.UNCONFIRMED;
                nonempty=true;total+=subtotal;if(total>Integer.MAX_VALUE)return PendingDisposition.UNCONFIRMED;
            }
            if(total!=counters.reservedRisk())return PendingDisposition.UNCONFIRMED;
            if(nonempty)return PendingDisposition.COHERENT_NONEMPTY;
            var empty=TypedContinuationPendingAdmission.assess(new TypedContinuationPendingAdmission.Profile(maxReceiptBytes,maxReceiptBytes),
                TypedContinuationPendingAdmission.Use.FRESH_ADMISSION,new TypedContinuationPendingAdmission.Snapshot(c.prior().scope(),c.originalTerms(),
                    counters.reservedRisk(),List.of(),List.of(),List.of(),List.of()));
            return empty.outcome()==TypedContinuationPendingAdmission.Outcome.EMPTY_EVIDENCE_NOT_AUTHORIZATION
                ?PendingDisposition.VERIFIED_EMPTY:PendingDisposition.UNCONFIRMED;
        }
        private void recheck(ContinuationCommand c,SyntheticTypedContinuationBinding.CurrentBindings supplied) {
            pending(); if(ticket==null || supplied!=ticket)throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            var fresh=observe(c);
            if(!ticket.origin().equals(fresh.origin()) || !Objects.equals(ticket.head(),fresh.head())
                    || !ticket.currentSource().equals(fresh.currentSource()) || !ticket.businessReference().equals(fresh.businessReference())
                    || ticket.amountKrw()!=fresh.amountKrw() || !ticket.payoutAccountId().equals(fresh.payoutAccountId())
                    || !ticket.oldState().equals(fresh.oldState()) || !Objects.equals(ticket.activeJobId(),fresh.activeJobId())
                    || !ticket.counters().equals(fresh.counters()) || ticket.pendingDisposition()!=fresh.pendingDisposition()
                    || ticket.resumeReadiness()!=fresh.resumeReadiness())throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            SyntheticTypedContinuationBinding.checkBindings(c,ticket);
            if(ticket.pendingDisposition()==PendingDisposition.COHERENT_NONEMPTY)throw stop(Status.REFUSED_BEFORE_ADMISSION);
            if(ticket.pendingDisposition()!=PendingDisposition.VERIFIED_EMPTY)throw stop(Status.RECONCILIATION_UNCONFIRMED);
        }
        @Override public ContinuationReceipt recordDeniedContinuation(ContinuationCommand c,SyntheticTypedContinuationBinding.CurrentBindings supplied) {
            bound(c);recheck(c,supplied);
            if(ticket.resumeReadiness()!=ResumeReadiness.KNOWN_NOT_READY)throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            var row=new LinkedHashMap<String,Object>(tx.get("virtual_workflows",c.identity().workflowId().toString()));
            row.put("state","ON_HOLD");row.put("lastDecision","DENY");row.put("reasonCodes",List.of("RESUME_BLOCKED"));
            tx.put("virtual_workflows",c.identity().workflowId().toString(),row);
            return finish(c,ContinuationKind.DENIED);
        }
        @Override public ContinuationReceipt recordContinuation(ContinuationCommand c,ResolvedContinuation resolved) {
            bound(c);if(resolved==null)throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);recheck(c,resolved.currentBindings());
            SyntheticTypedContinuationBinding.checkResolved(c,resolved);
            var i=c.identity();var claims=c.newRoot().claims();var old=c.prior().scope();var next=c.requestedScope();
            var root=new GrantSnapshot(i.grantId(),i.actionId(),i.targetRunId(),i.workflowId(),i.generation(),i.customerId(),AllowedAction.EVALUATE_KYC,GrantState.ISSUED);
            uniqueGrant(tx,root);var agent=c.stageAgents().get(AllowedAction.EVALUATE_KYC);var d=c.application().source();
            if(tx.get(TARGET_BINDINGS,i.targetRunId().toString())!=null || tx.get(ROOT_MATERIAL,i.grantId().toString())!=null)
                throw stop(Status.IDENTITY_CONFLICT);
            tx.put(GRANTS,i.grantId().toString(),grantMap(root));
            tx.put(TARGET_BINDINGS,i.targetRunId().toString(),targetMap(new TypedReference(i.workflowId(),i.generation(),i.customerId(),
                    i.targetRunId(),i.grantId(),i.actionId(),d.documentId(),d.documentVersion(),agent.agentId(),agent.version(),null,null,null)));
            var origin=continuationRootOrigin(c);origin.put("commandFingerprint",continuationFingerprint(c));
            tx.put(ROOT_MATERIAL,i.grantId().toString(),origin);tx.put(ROOT_RECEIPTS,i.globalRequestId().toString(),origin);
            var receipt=finish(c,ContinuationKind.ADVANCED);
            var expected=VirtualGrantGenerationHistory.readHead(tx,i.workflowId());
            if(c.prior() instanceof OriginalGenerationOne g){var o=ticket.origin();
                expected=VirtualGrantGenerationHistory.establishOriginal(tx,new VirtualGrantGenerationHistory.GenerationRecord(o.scope(),
                        o.rootGrantId(),o.rootRequestId(),o.rootTargetRunId(),o.sourceDocId(),o.sourceVersion(),o.terms(),c.observedAt()),g.firstObservedRevision());}
            VirtualGrantGenerationHistory.advance(tx,expected,new VirtualGrantGenerationHistory.GenerationRecord(next,i.grantId(),i.globalRequestId(),
                    i.targetRunId(),d.documentId(),d.documentVersion(),c.originalTerms(),c.observedAt()));
            var row=new LinkedHashMap<String,Object>(tx.get("virtual_workflows",i.workflowId().toString()));var agents=new LinkedHashMap<String,Object>();
            for(var entry:c.stageAgents().entrySet())agents.put(entry.getKey().name(),map("agentId",entry.getValue().agentId(),"agentVersion",entry.getValue().version()));
            row.put("generation",i.generation());row.put("documentId",d.documentId().toString());row.put("documentVersion",d.documentVersion());
            row.put("state","KYC_PENDING");row.put("lastDecision","ALLOW");row.put("reasonCodes",List.of());row.put("activeJobId",null);
            row.put("currentKycResultId",null);row.put("currentLoanResultId",null);row.put("riskLimit",c.originalTerms().baseLimit());row.put("typedStageAgents",agents);
            tx.put("virtual_workflows",i.workflowId().toString(),row);VirtualWorkflowLane.advanceTyped(tx,old,next);
            VirtualGrantGenerationHistory.requireCurrent(tx,next);
            if(!ticket.counters().equals(VirtualGrantHistoricalAccounting.readAggregate(tx,next)))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            return receipt;
        }
        private ContinuationReceipt finish(ContinuationCommand c,ContinuationKind kind){
            var row=continuationReceiptMap(c,kind);
            if(CanonicalJson.write(row).getBytes(java.nio.charset.StandardCharsets.UTF_8).length>maxReceiptBytes
                    ||tx.get("virtual_grant_profile_continuation_receipts",c.identity().globalRequestId().toString())!=null)
                throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            tx.put("virtual_grant_profile_continuation_receipts",c.identity().globalRequestId().toString(),row);
            var reply=new LinkedHashMap<String,Object>(row);reply.put("requestId",c.identity().globalRequestId().toString());reply.put("replayed",false);
            tx.complete(continuationIdentity(c),token,reply);completed=true;emitted=new ContinuationReceipt(1,kind,c);return emitted;
        }
    }

    @Override public RootOutcome provisionRoot(RootCommand command, RootWork work) {
        Objects.requireNonNull(command); Objects.requireNonNull(work);
        if (context != Context.APPLICATION) return new RootOutcome(Status.UNCONFIRMED_BEFORE_ADMISSION,
                null, RootEffect.NO_NEW_ROOT_PROVISION_ATTEMPT_THIS_INVOCATION);
        synchronized (epoch) {
            if (epoch.active) return new RootOutcome(Status.UNCONFIRMED_BEFORE_ADMISSION,
                    null, RootEffect.NO_NEW_ROOT_PROVISION_ATTEMPT_THIS_INVOCATION);
            epoch.active = true;
            boolean[] returned = {false};
            RootFacade[] observed = {null};
            try {
                return journal.reservedTransaction(tx -> {
                    RootFacade owned = new RootFacade(tx, command); observed[0] = owned;
                    try {
                        RootOutcome result = Objects.requireNonNull(work.apply(owned));
                        if ((result.receipt() != null && result.receipt() != owned.emitted)
                                || (owned.completed && (result.status() != Status.VIRTUAL_COMMITTED_IN_PROCESS
                                    || result.receipt() != owned.emitted))
                                || (owned.replayed && (result.status() != Status.VIRTUAL_REPLAYED_IN_PROCESS
                                    || result.receipt() != owned.emitted))
                                || (result.status() == Status.VIRTUAL_COMMITTED_IN_PROCESS && !owned.completed)
                                || (result.status() == Status.VIRTUAL_REPLAYED_IN_PROCESS && !owned.replayed)
                                || (owned.admitted && !owned.completed)) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
                        returned[0] = true;
                        return result;
                    } finally { owned.open = false; }
                });
            } catch (RuntimeException failure) {
                if (returned[0] && observed[0] != null && observed[0].completed) {
                    epoch.attempts.put(command.identity().globalRequestId(), new UnknownBinding(rootStage(command), null));
                    epoch.rootAttempts.put(command.identity().globalRequestId(), command);
                    return new RootOutcome(Status.COMMIT_UNKNOWN, null, RootEffect.UNKNOWN);
                }
                if (returned[0]) return new RootOutcome(Status.RECONCILIATION_UNCONFIRMED, null, RootEffect.UNKNOWN);
                if (failure instanceof ActionJournal.ActionConflictException)
                    return new RootOutcome(Status.IDENTITY_CONFLICT, null, RootEffect.NO_NEW_ROOT_PROVISION_ATTEMPT_THIS_INVOCATION);
                if (failure instanceof ActionJournal.PendingActionException)
                    return new RootOutcome(Status.RECONCILIATION_UNCONFIRMED, null, RootEffect.UNKNOWN);
                if (failure instanceof Stop stopped) return new RootOutcome(stopped.status, null,
                        stopped.status == Status.RECONCILIATION_UNCONFIRMED || stopped.status == Status.TRANSACTION_INVARIANT_UNCONFIRMED
                                ? RootEffect.UNKNOWN : RootEffect.NO_NEW_ROOT_PROVISION_ATTEMPT_THIS_INVOCATION);
                return new RootOutcome(Status.UNCONFIRMED_BEFORE_ADMISSION, null, RootEffect.NO_NEW_ROOT_PROVISION_ATTEMPT_THIS_INVOCATION);
            } finally { epoch.active = false; }
        }
    }

    private final class RootFacade implements OwnedRootTx {
        private final ActionJournal.ReservedTx tx;
        private final RootCommand command;
        private final Thread owner = Thread.currentThread();
        private boolean open = true, lookedUp, admitted, completed, replayed;
        private UUID token;
        private RootReceipt emitted;
        private CurrentBindings ticket;
        RootFacade(ActionJournal.ReservedTx tx, RootCommand command) { this.tx = tx; this.command = command; }
        private void bound(RootCommand value) {
            if (!open || owner != Thread.currentThread()) throw new IllegalStateException("OWNED_ROOT_TRANSACTION_UNAVAILABLE");
            if (!command.equals(value)) throw stop(Status.IDENTITY_CONFLICT);
        }
        @Override public RootReceipt lookupExactRoot(RootCommand value) {
            bound(value);
            if (admitted || completed) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            lookedUp = true;
            var stage = rootStage(value);
            var saved = tx.completed(journalIdentity(stage));
            var local = tx.get(ROOT_RECEIPTS, value.identity().globalRequestId().toString());
            if (saved == null) {
                if (local != null || uncertainRoot(value)) throw stop(Status.RECONCILIATION_UNCONFIRMED);
                return null;
            }
            var expected = rootReceiptMap(value);
            var payload = new LinkedHashMap<String, Object>(saved);
            if (!value.identity().globalRequestId().toString().equals(payload.remove("requestId"))
                    || !(payload.remove("replayed") instanceof Boolean) || !expected.equals(payload)
                    || !expected.equals(local)
                    || !expected.equals(tx.get(ROOT_MATERIAL, value.identity().grantId().toString())))
                throw stop(Status.IDENTITY_CONFLICT);
            var root = grantRow(tx, value.identity().grantId());
            if (root == null || !matches(stage, root)) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            requireHistoricalLane(tx, stage);
            var reference = requireTarget(tx, root);
            if (reference == null || reference.sourceRunId() != null || reference.sourceResultId() != null)
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var workflow = tx.get("virtual_workflows", value.identity().workflowId().toString());
            var app = value.workflowPlan().application();
            if (workflow == null || !app.businessReference().equals(workflow.get("businessReference"))
                    || !Long.valueOf(app.amountKrw()).equals(workflow.get("amountKrw"))
                    || !app.payoutAccountId().toString().equals(workflow.get("payoutAccountId")))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            requireHistoricalArtifact(tx,new VirtualWorkflowLane.Scope(value.identity().workflowId(),value.identity().generation(),
                    value.identity().customerId()),value.identity().targetRunId(),null);
            epoch.attempts.remove(value.identity().globalRequestId());
            epoch.rootAttempts.remove(value.identity().globalRequestId());
            replayed = true; emitted = new RootReceipt(1, value); return emitted;
        }
        @Override public void admitFreshRoot(RootCommand value) {
            bound(value);
            if (!lookedUp || admitted || replayed || uncertainRoot(value)) throw stop(Status.RECONCILIATION_UNCONFIRMED);
            token = Objects.requireNonNull(tokens.get());
            var reservation = tx.reserve(journalIdentity(rootStage(value)), token);
            if (reservation.status() != ActionJournal.ReservationStatus.RESERVED) throw stop(Status.RECONCILIATION_UNCONFIRMED);
            admitted = true;
        }
        private CurrentBindings observe(RootCommand value) {
            var identity = value.identity(); var app = value.workflowPlan().application();
            boolean workflow = tx.get("virtual_workflows", identity.workflowId().toString()) == null;
            boolean business = true;
            for (var entry : tx.rows("virtual_workflows").entrySet()) {
                var row = entry.getValue();
                if (!entry.getKey().equals(uuid(row, "workflowId").toString())
                        || !(row.get("generation") instanceof Integer generation) || generation < 1
                        || !(row.get("customerId") instanceof String customer) || customer.isBlank()
                        || !(row.get("businessReference") instanceof String reference) || reference.isBlank())
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                if (app.businessReference().equals(reference)) business = false;
            }
            boolean lane = tx.get("virtual_workflow_lanes", identity.workflowId().toString()) == null;
            boolean grant = tx.get(GRANTS, identity.grantId().toString()) == null
                    && tx.get(ROOT_MATERIAL, identity.grantId().toString()) == null;
            boolean action = true, target = true;
            for (var entry : tx.rows(GRANTS).entrySet()) {
                var existing = decodeGrant(entry.getValue());
                if (!entry.getKey().equals(existing.grantId().toString())) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                if (identity.actionId().equals(existing.actionId())) action = false;
                if (identity.targetRunId().equals(existing.targetRunId())) target = false;
            }
            for (var reference : typedReferences(tx)) {
                if (identity.actionId().equals(reference.actionId())) action = false;
                if (identity.targetRunId().equals(reference.targetRunId())) target = false;
            }
            return new CurrentBindings(workflow, business, lane, grant, action, target);
        }
        @Override public CurrentBindings readCurrentRootProvisionBindings(RootCommand value) {
            bound(value);
            if (!admitted || completed) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            if (ticket == null) ticket = observe(value);
            return ticket;
        }
        @Override public RootReceipt recordRootAndWorkflow(RootCommand value, ResolvedRootProvision resolved) {
            bound(value);
            if (!admitted || completed || ticket == null || resolved == null || resolved.currentBindings() != ticket
                    || !value.equals(resolved.command()) || !ticket.allAbsent() || !observe(value).allAbsent())
                throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            tx.requirePending(journalIdentity(rootStage(value)), token);
            SyntheticRootProvisionBinding.checkResolved(value, resolved);
            var plan = value.workflowPlan(); var app = plan.application(); var risk = plan.riskTerms();
            if (plan.generation() != 1) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            var agents = new LinkedHashMap<String, Object>();
            for (var entry : plan.stageAgents().entrySet())
                agents.put(entry.getKey().name(), map("agentId", entry.getValue().agentId(), "agentVersion", entry.getValue().version()));
            VirtualWorkflowLane.registerTyped(tx, new VirtualWorkflowLane.Scope(plan.workflowId(), plan.generation(), app.customerId()));
            var workflow = map("workflowId", plan.workflowId().toString(), "generation", 1, "state", "KYC_PENDING",
                    "businessReference", app.businessReference(), "customerId", app.customerId(), "amountKrw", app.amountKrw(),
                    "payoutAccountId", app.payoutAccountId().toString(), "documentId", app.source().documentId().toString(),
                    "documentVersion", app.source().documentVersion(), "usedRisk", 0, "reservedRisk", 0,
                    "riskLimit", risk.baseLimit(), "kycRuns", 0, "currentKycResultId", null, "currentLoanResultId", null,
                    "activeJobId", null, "reasonCodes", List.of(), "lastDecision", "ALLOW", "policyVersion", risk.policyVersion(),
                    "typedStageAgents", agents);
            tx.put("virtual_workflows", plan.workflowId().toString(), workflow);
            var claims = value.inputs().claims();
            var root = new GrantSnapshot(claims.grantId(), claims.actionId(), claims.targetRunId(), claims.workflowId(),
                    claims.generation(), claims.customerId(), claims.allowedAction(), GrantState.ISSUED);
            uniqueGrant(tx, root);
            recordTarget(tx, root, null, null);
            tx.put(GRANTS, root.grantId().toString(), grantMap(root));
            VirtualGrantWorkflowControl.requireCurrent(tx,
                    new VirtualWorkflowLane.Scope(plan.workflowId(), plan.generation(), app.customerId()));
            var row = rootReceiptMap(value);
            if (CanonicalJson.write(row).getBytes(java.nio.charset.StandardCharsets.UTF_8).length > maxReceiptBytes)
                throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            tx.put(ROOT_MATERIAL, root.grantId().toString(), row);
            tx.put(ROOT_RECEIPTS, value.identity().globalRequestId().toString(), row);
            var reply = new LinkedHashMap<String, Object>(row); reply.put("requestId", value.identity().globalRequestId().toString());
            tx.complete(journalIdentity(rootStage(value)), token, reply);
            completed = true; emitted = new RootReceipt(1, value); return emitted;
        }
    }

    /** Package-local safe metadata only; opaque result frames are neither decoded nor returned. */
    record ReadResultMetadata(CommandIdentity identity, TypedReference reference, BusinessConclusion conclusion) { }
    static ReadResultMetadata readResultMetadata(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope,
                                                  UUID resultId, AllowedAction action) {
        TypedReference found=null;
        for(var r:typedReferences(tx))if(resultId.equals(r.resultId())) {
            if(found!=null || !r.workflowId().equals(scope.workflowId()) || r.generation()!=scope.generation()
                    || !r.customerId().equals(scope.customerId()))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            found=r;
        }
        if(found==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var grant=grantRow(tx,found.grantId());
        if(grant==null || grant.action()!=action || grant.state()!=GrantState.CONSUMED
                || !grant.workflowId().equals(found.workflowId()) || grant.generation()!=found.generation()
                || !grant.customerId().equals(found.customerId()) || !grant.actionId().equals(found.actionId())
                || !grant.targetRunId().equals(found.targetRunId())
                || !targetMap(found).equals(tx.get(TARGET_BINDINGS,found.targetRunId().toString()))
                || !grantMap(grant).equals(tx.get(GRANTS,grant.grantId().toString())))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var index=tx.get(BY_GRANT,grant.grantId().toString());
        if(index==null || !index.keySet().equals(java.util.Set.of("requestId")))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var request=uuid(index,"requestId");var local=tx.get(RECEIPTS,request.toString());
        if(local==null || !local.keySet().equals(java.util.Set.of("identity","kind","result","parentGrantId"))
                || !"CONSUMPTION".equals(local.get("kind")) || local.get("parentGrantId")!=null)
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var identity=decodeIdentity(castMap(local.get("identity")));
        if(!request.equals(identity.globalRequestId()) || !matches(new StageCommand(identity,action),grant)
                || !identityMap(identity).equals(local.get("identity")))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        for(var key:new String[][]{{BY_ACTION,grant.actionId().toString()},{BY_TARGET,grant.targetRunId().toString()}})
            if(!index.equals(tx.get(key[0],key[1])))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var saved=completedOwnedRecord(tx,journalIdentity(new StageCommand(identity,action)));
        if(saved==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var global=new LinkedHashMap<String,Object>(saved);
        if(!request.toString().equals(global.remove("requestId")) || !(global.remove("replayed") instanceof Boolean)
                || !global.keySet().equals(local.keySet()) || !global.get("identity").equals(local.get("identity"))
                || !"CONSUMPTION".equals(global.get("kind")) || global.get("parentGrantId")!=null)
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var stored=tx.get(RESULTS,resultId.toString());var projected=castMap(local.get("result"));var globalResult=castMap(global.get("result"));
        var resultKeys=java.util.Set.of("resultId","businessConclusion","bindingProfile","bindingBytes","bindingDigest");
        if(stored==null || !stored.keySet().equals(resultKeys) || !projected.keySet().equals(resultKeys)
                || !globalResult.keySet().equals(resultKeys))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        for(var k:List.of("resultId","businessConclusion","bindingProfile"))
            if(!(stored.get(k) instanceof String) || !stored.get(k).equals(projected.get(k)) || !stored.get(k).equals(globalResult.get(k)))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        if(!resultId.toString().equals(stored.get("resultId")) || ((String)stored.get("bindingProfile")).isBlank())
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var conclusion=BusinessConclusion.valueOf((String)stored.get("businessConclusion"));
        if(conclusion==BusinessConclusion.UNCONFIRMED)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return new ReadResultMetadata(identity,found,conclusion);
    }
    /** Current approval and its original safe Review receipt, without agent body/frame decoding. */
    static ApprovalSnapshot readApprovalMetadata(TransactionalStore.Tx tx, UUID approvalId) {
        var row=tx.get(PLAN_APPROVALS,approvalId.toString());
        if(row==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var approval=decodeApproval(row);
        if(!approvalId.equals(approval.approvalId()) || !approvalMap(approval).equals(row))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var reviewRow=tx.get(PLAN_RECEIPTS,approval.reviewRequestId().toString());
        if(reviewRow==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var review=accountingPlanOrigin(tx,reviewRow);var original=review.approval();
        var state=approval.decision()==ReviewDecision.APPROVE?ApprovalPlanState.AVAILABLE:ApprovalPlanState.REJECTED;
        if(review.purpose()!=PlanOperation.REVIEW || review.domain()!=null || review.riskPoints()!=0
                || original.state()!=state || !approvalMap(withApprovalState(approval,state)).equals(approvalMap(original))
                || !approval.reviewRequestId().equals(review.identity().globalRequestId())
                || !approval.reviewerActorId().equals(review.identity().actorId())
                || !SyntheticMockPaymentPlanBinding.reviewHash(approval.material()).equals(approval.reviewSnapshotHash()))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var scope=approval.material().scope();var loan=readResultMetadata(tx,scope,approval.material().loanResultId(),AllowedAction.CREATE_LOAN_RECOMMENDATION);
        if(!matches(new StageCommand(review.identity(),AllowedAction.CREATE_LOAN_RECOMMENDATION),grantRow(tx,loan.reference().grantId())))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return approval;
    }

    static PaymentDomain readPlanMetadata(TransactionalStore.Tx tx, UUID reservationId) {
        var plan=decodePaymentDomain(tx.get(MP_PLANS,reservationId.toString()));
        if(!reservationId.equals(plan.reservationId()))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        boolean paid=plan.reservationState()==ReservationState.COMMITTED && plan.approvalState()==ApprovalState.CONSUMED;
        if(!paid && !(plan.reservationState()==ReservationState.RESERVED && plan.approvalState()==ApprovalState.RESERVED))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var originalMap=new LinkedHashMap<String,Object>(paymentDomainMap(plan));
        originalMap.put("reservationState","RESERVED");originalMap.put("approvalState","RESERVED");
        var original=decodePaymentDomain(originalMap);Map<String,Object> found=null;
        for(var entry:tx.rows(PLAN_RECEIPTS).entrySet())if("RESERVE".equals(entry.getValue().get("purpose"))
                && originalMap.equals(entry.getValue().get("domain"))) {
            if(found!=null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);found=entry.getValue();
        }
        if(found==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var reserve=accountingPlanOrigin(tx,found);var approval=readApprovalMetadata(tx,plan.approvalId());
        var scope=new VirtualWorkflowLane.Scope(plan.workflowId(),plan.generation(),plan.customerId());
        var terms=VirtualGrantGenerationHistory.validate(tx,scope).terms();
        if(reserve.purpose()!=PlanOperation.RESERVE || !original.equals(reserve.domain()) || reserve.riskPoints()!=terms.payPoints()
                || !approvalMap(withApprovalState(approval,ApprovalPlanState.RESERVED)).equals(approvalMap(reserve.approval()))
                || approval.state()!=(paid?ApprovalPlanState.CONSUMED:ApprovalPlanState.RESERVED)
                || !scope.equals(approval.material().scope()) || !plan.applicationId().equals(approval.material().applicationId())
                || plan.amountKrw()!=approval.material().amountKrw() || !plan.payoutAccountId().equals(approval.material().payoutAccountId())
                || !plan.securityPolicyVersion().equals(terms.policyVersion()))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var grant=grantRow(tx,plan.grantId());
        if(grant==null || !matches(new StageCommand(reserve.identity(),AllowedAction.EXECUTE_MOCK_PAYMENT),grant))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        if(paid) {
            var result=readResultMetadata(tx,scope,plan.paymentId(),AllowedAction.EXECUTE_MOCK_PAYMENT);
            var payment=tx.get(MP_PAYMENTS,plan.paymentId().toString());
            if(payment==null || !payment.keySet().equals(java.util.Set.of("input","domain","digestReference","profileName","profileVersion","canonicalBytes","receiptDigest"))
                    || !paymentDomainMap(plan).equals(payment.get("domain"))
                    || !SyntheticMockPaymentReceiptCodec.PROFILE_NAME.equals(payment.get("profileName"))
                    || !Integer.valueOf(SyntheticMockPaymentReceiptCodec.PROFILE_VERSION).equals(payment.get("profileVersion"))
                    || !RECEIPT_BINDING_PROFILE.equals(tx.get(RESULTS,plan.paymentId().toString()).get("bindingProfile")))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var input=decodePaymentInput(castMap(payment.get("input")));checkDomain(input,original);
            var i=result.identity();
            if(result.conclusion()!=BusinessConclusion.POSITIVE || !input.globalRequestId().equals(i.globalRequestId())
                    || !input.authenticatedActor().equals(i.actorId()) || !input.operation().equals(i.operation())
                    || !input.canonicalizationVersion().equals(i.canonicalizationVersion())
                    || !i.canonicalBodyDigest().equals(payment.get("digestReference"))
                    || !input.grantId().equals(i.grantId()) || !input.actionId().equals(i.actionId())
                    || !input.targetRunId().equals(i.targetRunId()) || !input.workflowId().equals(i.workflowId())
                    || input.generation()!=i.generation() || !input.customerId().equals(i.customerId()))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        } else if(grant.state()!=GrantState.ISSUED || tx.get(MP_PAYMENTS,plan.paymentId().toString())!=null)
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return plan;
    }

    private static GrantSnapshot grantRow(TransactionalStore.Tx tx, UUID id) {
        var row = tx.get(GRANTS, id.toString()); return row == null ? null : decodeGrant(row);
    }
    private static StageCommand rootStage(RootCommand command) {
        return new StageCommand(command.identity(), command.inputs().claims().allowedAction());
    }
    /** Immutable stored origin projection; neither current eligibility nor actual issuer proof. */
    public record GenerationOrigin(VirtualWorkflowLane.Scope scope, UUID rootGrantId, UUID rootActionId,
                                   UUID targetRunId, UUID rootReceiptRequestId,
                                   UUID documentId, int documentVersion, String contentHash, boolean reviewedSafe,
                                   SimulationSpec.RiskTerms terms, String laneReference) {
        public GenerationOrigin {
            if(scope==null||rootGrantId==null||rootActionId==null||targetRunId==null||rootReceiptRequestId==null
                    ||laneReference==null||laneReference.isBlank()||documentId==null||documentVersion<1
                    ||!SimulationSpec.hash(contentHash)||terms==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        }
        public boolean actualAuthority(){return false;}
        @Override public String toString(){return "GenerationOrigin[STORED_REDACTED]";}
    }
    /** Gen1 discovery is a unique positive stored join, never absence permission or a write. */
    public static GenerationOrigin originalGeneration(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope) {
        if(tx==null||scope==null||scope.generation()!=1)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        GenerationOrigin found=null;
        for(var entry:tx.rows(ROOT_MATERIAL).entrySet()){
            var identity=decodeIdentity(castMap(entry.getValue().get("identity")));
            if(identity.workflowId().equals(scope.workflowId())&&identity.generation()==scope.generation()
                    &&identity.customerId().equals(scope.customerId())){
                if(found!=null||!entry.getKey().equals(identity.grantId().toString()))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                found=generationOrigin(tx,scope,identity.grantId(),identity.globalRequestId());
            }
        }
        if(found==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return found;
    }
    /** Own-generation history join; deliberately calls no history/accounting/lane/control helper. */
    public static GenerationOrigin generationOrigin(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope,
                                                     UUID rootGrantId, UUID rootReceiptRequestId) {
        try {
            if(tx==null||scope==null||rootGrantId==null||rootReceiptRequestId==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var row=tx.get(ROOT_MATERIAL,rootGrantId.toString());
            if(row==null||!row.equals(tx.get(ROOT_RECEIPTS,rootReceiptRequestId.toString()))
                    ||!Integer.valueOf(1).equals(row.get("recordVersion")))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            boolean initial="VIRTUAL_ROOT_PROVISION_1".equals(row.get("recordProfile"));
            boolean continuation="VIRTUAL_TYPED_CONTINUATION_ROOT_1".equals(row.get("recordProfile"));
            var keys=initial?java.util.Set.of("recordVersion","recordProfile","identity","unsignedRootMaterial","workflowPlan")
                    :java.util.Set.of("recordVersion","recordProfile","identity","unsignedRootMaterial","workflowPlan","commandFingerprint");
            if(!(initial||continuation)||!row.keySet().equals(keys)||initial&&scope.generation()!=1
                    ||continuation&&scope.generation()<2)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var rawIdentity=castMap(row.get("identity"));var identity=decodeIdentity(rawIdentity);
            if(!identityMap(identity).equals(rawIdentity)||!identity.grantId().equals(rootGrantId)
                    ||!identity.globalRequestId().equals(rootReceiptRequestId)||!identity.workflowId().equals(scope.workflowId())
                    ||identity.generation()!=scope.generation()||!identity.customerId().equals(scope.customerId()))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var grant=grantRow(tx,rootGrantId);var grantRaw=tx.get(GRANTS,rootGrantId.toString());
            if(grant==null||!grantMap(grant).equals(grantRaw)||!matches(new StageCommand(identity,AllowedAction.EVALUATE_KYC),grant))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var target=decodeTarget(tx.get(TARGET_BINDINGS,identity.targetRunId().toString()));
            if(!target.workflowId().equals(scope.workflowId())||target.generation()!=scope.generation()
                    ||!target.customerId().equals(scope.customerId())||!target.grantId().equals(rootGrantId)
                    ||!target.actionId().equals(identity.actionId())||!target.targetRunId().equals(identity.targetRunId())
                    ||target.sourceRunId()!=null||target.sourceResultId()!=null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var plan=castMap(row.get("workflowPlan"));
            if(!plan.keySet().equals(java.util.Set.of("workflowId","generation","laneReference","targetRunId","stageAgents","application","riskTerms"))
                    ||!scope.workflowId().toString().equals(plan.get("workflowId"))||!Integer.valueOf(scope.generation()).equals(plan.get("generation"))
                    ||!identity.targetRunId().toString().equals(plan.get("targetRunId")))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var app=castMap(plan.get("application"));var source=castMap(app.get("source"));
            if(!app.keySet().equals(java.util.Set.of("fixtureId","businessReference","customerId","amountKrw","payoutAccountId",
                    "monthlyIncomeKrw","maxLoanAmountKrw","ownsActiveAccount","source"))
                    ||!scope.customerId().equals(app.get("customerId"))
                    ||!source.keySet().equals(java.util.Set.of("documentId","documentVersion","contentHash","reviewedSafe")))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var unsigned=castMap(row.get("unsignedRootMaterial"));
            if(!unsigned.keySet().equals(java.util.Set.of("profile","claimsBytes","actionBytes","unsignedFrame","payloadSha256"))
                    ||!SimulationSpec.hash((String)unsigned.get("payloadSha256")))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var fingerprint=initial?CanonicalJson.sha256(identityMap(identity)):(String)row.get("commandFingerprint");
            var global=completedOwnedRecord(tx,new ActionJournal.ActionIdentity(identity.actorId(),identity.globalRequestId(),identity.operation(),fingerprint));
            if(global==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var payload=new LinkedHashMap<String,Object>(global);
            if(!identity.globalRequestId().toString().equals(payload.remove("requestId"))||!(payload.remove("replayed") instanceof Boolean))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            if(initial&&!payload.equals(row))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            if(continuation&&(!"ADVANCED".equals(payload.get("kind"))||!row.equals(payload.get("rootOrigin"))
                    ||!payload.equals(tx.get("virtual_grant_profile_continuation_receipts",rootReceiptRequestId.toString()))))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var agents=castMap(plan.get("stageAgents"));var kyc=castMap(agents.get(AllowedAction.EVALUATE_KYC.name()));
            if(!target.documentId().equals(uuid(source,"documentId"))||target.documentVersion()!=(Integer)source.get("documentVersion")
                    ||!target.agentId().equals(kyc.get("agentId"))||!Integer.valueOf(target.agentVersion()).equals(kyc.get("agentVersion")))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            return new GenerationOrigin(scope,rootGrantId,identity.actionId(),identity.targetRunId(),rootReceiptRequestId,
                    uuid(source,"documentId"),(Integer)source.get("documentVersion"),(String)source.get("contentHash"),
                    (Boolean)source.get("reviewedSafe"),decodeRiskTerms(castMap(plan.get("riskTerms"))),(String)plan.get("laneReference"));
        }catch(RuntimeException malformed){throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);}
    }
    /** Pure stored-origin terms; current business eligibility is checked by the caller. */
    public static SimulationSpec.RiskTerms rootRiskTerms(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope) {
        if(scope==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        if(scope.generation()==1)return originalGeneration(tx,scope).terms();
        GenerationOrigin found=null;
        for(var entry:tx.rows(ROOT_MATERIAL).entrySet()){
            var i=decodeIdentity(castMap(entry.getValue().get("identity")));
            if(i.workflowId().equals(scope.workflowId())&&i.generation()==scope.generation()&&i.customerId().equals(scope.customerId())){
                if(found!=null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                found=generationOrigin(tx,scope,i.grantId(),i.globalRequestId());
            }
        }
        if(found==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);return found.terms();
    }
    private static SimulationSpec.RiskTerms decodeRiskTerms(Map<String,Object> found){
        if(!found.keySet().equals(java.util.Set.of("policyVersion","kycPoints","loanPoints","payPoints","baseLimit",
                "additionalApprovalLimit","maxAutomaticKycRuns","approvalLifetime")))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return new SimulationSpec.RiskTerms((String)found.get("policyVersion"),(Integer)found.get("kycPoints"),(Integer)found.get("loanPoints"),
                (Integer)found.get("payPoints"),(Integer)found.get("baseLimit"),(Integer)found.get("additionalApprovalLimit"),
                (Integer)found.get("maxAutomaticKycRuns"),Duration.parse((String)found.get("approvalLifetime")));
    }
    private static Map<String,Object> completedOwnedRecord(TransactionalStore.Tx tx,ActionJournal.ActionIdentity identity){
        if(tx instanceof ActionJournal.ReservedTx owned)return owned.completed(identity);
        var row=tx.get(ActionJournal.TABLE,identity.requestId().toString());if(row==null)return null;
        boolean pending="RESERVED".equals(row.get("reservationStatus"));
        var keys=pending?java.util.Set.of("actorId","requestId","operation","canonicalBodyHash","persistenceMode","durable","reservationStatus","attemptToken")
                :java.util.Set.of("actorId","requestId","operation","canonicalBodyHash","persistenceMode","durable","reply");
        if(!row.keySet().equals(keys)||!identity.actorId().equals(row.get("actorId"))
                ||!identity.requestId().toString().equals(row.get("requestId"))||!identity.operation().equals(row.get("operation"))
                ||!identity.canonicalBodyHash().equals(row.get("canonicalBodyHash"))||!VirtualTransactionalStore.MODE.equals(row.get("persistenceMode"))
                ||!Boolean.FALSE.equals(row.get("durable")))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        if(pending){uuid(row,"attemptToken");return null;}
        var reply=new LinkedHashMap<String,Object>(castMap(row.get("reply")));
        if(!identity.requestId().toString().equals(reply.get("requestId"))||!(reply.get("replayed") instanceof Boolean))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        reply.put("replayed",true);return reply;
    }
    /** Opaque lifetime proof available only to this journal's positive pending writer. */
    public static final class AccountingPhase {
        private final ActionJournal.ReservedTx tx;private final ActionJournal.ActionIdentity action;
        private final CommandIdentity identity;private final UUID token,resultId;private final String inputHash;
        private final Thread thread=Thread.currentThread();private boolean open=true;
        private AccountingPhase(ActionJournal.ReservedTx tx,ActionJournal.ActionIdentity action,CommandIdentity identity,UUID token,
                                String inputHash,UUID resultId){this.tx=tx;this.action=action;this.identity=identity;this.token=token;this.inputHash=inputHash;this.resultId=resultId;}
        @Override public String toString(){return "AccountingPhase[OPAQUE_REDACTED]";}
    }
    private static void requirePhase(TransactionalStore.Tx tx,AccountingPhase phase){
        if(phase==null||!phase.open||phase.thread!=Thread.currentThread()||phase.tx!=tx)
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        phase.tx.requirePending(phase.action,phase.token);
    }
    public static boolean accountingConsumptionIsPending(TransactionalStore.Tx tx,UUID grantId,UUID resultId,AccountingPhase phase){
        if(phase==null)return false;requirePhase(tx,phase);
        return phase.resultId!=null&&phase.identity.grantId().equals(grantId)&&phase.resultId.equals(resultId);
    }
    public static boolean accountingPreparationIsPending(TransactionalStore.Tx tx,SyntheticKycPreparationBinding.PreparationMarker marker,AccountingPhase phase){
        if(phase==null)return false;requirePhase(tx,phase);
        return marker!=null&&phase.inputHash!=null&&phase.identity.equals(marker.identity())&&phase.inputHash.equals(marker.inputSnapshotHash());
    }
    public static void requireAccountingPreparation(TransactionalStore.Tx tx,SyntheticKycPreparationBinding.PreparationMarker marker,AccountingPhase phase){
        if(marker==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        if(phase!=null){requirePhase(tx,phase);if(phase.inputHash!=null&&phase.identity.equals(marker.identity())){
            if(!phase.inputHash.equals(marker.inputSnapshotHash()))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);return;
        }}
        var i=marker.identity();var row=tx.get(PREPARATION_RECEIPTS,i.globalRequestId().toString());
        if(row==null||!row.keySet().equals(java.util.Set.of("recordVersion","recordProfile","identity","descriptor","inputSnapshotHash",
                "decision","refusal","chargedPoints","kycRunsAfter","usedRiskAfter"))||!Integer.valueOf(1).equals(row.get("recordVersion"))
                ||!"VIRTUAL_KYC_PREPARATION_1".equals(row.get("recordProfile"))||!identityMap(i).equals(row.get("identity"))
                ||!marker.inputSnapshotHash().equals(row.get("inputSnapshotHash"))||!"PREPARED".equals(row.get("decision"))
                ||!"NONE".equals(row.get("refusal"))||!Integer.valueOf(marker.chargedPoints()).equals(row.get("chargedPoints"))
                ||!Integer.valueOf(marker.kycRunsAfter()).equals(row.get("kycRunsAfter"))||!Integer.valueOf(marker.usedRiskAfter()).equals(row.get("usedRiskAfter")))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var descriptor=castMap(row.get("descriptor"));
        if(!marker.preparedAt().toString().equals(descriptor.get("preparedAt")))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var fp=CanonicalJson.sha256(map("purpose","KYC_PREPARATION_1","identity",identityMap(i),"descriptor",descriptor,"inputSnapshotHash",marker.inputSnapshotHash()));
        requireAccountingReply(tx,new ActionJournal.ActionIdentity(i.actorId(),i.globalRequestId(),i.operation(),fp),row);
    }
    public static void requireAccountingConsumption(TransactionalStore.Tx tx,UUID grantId,UUID resultId,AccountingPhase phase){
        var grant=grantRow(tx,grantId);var index=tx.get(BY_GRANT,grantId.toString());
        if(grant==null||grant.state()!=GrantState.CONSUMED||index==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        UUID request=uuid(index,"requestId");CommandIdentity identity;
        if(accountingConsumptionIsPending(tx,grantId,resultId,phase))identity=phase.identity;
        else{
            var local=tx.get(RECEIPTS,request.toString());if(local==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var receipt=decodeLocal(local);identity=receipt.identity();
            if(receipt.kind()!=ReceiptKind.CONSUMPTION||receipt.result()==null||!resultId.equals(receipt.result().resultId())
                    ||!resultMap(receipt.result()).equals(tx.get(RESULTS,resultId.toString()))||!receiptMap(receipt).equals(local))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            requireAccountingReply(tx,journalIdentity(new StageCommand(identity,grant.action())),local);
        }
        if(!request.equals(identity.globalRequestId())||!matches(new StageCommand(identity,grant.action()),grant)
                ||tx.get(RESULTS,resultId.toString())==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var target=decodeTarget(tx.get(TARGET_BINDINGS,grant.targetRunId().toString()));
        if(!target.grantId().equals(grantId)||!target.actionId().equals(grant.actionId())||!target.targetRunId().equals(grant.targetRunId())
                ||!target.workflowId().equals(grant.workflowId())||target.generation()!=grant.generation()
                ||!target.customerId().equals(grant.customerId())||!resultId.equals(target.resultId()))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
    }
    private static PlanReceipt accountingPlanOrigin(TransactionalStore.Tx tx,Map<String,Object> row){
        var receipt=decodePlanReceipt(row);var i=receipt.identity();
        if(!(row.get("commandFingerprint") instanceof String fp)||!fp.matches("[0-9a-f]{64}")||!planReceiptMap(receipt,fp).equals(row))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        requireAccountingReply(tx,new ActionJournal.ActionIdentity(i.actorId(),i.globalRequestId(),i.operation(),fp),row);
        return receipt;
    }
    public static void requireAccountingReservation(TransactionalStore.Tx tx,UUID reservationId){
        try{
            var plan=decodePaymentDomain(tx.get(MP_PLANS,reservationId.toString()));
            if(!reservationId.equals(plan.reservationId())||plan.reservationState()!=ReservationState.RESERVED
                    ||plan.approvalState()!=ApprovalState.RESERVED)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            Map<String,Object> found=null;
            for(var e:tx.rows(PLAN_RECEIPTS).entrySet())if("RESERVE".equals(e.getValue().get("purpose"))&&paymentDomainMap(plan).equals(e.getValue().get("domain"))){
                if(found!=null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);found=e.getValue();
                if(!e.getKey().equals(decodeIdentity(castMap(found.get("identity"))).globalRequestId().toString()))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            }
            if(found==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var reserve=accountingPlanOrigin(tx,found);var a=decodeApproval(tx.get(PLAN_APPROVALS,plan.approvalId().toString()));
            var terms=rootRiskTerms(tx,new VirtualWorkflowLane.Scope(plan.workflowId(),plan.generation(),plan.customerId()));
            var grant=grantRow(tx,plan.grantId());
            if(reserve.purpose()!=PlanOperation.RESERVE||reserve.riskPoints()!=terms.payPoints()||!reserve.approval().equals(a)
                    ||a.state()!=ApprovalPlanState.RESERVED||a.decision()!=ReviewDecision.APPROVE||!plan.equals(reserve.domain())
                    ||grant==null||grant.action()!=AllowedAction.EXECUTE_MOCK_PAYMENT||grant.state()!=GrantState.ISSUED
                    ||!matches(new StageCommand(reserve.identity(),AllowedAction.EXECUTE_MOCK_PAYMENT),grant))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var risk=tx.get(PAYMENT_RISK,reservationId.toString());
            if(!paymentRiskMap(plan,terms.payPoints(),"RESERVED").equals(risk))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var reviewRow=tx.get(PLAN_RECEIPTS,a.reviewRequestId().toString());if(reviewRow==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var review=accountingPlanOrigin(tx,reviewRow);var m=a.material();
            if(review.purpose()!=PlanOperation.REVIEW||review.domain()!=null||review.riskPoints()!=0
                    ||!a.reviewerActorId().equals(review.identity().actorId())||!a.reviewRequestId().equals(review.identity().globalRequestId())
                    ||!approvalMap(withApprovalState(a,ApprovalPlanState.AVAILABLE)).equals(approvalMap(review.approval()))
                    ||!SyntheticMockPaymentPlanBinding.reviewHash(m).equals(a.reviewSnapshotHash())
                    ||!m.scope().workflowId().equals(plan.workflowId())||m.scope().generation()!=plan.generation()
                    ||!m.scope().customerId().equals(plan.customerId())||!m.applicationId().equals(plan.applicationId())
                    ||m.amountKrw()!=plan.amountKrw()||!m.payoutAccountId().equals(plan.payoutAccountId())
                    ||!m.policyVersion().equals(plan.securityPolicyVersion())||!m.policyVersion().equals(terms.policyVersion()))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var loan=grantRow(tx,review.identity().grantId());
            if(loan==null||loan.action()!=AllowedAction.CREATE_LOAN_RECOMMENDATION||!matches(new StageCommand(review.identity(),loan.action()),loan))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            requireAccountingConsumption(tx,loan.grantId(),m.loanResultId(),null);
            var loanRef=decodeTarget(tx.get(TARGET_BINDINGS,loan.targetRunId().toString()));
            if(!m.kycResultId().equals(loanRef.sourceResultId())||loanRef.sourceRunId()==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var kycRef=decodeTarget(tx.get(TARGET_BINDINGS,loanRef.sourceRunId().toString()));var kyc=grantRow(tx,kycRef.grantId());
            if(kyc==null||kyc.action()!=AllowedAction.EVALUATE_KYC)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            requireAccountingConsumption(tx,kyc.grantId(),m.kycResultId(),null);
            for(var r:List.of(loanRef,kycRef))if(!r.workflowId().equals(plan.workflowId())||r.generation()!=plan.generation()
                    ||!r.customerId().equals(plan.customerId())||!r.documentId().equals(m.documentId())||r.documentVersion()!=m.documentVersion())
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            for(var id:List.of(m.kycResultId(),m.loanResultId()))if(decodeResult(tx.get(RESULTS,id.toString())).businessConclusion()!=BusinessConclusion.POSITIVE)
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        }catch(RuntimeException malformed){throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);}
    }
    private static void requireAccountingReply(TransactionalStore.Tx tx,ActionJournal.ActionIdentity identity,Map<String,Object> local){
        var global=completedOwnedRecord(tx,identity);if(global==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var copy=new LinkedHashMap<String,Object>(global);
        if(!identity.requestId().toString().equals(copy.remove("requestId"))||!(copy.remove("replayed") instanceof Boolean)||!copy.equals(local))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
    }

    private static Map<String, Object> reviewMaterialMap(ReviewMaterial m) {
        var s = m.scope();
        return map("scope", map("workflowId", s.workflowId().toString(), "generation", s.generation(), "customerId", s.customerId()),
                "applicationId", m.applicationId().toString(), "amountKrw", m.amountKrw(), "payoutAccountId", m.payoutAccountId().toString(),
                "kycResultId", m.kycResultId().toString(), "loanResultId", m.loanResultId().toString(),
                "evidenceBundleHash", m.evidenceBundleHash(), "loanResultHash", m.loanResultHash(),
                "documentId", m.documentId().toString(), "documentVersion", m.documentVersion(), "sourceContentHash", m.sourceContentHash(),
                "policyVersion", m.policyVersion(), "usedRisk", m.usedRisk(), "reservedRisk", m.reservedRisk(),
                "riskLimitAfterApproval", m.riskLimitAfterApproval());
    }
    private static ReviewMaterial decodeReviewMaterial(Map<String, Object> m) {
        if (!m.keySet().equals(java.util.Set.of("scope", "applicationId", "amountKrw", "payoutAccountId", "kycResultId", "loanResultId",
                "evidenceBundleHash", "loanResultHash", "documentId", "documentVersion", "sourceContentHash", "policyVersion",
                "usedRisk", "reservedRisk", "riskLimitAfterApproval"))) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var s = castMap(m.get("scope"));
        if (!s.keySet().equals(java.util.Set.of("workflowId", "generation", "customerId"))) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return new ReviewMaterial(new VirtualWorkflowLane.Scope(uuid(s, "workflowId"), (Integer) s.get("generation"), (String) s.get("customerId")),
                uuid(m, "applicationId"), (Long) m.get("amountKrw"), uuid(m, "payoutAccountId"), uuid(m, "kycResultId"), uuid(m, "loanResultId"),
                (String) m.get("evidenceBundleHash"), (String) m.get("loanResultHash"), uuid(m, "documentId"), (Integer) m.get("documentVersion"),
                (String) m.get("sourceContentHash"), (String) m.get("policyVersion"), (Integer) m.get("usedRisk"),
                (Integer) m.get("reservedRisk"), (Integer) m.get("riskLimitAfterApproval"));
    }
    private static Map<String, Object> approvalMap(ApprovalSnapshot a) {
        return map("approvalId", a.approvalId().toString(), "reviewRequestId", a.reviewRequestId().toString(), "reviewerActorId", a.reviewerActorId(),
                "decision", a.decision().name(), "material", reviewMaterialMap(a.material()), "reviewSnapshotHash", a.reviewSnapshotHash(),
                "createdAt", a.createdAt().toString(), "expiresAt", a.expiresAt().toString(), "extraRiskLimit", a.extraRiskLimit(),
                "riskLimit", a.riskLimit(), "state", a.state().name());
    }
    private static ApprovalSnapshot decodeApproval(Map<String, Object> a) {
        if (!a.keySet().equals(java.util.Set.of("approvalId", "reviewRequestId", "reviewerActorId", "decision", "material", "reviewSnapshotHash",
                "createdAt", "expiresAt", "extraRiskLimit", "riskLimit", "state"))) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return new ApprovalSnapshot(uuid(a, "approvalId"), uuid(a, "reviewRequestId"), (String) a.get("reviewerActorId"),
                ReviewDecision.valueOf((String) a.get("decision")), decodeReviewMaterial(castMap(a.get("material"))),
                (String) a.get("reviewSnapshotHash"), Instant.parse((String) a.get("createdAt")), Instant.parse((String) a.get("expiresAt")),
                (Integer) a.get("extraRiskLimit"), (Integer) a.get("riskLimit"), ApprovalPlanState.valueOf((String) a.get("state")));
    }
    private static Map<String, Object> planReceiptMap(PlanReceipt r, String fingerprint) {
        return map("recordVersion", r.version(), "recordProfile", "VIRTUAL_PAYMENT_PLAN_RECEIPT_1", "purpose", r.purpose().name(),
                "identity", identityMap(r.identity()), "commandFingerprint", fingerprint, "approval", approvalMap(r.approval()),
                "domain", r.domain() == null ? null : paymentDomainMap(r.domain()), "riskPoints", r.riskPoints());
    }
    private static PlanReceipt decodePlanReceipt(Map<String, Object> r) {
        if (!r.keySet().equals(java.util.Set.of("recordVersion", "recordProfile", "purpose", "identity", "commandFingerprint", "approval", "domain", "riskPoints"))
                || !"VIRTUAL_PAYMENT_PLAN_RECEIPT_1".equals(r.get("recordProfile"))) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return new PlanReceipt((Integer) r.get("recordVersion"), PlanOperation.valueOf((String) r.get("purpose")),
                decodeIdentity(castMap(r.get("identity"))), decodeApproval(castMap(r.get("approval"))),
                r.get("domain") == null ? null : decodePaymentDomain(castMap(r.get("domain"))), (Integer) r.get("riskPoints"));
    }
    private static String planFingerprint(PlanOperation purpose, Object command) {
        if (purpose == PlanOperation.REVIEW) {
            var c = (ReviewCommand) command;
            return CanonicalJson.sha256(map("purpose", purpose.name(), "identity", identityMap(c.identity()), "approvalId", c.approvalId().toString(),
                    "decision", c.decision().name(), "expectedReviewSnapshotHash", c.expectedReviewSnapshotHash(),
                    "now", c.now().toString(), "expiresAt", c.expiresAt().toString(), "comment", c.comment()));
        }
        var c = (ReserveCommand) command;
        return CanonicalJson.sha256(map("purpose", purpose.name(), "identity", identityMap(c.identity()), "domain", paymentDomainMap(c.domain()),
                "expectedReviewSnapshotHash", c.expectedReviewSnapshotHash(), "now", c.now().toString()));
    }
    private static StageCommand planStage(com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity i, PlanOperation purpose) {
        return new StageCommand(i, purpose == PlanOperation.REVIEW ? AllowedAction.CREATE_LOAN_RECOMMENDATION : AllowedAction.EXECUTE_MOCK_PAYMENT);
    }
    private static ActionJournal.ActionIdentity planIdentity(com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity i,
                                                            PlanOperation purpose, Object command) {
        return new ActionJournal.ActionIdentity(i.actorId(), i.globalRequestId(), i.operation(), planFingerprint(purpose, command));
    }

    private static Map<String, Object> rootReceiptMap(RootCommand command) {
        var inputs = command.inputs(); var prepared = inputs.prepared(); var profile = inputs.profile();
        var plan = command.workflowPlan(); var app = plan.application(); var source = app.source(); var risk = plan.riskTerms();
        var agents = new LinkedHashMap<String, Object>();
        for (var entry : plan.stageAgents().entrySet())
            agents.put(entry.getKey().name(), map("agentId", entry.getValue().agentId(), "agentVersion", entry.getValue().version()));
        var material = map("profile", map("claimsMaxUtf8Bytes", profile.claimsMaxUtf8Bytes(),
                "actionMaxUtf8Bytes", profile.actionMaxUtf8Bytes(), "jsonDepthMax", profile.jsonDepthMax(),
                "fieldsPerObjectMax", profile.fieldsPerObjectMax(), "stringMaxUtf16CodeUnits", profile.stringMaxUtf16CodeUnits(),
                "ttlSecondsMax", profile.ttlSecondsMax()), "claimsBytes", HexFormat.of().formatHex(prepared.claimsBytes()),
                "actionBytes", HexFormat.of().formatHex(prepared.actionBytes()), "unsignedFrame", HexFormat.of().formatHex(prepared.unsignedFrame()),
                "payloadSha256", prepared.payloadSha256());
        var safePlan = map("workflowId", plan.workflowId().toString(), "generation", plan.generation(),
                "laneReference", plan.laneReference(), "targetRunId", plan.targetRunId().toString(), "stageAgents", agents,
                "application", map("fixtureId", app.fixtureId(), "businessReference", app.businessReference(), "customerId", app.customerId(),
                    "amountKrw", app.amountKrw(), "payoutAccountId", app.payoutAccountId().toString(), "monthlyIncomeKrw", app.monthlyIncomeKrw(),
                    "maxLoanAmountKrw", app.maxLoanAmountKrw(), "ownsActiveAccount", app.ownsActiveAccount(),
                    "source", map("documentId", source.documentId().toString(), "documentVersion", source.documentVersion(),
                        "contentHash", source.contentHash(), "reviewedSafe", source.reviewedSafe())),
                "riskTerms", map("policyVersion", risk.policyVersion(), "kycPoints", risk.kycPoints(), "loanPoints", risk.loanPoints(),
                    "payPoints", risk.payPoints(), "baseLimit", risk.baseLimit(), "additionalApprovalLimit", risk.additionalApprovalLimit(),
                    "maxAutomaticKycRuns", risk.maxAutomaticKycRuns(), "approvalLifetime", risk.approvalLifetime().toString()));
        return map("recordVersion", 1, "recordProfile", "VIRTUAL_ROOT_PROVISION_1", "identity", identityMap(command.identity()),
                "unsignedRootMaterial", material, "workflowPlan", safePlan);
    }

    @Override public PreparationOutcome prepareKyc(PreparationCommand command, PreparationWork work) {
        Objects.requireNonNull(command); Objects.requireNonNull(work);
        if (context != Context.APPLICATION) return preparationFailure(Status.UNCONFIRMED_BEFORE_ADMISSION);
        synchronized (epoch) {
            if (epoch.active) return preparationFailure(Status.UNCONFIRMED_BEFORE_ADMISSION);
            epoch.active = true; boolean[] returned = {false}; PreparationFacade[] observed = {null};
            try {
                return journal.reservedTransaction(tx -> {
                    var owned = new PreparationFacade(tx, command); observed[0] = owned;
                    try {
                        var result = Objects.requireNonNull(work.apply(owned));
                        if (result.receipt() != null && result.receipt() != owned.emitted
                                || owned.completed && (result.status() != Status.VIRTUAL_COMMITTED_IN_PROCESS || result.receipt() != owned.emitted)
                                || owned.replayed && (result.status() != Status.VIRTUAL_REPLAYED_IN_PROCESS || result.receipt() != owned.emitted)
                                || result.status() == Status.VIRTUAL_COMMITTED_IN_PROCESS && !owned.completed
                                || result.status() == Status.VIRTUAL_REPLAYED_IN_PROCESS && !owned.replayed
                                || owned.admitted && !owned.completed) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
                        returned[0] = true; return result;
                    } finally { owned.open = false; }
                });
            } catch (RuntimeException failure) {
                if (returned[0] && observed[0] != null && observed[0].completed) {
                    epoch.attempts.put(command.identity().globalRequestId(), new UnknownBinding(preparationStage(command), null));
                    return preparationFailure(Status.COMMIT_UNKNOWN);
                }
                if (returned[0]) return preparationFailure(Status.RECONCILIATION_UNCONFIRMED);
                if (failure instanceof ActionJournal.ActionConflictException) return preparationFailure(Status.IDENTITY_CONFLICT);
                if (failure instanceof ActionJournal.PendingActionException) return preparationFailure(Status.RECONCILIATION_UNCONFIRMED);
                if (failure instanceof Stop stopped) return preparationFailure(stopped.status);
                return preparationFailure(Status.UNCONFIRMED_BEFORE_ADMISSION);
            } finally { epoch.active = false; }
        }
    }
    private static PreparationOutcome preparationFailure(Status status) {
        boolean unknown = status == Status.COMMIT_UNKNOWN || status == Status.RECONCILIATION_UNCONFIRMED
                || status == Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH || status == Status.TRANSACTION_INVARIANT_UNCONFIRMED;
        return new PreparationOutcome(status, null, unknown ? PreparationEffect.UNKNOWN
                : PreparationEffect.NO_NEW_PREPARATION_ATTEMPT_THIS_INVOCATION);
    }
    private static StageCommand preparationStage(PreparationCommand c) {
        return new StageCommand(c.identity(), AllowedAction.EVALUATE_KYC);
    }
    private static Map<String,Object> preparationDescriptor(PreparationCommand c) {
        var d = SyntheticKycPreparationBinding.descriptor(c); var t = d.terms();
        return map("source", map("documentId", d.source().documentId().toString(), "documentVersion", d.source().documentVersion(),
                        "contentHash", d.source().contentHash()),
                "facts", d.facts().stream().map(f -> map("evidenceId", f.evidenceId().toString(), "customerId", f.customerId(),
                        "kind", f.kind().name(), "result", f.result().name(), "active", f.active(),
                        "issuedAt", f.issuedAt().toString(), "expiresAt", f.expiresAt().toString())).toList(),
                "terms", map("policyVersion", t.policyVersion(), "kycPoints", t.kycPoints(), "loanPoints", t.loanPoints(),
                        "payPoints", t.payPoints(), "baseLimit", t.baseLimit(), "additionalApprovalLimit", t.additionalApprovalLimit(),
                        "maxAutomaticKycRuns", t.maxAutomaticKycRuns(), "approvalLifetime", t.approvalLifetime().toString()),
                "preparedAt", d.preparedAt().toString());
    }
    private static ActionJournal.ActionIdentity preparationIdentity(PreparationCommand c) {
        return new ActionJournal.ActionIdentity(c.identity().actorId(), c.identity().globalRequestId(), c.identity().operation(),
                CanonicalJson.sha256(map("purpose", "KYC_PREPARATION_1", "identity", identityMap(c.identity()),
                        "descriptor", preparationDescriptor(c),
                        "inputSnapshotHash", SyntheticKycPreparationBinding.prepareRequested(c).inputSnapshotHash())));
    }
    private static Map<String,Object> preparationReceiptMap(PreparationCommand c, PreparationReceipt r) {
        return map("recordVersion", 1, "recordProfile", "VIRTUAL_KYC_PREPARATION_1", "identity", identityMap(r.identity()),
                "descriptor", preparationDescriptor(c), "inputSnapshotHash", r.inputSnapshotHash(),
                "decision", r.decision().name(), "refusal", r.refusal().name(), "chargedPoints", r.chargedPoints(),
                "kycRunsAfter", r.kycRunsAfter(), "usedRiskAfter", r.usedRiskAfter());
    }
    private final class PreparationFacade implements OwnedPreparationTx {
        private final ActionJournal.ReservedTx tx; private final PreparationCommand command;
        private final Thread owner = Thread.currentThread();
        private boolean open = true, lookedUp, admitted, completed, replayed;
        private UUID token; private FreshBindings ticket; private PreparationReceipt emitted;
        PreparationFacade(ActionJournal.ReservedTx tx, PreparationCommand command) { this.tx = tx; this.command = command; }
        private void bound(PreparationCommand value) {
            if (!open || owner != Thread.currentThread()) throw new IllegalStateException("OWNED_PREPARATION_TRANSACTION_UNAVAILABLE");
            if (!command.equals(value)) throw stop(Status.IDENTITY_CONFLICT);
        }
        private void pending() {
            if (!admitted || completed) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            tx.requirePending(preparationIdentity(command), token);
        }
        @Override public PreparationReceipt lookupPreparation(PreparationCommand c) {
            bound(c);
            if (admitted || completed) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            requireHistoricalLane(tx, preparationStage(c)); lookedUp = true;
            var grant = grantRow(tx, c.identity().grantId());
            if (grant == null || !matches(preparationStage(c), grant)) throw stop(Status.IDENTITY_CONFLICT);
            var saved = tx.completed(preparationIdentity(c));
            var row = tx.get(PREPARATION_RECEIPTS, c.identity().globalRequestId().toString());
            if (saved == null) {
                if (row != null || uncertain(preparationStage(c))) throw stop(Status.RECONCILIATION_UNCONFIRMED);
                return null;
            }
            if (row == null) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var receipt = new PreparationReceipt(c.identity(), SyntheticKycPreparationBinding.descriptor(c),
                    (String) row.get("inputSnapshotHash"), Decision.valueOf((String) row.get("decision")),
                    Refusal.valueOf((String) row.get("refusal")), (Integer) row.get("chargedPoints"),
                    (Integer) row.get("kycRunsAfter"), (Integer) row.get("usedRiskAfter"));
            var input = SyntheticKycPreparationBinding.prepareRequested(c);
            if (!receipt.inputSnapshotHash().equals(input.inputSnapshotHash()) || !preparationReceiptMap(c, receipt).equals(row))
                throw stop(Status.IDENTITY_CONFLICT);
            var payload = new LinkedHashMap<String,Object>(saved);
            if (!c.identity().globalRequestId().toString().equals(payload.remove("requestId"))
                    || !(payload.remove("replayed") instanceof Boolean) || !payload.equals(row))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            if (receipt.decision() == Decision.PREPARED) {
                var marker = VirtualGrantEvaluationAccounting.requireHistoricalPrepared(tx, preparationStage(c), receipt.inputSnapshotHash());
                if (!marker.identity().equals(c.identity()) || !marker.preparedAt().equals(c.preparedAt())
                        || marker.chargedPoints() != receipt.chargedPoints() || marker.kycRunsAfter() != receipt.kycRunsAfter()
                        || marker.usedRiskAfter() != receipt.usedRiskAfter()) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                var storedInput = tx.get("virtual_grant_profile_kyc_inputs", c.identity().targetRunId().toString());
                if (storedInput == null || !input.canonicalInput().equals(storedInput.get("canonicalInput")))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            }
            requireHistoricalArtifact(tx,new VirtualWorkflowLane.Scope(c.identity().workflowId(),c.identity().generation(),c.identity().customerId()),
                    c.identity().targetRunId(),null);
            epoch.attempts.remove(c.identity().globalRequestId()); replayed = true; emitted = receipt; return receipt;
        }
        @Override public void admitFreshPreparation(PreparationCommand c) {
            bound(c); requireFreshLane(tx, preparationStage(c));
            if (!lookedUp || admitted || replayed || uncertain(preparationStage(c))) throw stop(Status.RECONCILIATION_UNCONFIRMED);
            var grant = grantRow(tx, c.identity().grantId());
            if (grant == null || !matches(preparationStage(c), grant) || grant.state() != GrantState.ISSUED)
                throw stop(Status.IDENTITY_CONFLICT);
            if (tx.get("virtual_grant_profile_kyc_preparations", c.identity().targetRunId().toString()) != null
                    || tx.get("virtual_grant_profile_kyc_inputs", c.identity().targetRunId().toString()) != null)
                throw stop(Status.IDENTITY_CONFLICT);
            token = Objects.requireNonNull(tokens.get());
            if (tx.reserve(preparationIdentity(c), token).status() != ActionJournal.ReservationStatus.RESERVED)
                throw stop(Status.RECONCILIATION_UNCONFIRMED);
            admitted = true;
        }
        private FreshBindings currentBindings() {
            var i = command.identity(); var scope = new VirtualWorkflowLane.Scope(i.workflowId(), i.generation(), i.customerId());
            requireFreshLane(tx, preparationStage(command));
            var workflow = tx.get("virtual_workflows", i.workflowId().toString());
            var grant = grantRow(tx, i.grantId());
            if (workflow == null || grant == null || !matches(preparationStage(command), grant)) throw stop(Status.IDENTITY_CONFLICT);
            var terms = rootRiskTerms(tx, scope);
            if (!Integer.valueOf(terms.baseLimit()).equals(workflow.get("riskLimit")))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            return new FreshBindings(grant, (String) workflow.get("state"), VirtualGrantEvaluationAccounting.readVerified(tx, scope),
                    terms.baseLimit(), new SourceCoordinate(uuid(workflow, "documentId"),
                    (Integer) workflow.get("documentVersion")), terms, false);
        }
        @Override public FreshBindings readPreparationBindings(PreparationCommand c) {
            bound(c); pending(); if (ticket == null) ticket = currentBindings(); return ticket;
        }
        private void checkTicket(FreshBindings supplied) {
            pending();
            if (ticket == null || supplied != ticket || !ticket.equals(currentBindings())) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            SyntheticKycPreparationBinding.checkBindings(command, ticket);
            if (!"KYC_PENDING".equals(ticket.workflowState()) || ticket.held()) throw stop(Status.REFUSED_BEFORE_ADMISSION);
        }
        @Override public PreparationReceipt recordPreparation(PreparationCommand c, ResolvedPreparation resolved) {
            bound(c); if (resolved == null) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION); checkTicket(resolved.bindings());
            var requested = SyntheticKycPreparationBinding.prepareRequested(c);
            if (!requested.canonicalInput().equals(resolved.input().canonicalInput())
                    || !requested.inputSnapshotHash().equals(resolved.input().inputSnapshotHash())) throw stop(Status.IDENTITY_CONFLICT);
            var phase = new AccountingPhase(tx, preparationIdentity(c), c.identity(), token,
                    resolved.input().inputSnapshotHash(), null);
            try {
                var marker = VirtualGrantEvaluationAccounting.prepareKyc(tx, c, resolved.input(), phase);
                return finish(new PreparationReceipt(c.identity(), SyntheticKycPreparationBinding.descriptor(c), marker.inputSnapshotHash(),
                        Decision.PREPARED, Refusal.NONE, marker.chargedPoints(), marker.kycRunsAfter(), marker.usedRiskAfter()));
            } finally { phase.open = false; }
        }
        @Override public PreparationReceipt recordRefusal(PreparationCommand c, FreshBindings supplied, Refusal refusal) {
            bound(c); checkTicket(supplied);
            int cost = ticket.counters().kycCharged() ? 0 : ticket.riskTerms().kycPoints();
            var expected = ticket.counters().kycRuns() >= ticket.riskTerms().maxAutomaticKycRuns()
                    ? Refusal.KYC_PRECONDITION_FAILED
                    : (long) ticket.counters().usedRisk() + ticket.counters().reservedRisk() + cost > ticket.riskLimit()
                        ? Refusal.RISK_LIMIT_EXCEEDED : Refusal.NONE;
            if (refusal == null || refusal == Refusal.NONE || refusal != expected) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            var workflow = new LinkedHashMap<String,Object>(tx.get("virtual_workflows", c.identity().workflowId().toString()));
            workflow.put("state", "ON_HOLD"); workflow.put("lastDecision", "DENY");
            workflow.put("reasonCodes", List.of(refusal.name()));
            tx.put("virtual_workflows", c.identity().workflowId().toString(), workflow);
            return finish(new PreparationReceipt(c.identity(), SyntheticKycPreparationBinding.descriptor(c),
                    SyntheticKycPreparationBinding.prepareRequested(c).inputSnapshotHash(), Decision.ON_HOLD, refusal,
                    0, ticket.counters().kycRuns(), ticket.counters().usedRisk()));
        }
        private PreparationReceipt finish(PreparationReceipt receipt) {
            var row = preparationReceiptMap(command, receipt);
            if (CanonicalJson.write(row).getBytes(java.nio.charset.StandardCharsets.UTF_8).length > maxReceiptBytes)
                throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            tx.put(PREPARATION_RECEIPTS, command.identity().globalRequestId().toString(), row);
            var reply = new LinkedHashMap<String,Object>(row); reply.put("requestId", command.identity().globalRequestId().toString());
            tx.complete(preparationIdentity(command), token, reply); completed = true; emitted = receipt; return receipt;
        }
    }

    @Override public PlanOutcome review(ReviewCommand command, PlanWork work) {
        Objects.requireNonNull(command); return planTransaction(command.identity(), PlanOperation.REVIEW, command, work);
    }
    @Override public PlanOutcome reserve(ReserveCommand command, PlanWork work) {
        Objects.requireNonNull(command); return planTransaction(command.identity(), PlanOperation.RESERVE, command, work);
    }
    private PlanOutcome planTransaction(com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity identity,
                                        PlanOperation purpose, Object command, PlanWork work) {
        Objects.requireNonNull(work);
        if (context != Context.APPLICATION) return new PlanOutcome(Status.UNCONFIRMED_BEFORE_ADMISSION, null, PlanEffect.NO_NEW_PLAN_ATTEMPT_THIS_INVOCATION);
        synchronized (epoch) {
            if (epoch.active) return new PlanOutcome(Status.UNCONFIRMED_BEFORE_ADMISSION, null, PlanEffect.NO_NEW_PLAN_ATTEMPT_THIS_INVOCATION);
            epoch.active = true; boolean[] returned = {false}; PlanFacade[] observed = {null};
            try {
                return journal.reservedTransaction(tx -> {
                    PlanFacade owned = new PlanFacade(tx, identity, purpose, command); observed[0] = owned;
                    try {
                        PlanOutcome result = Objects.requireNonNull(work.apply(owned));
                        if ((result.receipt() != null && result.receipt() != owned.emitted)
                                || (owned.completed && (result.status() != Status.VIRTUAL_COMMITTED_IN_PROCESS || result.receipt() != owned.emitted))
                                || (owned.replayed && (result.status() != Status.VIRTUAL_REPLAYED_IN_PROCESS || result.receipt() != owned.emitted))
                                || (result.status() == Status.VIRTUAL_COMMITTED_IN_PROCESS && !owned.completed)
                                || (result.status() == Status.VIRTUAL_REPLAYED_IN_PROCESS && !owned.replayed)
                                || (owned.admitted && !owned.completed)) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
                        returned[0] = true; return result;
                    } finally { owned.open = false; }
                });
            } catch (RuntimeException failure) {
                if (returned[0] && observed[0] != null && observed[0].completed) {
                    epoch.attempts.put(identity.globalRequestId(), new UnknownBinding(planStage(identity, purpose), null));
                    epoch.planAttempts.put(identity.globalRequestId(), planAttempt(identity, purpose, command));
                    return new PlanOutcome(Status.COMMIT_UNKNOWN, null, PlanEffect.UNKNOWN);
                }
                if (returned[0]) return new PlanOutcome(Status.RECONCILIATION_UNCONFIRMED, null, PlanEffect.UNKNOWN);
                if (failure instanceof ActionJournal.ActionConflictException)
                    return new PlanOutcome(Status.IDENTITY_CONFLICT, null, PlanEffect.NO_NEW_PLAN_ATTEMPT_THIS_INVOCATION);
                if (failure instanceof ActionJournal.PendingActionException)
                    return new PlanOutcome(Status.RECONCILIATION_UNCONFIRMED, null, PlanEffect.UNKNOWN);
                if (failure instanceof Stop stopped) return new PlanOutcome(stopped.status, null,
                        stopped.status == Status.RECONCILIATION_UNCONFIRMED || stopped.status == Status.TRANSACTION_INVARIANT_UNCONFIRMED
                                ? PlanEffect.UNKNOWN : PlanEffect.NO_NEW_PLAN_ATTEMPT_THIS_INVOCATION);
                return new PlanOutcome(Status.UNCONFIRMED_BEFORE_ADMISSION, null, PlanEffect.NO_NEW_PLAN_ATTEMPT_THIS_INVOCATION);
            } finally { epoch.active = false; }
        }
    }
    private static PlanAttempt planAttempt(com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity i,
                                           PlanOperation p, Object c) {
        return p == PlanOperation.REVIEW ? new PlanAttempt(i, p, ((ReviewCommand)c).approvalId(), null)
                : new PlanAttempt(i, p, ((ReserveCommand)c).domain().approvalId(), ((ReserveCommand)c).domain().reservationId());
    }
    private boolean uncertainPlan(com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity i,
                                   PlanOperation p, Object c) {
        var candidate = planAttempt(i, p, c);
        return uncertain(planStage(i, p)) || epoch.planAttempts.values().stream().anyMatch(previous ->
                previous.identity().workflowId().equals(i.workflowId()) || previous.approvalId().equals(candidate.approvalId())
                || candidate.reservationId() != null && candidate.reservationId().equals(previous.reservationId()));
    }

    private final class PlanFacade implements OwnedPlanTx {
        private final ActionJournal.ReservedTx tx;
        private final com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity identity;
        private final PlanOperation purpose; private final Object command;
        private final Thread owner = Thread.currentThread();
        private boolean open = true, lookedUp, admitted, completed, replayed;
        private UUID token; private PlanReceipt emitted;
        private ReviewBindings reviewTicket; private ReservationBindings reservationTicket;
        PlanFacade(ActionJournal.ReservedTx tx, com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity i,
                   PlanOperation p, Object c) { this.tx=tx; identity=i; purpose=p; command=c; }
        private void bound(PlanOperation p, Object c) {
            if (!open || owner != Thread.currentThread()) throw new IllegalStateException("OWNED_PLAN_TRANSACTION_UNAVAILABLE");
            if (purpose != p || !command.equals(c)) throw stop(Status.IDENTITY_CONFLICT);
        }
        @Override public PlanReceipt lookupReview(ReviewCommand c) { bound(PlanOperation.REVIEW,c); return lookup(); }
        @Override public PlanReceipt lookupReservation(ReserveCommand c) { bound(PlanOperation.RESERVE,c); return lookup(); }
        private PlanReceipt lookup() {
            if (admitted || completed) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            requireHistoricalLane(tx, planStage(identity,purpose));
            var boundGrant=grantRow(tx,identity.grantId());
            if(boundGrant==null||!matches(planStage(identity,purpose),boundGrant)
                    ||purpose==PlanOperation.REVIEW&&boundGrant.state()!=GrantState.CONSUMED)
                throw stop(Status.IDENTITY_CONFLICT);
            lookedUp=true;
            var saved=tx.completed(planIdentity(identity,purpose,command));
            var local=tx.get(PLAN_RECEIPTS,identity.globalRequestId().toString());
            if(saved==null) {
                if(local!=null || uncertainPlan(identity,purpose,command))throw stop(Status.RECONCILIATION_UNCONFIRMED);
                return null;
            }
            if(local==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var receipt=decodePlanReceipt(local);var fingerprint=planFingerprint(purpose,command);
            if(receipt.purpose()!=purpose || !receipt.identity().equals(identity)
                    || !planReceiptMap(receipt,fingerprint).equals(local))throw stop(Status.IDENTITY_CONFLICT);
            var payload=new LinkedHashMap<String,Object>(saved);
            if(!identity.globalRequestId().toString().equals(payload.remove("requestId"))
                    || !(payload.remove("replayed") instanceof Boolean) || !payload.equals(local))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var storedApproval=tx.get(PLAN_APPROVALS,receipt.approval().approvalId().toString());
            if(storedApproval==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var currentApproval=decodeApproval(storedApproval);
            var old=receipt.approval();
            if(!approvalMap(withApprovalState(currentApproval,old.state())).equals(approvalMap(old))
                    || old.state()==ApprovalPlanState.REJECTED && currentApproval.state()!=ApprovalPlanState.REJECTED
                    || old.state()==ApprovalPlanState.RESERVED && currentApproval.state()!=ApprovalPlanState.RESERVED
                        && currentApproval.state()!=ApprovalPlanState.CONSUMED
                    || old.state()==ApprovalPlanState.AVAILABLE && currentApproval.state()!=ApprovalPlanState.AVAILABLE
                        && currentApproval.state()!=ApprovalPlanState.RESERVED && currentApproval.state()!=ApprovalPlanState.CONSUMED)
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            if(currentApproval.state()==ApprovalPlanState.CONSUMED && committedPaymentDomains(tx).stream()
                    .noneMatch(d->d.approvalId().equals(currentApproval.approvalId())))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            if(purpose==PlanOperation.REVIEW) {
                var c=(ReviewCommand)command;
                if(!c.approvalId().equals(old.approvalId()) || old.decision()!=c.decision()
                        || !c.identity().globalRequestId().equals(old.reviewRequestId())
                        || !c.identity().actorId().equals(old.reviewerActorId()) || !c.now().equals(old.createdAt())
                        || !c.expiresAt().equals(old.expiresAt()) || !c.expectedReviewSnapshotHash().equals(old.reviewSnapshotHash()))
                    throw stop(Status.IDENTITY_CONFLICT);
            } else {
                var c=(ReserveCommand)command;
                if(!c.domain().equals(receipt.domain()))throw stop(Status.IDENTITY_CONFLICT);
                var planRow=tx.get(MP_PLANS,c.domain().reservationId().toString());
                if(planRow==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                var domain=decodePaymentDomain(planRow);
                boolean reserved=domain.reservationState()==ReservationState.RESERVED && domain.approvalState()==ApprovalState.RESERVED;
                boolean consumed=domain.reservationState()==ReservationState.COMMITTED && domain.approvalState()==ApprovalState.CONSUMED;
                if(!(reserved||consumed) || !paymentDomainMap(reserved?c.domain():committed(c.domain())).equals(planRow))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                verifyPaymentRisk(tx,domain,receipt.riskPoints(),consumed?"CONSUMED":"RESERVED");
                if(consumed && committedPaymentDomains(tx).stream().noneMatch(d->d.equals(domain)))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            }
            var historyScope=receipt.approval().material().scope();
            requireHistoricalResult(tx,historyScope,receipt.approval().material().kycResultId());
            requireHistoricalResult(tx,historyScope,receipt.approval().material().loanResultId());
            if(receipt.domain()!=null)requireHistoricalArtifact(tx,historyScope,receipt.domain().targetRunId(),null);
            epoch.attempts.remove(identity.globalRequestId());epoch.planAttempts.remove(identity.globalRequestId());
            replayed=true;emitted=receipt;return receipt;
        }
        @Override public void admitReview(ReviewCommand c){bound(PlanOperation.REVIEW,c);admit();}
        @Override public void admitReservation(ReserveCommand c){bound(PlanOperation.RESERVE,c);admit();}
        private void admit(){
            requireFreshLane(tx,planStage(identity,purpose));
            if(!lookedUp||admitted||replayed||uncertainPlan(identity,purpose,command))throw stop(Status.RECONCILIATION_UNCONFIRMED);
            var grant=grantRow(tx,identity.grantId());
            if(grant==null||!matches(planStage(identity,purpose),grant)
                    ||purpose==PlanOperation.RESERVE&&grant.state()!=GrantState.ISSUED)
                throw stop(Status.IDENTITY_CONFLICT);
            token=Objects.requireNonNull(tokens.get());
            var reservation=tx.reserve(planIdentity(identity,purpose,command),token);
            if(reservation.status()!=ActionJournal.ReservationStatus.RESERVED)throw stop(Status.RECONCILIATION_UNCONFIRMED);
            admitted=true;
        }
        private void pending(){
            if(!admitted||completed)throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            tx.requirePending(planIdentity(identity,purpose,command),token);
        }
        @Override public ReviewBindings readReviewBindings(ReviewCommand c){
            bound(PlanOperation.REVIEW,c);pending();
            if(reviewTicket==null)reviewTicket=readReviewBasis(tx,identity);
            requirePlanState(tx,reviewTicket,"WAIT_APPROVAL");
            var loan=reviewTicket.evaluation().loanGrant();
            if(!identity.grantId().equals(loan.grantId())||!identity.actionId().equals(loan.actionId())
                    ||!identity.targetRunId().equals(loan.targetRunId()))throw stop(Status.IDENTITY_CONFLICT);
            return reviewTicket;
        }
        @Override public ReservationBindings readReservationBindings(ReserveCommand c){
            bound(PlanOperation.RESERVE,c);pending();
            if(reservationTicket==null)reservationTicket=readReservationBasis(tx,c);
            return reservationTicket;
        }
        @Override public PlanReceipt recordReview(ReviewCommand c,PreparedReview prepared){
            bound(PlanOperation.REVIEW,c);pending();requireFreshLane(tx,planStage(identity,purpose));
            if(prepared==null||!c.equals(prepared.command())||prepared.bindings()!=reviewTicket||reviewTicket==null
                    || !sameReview(reviewTicket,readReviewBasis(tx,identity)))throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            requirePlanState(tx,reviewTicket,"WAIT_APPROVAL");
            var a=prepared.approval();validateReviewPrepared(c,reviewTicket,a);
            if(tx.get(PLAN_APPROVALS,c.approvalId().toString())!=null)throw stop(Status.IDENTITY_CONFLICT);
            tx.put(PLAN_APPROVALS,c.approvalId().toString(),approvalMap(a));
            var workflow=new LinkedHashMap<String,Object>(tx.get("virtual_workflows",identity.workflowId().toString()));
            workflow.put("riskLimit",a.riskLimit()); workflow.put("activeJobId",null);
            workflow.put("state",c.decision()==ReviewDecision.APPROVE?"APPROVED":"REJECTED");
            workflow.put("lastDecision","ALLOW");
            workflow.put("reasonCodes",List.of(c.decision()==ReviewDecision.APPROVE?"APPROVAL_RECORDED":"REJECTION_RECORDED"));
            tx.put("virtual_workflows",identity.workflowId().toString(),workflow);
            return finishPlan(new PlanReceipt(1,purpose,identity,a,null,0));
        }
        @Override public PlanReceipt recordReservation(ReserveCommand c,PreparedReservation prepared){
            bound(PlanOperation.RESERVE,c);pending();requireFreshLane(tx,planStage(identity,purpose));
            if(prepared==null||!c.equals(prepared.command())||prepared.bindings()!=reservationTicket||reservationTicket==null
                    || !sameReservation(reservationTicket,readReservationBasis(tx,c)))throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            validateReservePrepared(c,reservationTicket,prepared);
            VirtualGrantWorkflowControl.requireApprovalUsable(tx,reservationTicket.review().workflow().scope(),c.domain().approvalId());
            if(tx.get(MP_PLANS,c.domain().reservationId().toString())!=null||tx.get(PAYMENT_RISK,c.domain().reservationId().toString())!=null
                    ||tx.rows(MP_PLANS).values().stream().anyMatch(row->c.domain().paymentId().toString().equals(row.get("paymentId"))
                        ||c.domain().approvalId().toString().equals(row.get("approvalId"))))throw stop(Status.IDENTITY_CONFLICT);
            tx.put(MP_PLANS,c.domain().reservationId().toString(),paymentDomainMap(c.domain()));
            tx.put(PLAN_APPROVALS,c.domain().approvalId().toString(),approvalMap(prepared.approval()));
            tx.put(PAYMENT_RISK,c.domain().reservationId().toString(),paymentRiskMap(c.domain(),prepared.riskPoints(),"RESERVED"));
            var workflow=new LinkedHashMap<String,Object>(tx.get("virtual_workflows",identity.workflowId().toString()));
            workflow.put("reservedRisk",Math.addExact((Integer)workflow.get("reservedRisk"),prepared.riskPoints()));
            workflow.put("state","PAYMENT_RESERVED"); workflow.put("lastDecision","ALLOW");
            workflow.put("reasonCodes",List.of("PAYMENT_RESERVED")); workflow.put("activeJobId",null);
            tx.put("virtual_workflows",identity.workflowId().toString(),workflow);
            return finishPlan(new PlanReceipt(1,purpose,identity,prepared.approval(),c.domain(),prepared.riskPoints()));
        }
        private PlanReceipt finishPlan(PlanReceipt receipt){
            var row=planReceiptMap(receipt,planFingerprint(purpose,command));
            if(CanonicalJson.write(row).getBytes(java.nio.charset.StandardCharsets.UTF_8).length>maxReceiptBytes)
                throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            tx.put(PLAN_RECEIPTS,identity.globalRequestId().toString(),row);
            var reply=new LinkedHashMap<String,Object>(row);reply.put("requestId",identity.globalRequestId().toString());
            tx.complete(planIdentity(identity,purpose,command),token,reply);
            completed=true;emitted=receipt;return receipt;
        }
    }

    private Receipt coherentEvaluation(TransactionalStore.Tx tx,GrantSnapshot grant){
        if(grant.state()!=GrantState.CONSUMED)throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
        var pointer=tx.get(BY_GRANT,grant.grantId().toString());
        if(pointer==null||!(pointer.get("requestId") instanceof String request))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var row=tx.get(RECEIPTS,request);if(row==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var receipt=decodeLocal(row);var stage=new StageCommand(receipt.identity(),grant.action());
        var global=tx.completed(journalIdentity(stage));
        if(!matches(stage,grant)||!receipt.identity().globalRequestId().toString().equals(request)||global==null
                ||!receiptMap(decode(global,stage)).equals(row)||receipt.kind()!=ReceiptKind.CONSUMPTION
                ||receipt.result()==null||receipt.result().businessConclusion()!=BusinessConclusion.POSITIVE
                ||!"AGENT_RESULT_BINDING_RECORD_1".equals(receipt.result().bindingProfile())
                ||!resultMap(receipt.result()).equals(tx.get(RESULTS,receipt.result().resultId().toString())))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        for(String[] index:new String[][]{{BY_ACTION,grant.actionId().toString()},{BY_TARGET,grant.targetRunId().toString()}}){
            var saved=tx.get(index[0],index[1]);if(saved==null||!request.equals(saved.get("requestId")))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        }
        var domains=tx.get(DOMAIN_LINKS,request);if(domains==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        for(var entry:domains.entrySet())if(!entry.getValue().equals(tx.get(DOMAIN,entry.getKey())))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return receipt;
    }
    private ReviewBindings readReviewBasis(ActionJournal.ReservedTx tx,com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity identity){
        var scope=new VirtualWorkflowLane.Scope(identity.workflowId(),identity.generation(),identity.customerId());
        VirtualGrantWorkflowControl.requireFreshBusiness(tx,scope);
        var refs=typedReferences(tx).stream().filter(r->r.workflowId().equals(scope.workflowId())&&r.generation()==scope.generation()
                &&r.customerId().equals(scope.customerId())).toList();
        TypedReference kyc=null,loan=null;GrantSnapshot kg=null,lg=null;
        for(var reference:refs){
            var grant=grantRow(tx,reference.grantId());if(grant==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            if(grant.action()==AllowedAction.EVALUATE_KYC){if(kyc!=null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);kyc=reference;kg=grant;}
            if(grant.action()==AllowedAction.CREATE_LOAN_RECOMMENDATION){if(loan!=null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);loan=reference;lg=grant;}
        }
        if(kyc==null||loan==null)throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
        var kr=coherentEvaluation(tx,kg);var lr=coherentEvaluation(tx,lg);
        if(!kg.targetRunId().equals(loan.sourceRunId())||!kr.result().resultId().equals(loan.sourceResultId())
                ||!kr.result().resultId().equals(kyc.resultId())||!lr.result().resultId().equals(loan.resultId()))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var terms=rootRiskTerms(tx,scope);
        var counters=VirtualGrantEvaluationAccounting.readVerified(tx,scope);
        if(!counters.kycCharged()||!counters.loanCharged())throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
        var w=tx.get("virtual_workflows",scope.workflowId().toString());
        var workflow=new WorkflowSnapshot(scope,(String)w.get("businessReference"),uuid(w,"documentId"),(Integer)w.get("documentVersion"),
                (Long)w.get("amountKrw"),uuid(w,"payoutAccountId"),counters.usedRisk(),counters.reservedRisk(),(Integer)w.get("riskLimit"),terms);
        for(var reference:List.of(kyc,loan))if(!reference.documentId().equals(workflow.documentId())
                ||reference.documentVersion()!=workflow.documentVersion())throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
        return new ReviewBindings(workflow,new EvaluationSnapshot(kg,kr,kyc,lg,lr,loan));
    }
    private ReservationBindings readReservationBasis(ActionJournal.ReservedTx tx,ReserveCommand c){
        var review=readReviewBasis(tx,c.identity());var row=tx.get(PLAN_APPROVALS,c.domain().approvalId().toString());
        if(row==null)throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
        requirePlanState(tx,review,"APPROVED");
        var approval=decodeApproval(row); requireReviewRecord(tx,approval,review); validateMaterial(approval.material(),review);
        var grant=grantRow(tx,c.identity().grantId());
        if(grant==null||grant.state()!=GrantState.ISSUED||grant.action()!=AllowedAction.EXECUTE_MOCK_PAYMENT
                ||!matches(new StageCommand(c.identity(),AllowedAction.EXECUTE_MOCK_PAYMENT),grant))throw stop(Status.IDENTITY_CONFLICT);
        var reference=requireTarget(tx,grant);if(reference==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        VirtualGrantWorkflowControl.requireApprovalUsable(tx,review.workflow().scope(),approval.approvalId());
        return new ReservationBindings(review,approval,grant,reference);
    }
    private static void requireReviewRecord(ActionJournal.ReservedTx tx,ApprovalSnapshot approval,ReviewBindings basis) {
        var row=tx.get(PLAN_RECEIPTS,approval.reviewRequestId().toString());
        if(row==null || !(row.get("commandFingerprint") instanceof String fingerprint)
                || !fingerprint.matches("[0-9a-f]{64}")) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var receipt=decodePlanReceipt(row); var identity=receipt.identity(); var loan=basis.evaluation().loanGrant();
        var original=receipt.approval();
        if(receipt.purpose()!=PlanOperation.REVIEW || receipt.domain()!=null || receipt.riskPoints()!=0
                || !identity.globalRequestId().equals(approval.reviewRequestId()) || !identity.actorId().equals(approval.reviewerActorId())
                || !matches(new StageCommand(identity,AllowedAction.CREATE_LOAN_RECOMMENDATION),loan)
                || original.state()!=(approval.decision()==ReviewDecision.APPROVE?ApprovalPlanState.AVAILABLE:ApprovalPlanState.REJECTED)
                || !approvalMap(withApprovalState(approval,original.state())).equals(approvalMap(original))
                || !planReceiptMap(receipt,fingerprint).equals(row)
                || !SyntheticMockPaymentPlanBinding.reviewHash(approval.material()).equals(approval.reviewSnapshotHash()))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var global=tx.completed(new ActionJournal.ActionIdentity(identity.actorId(),identity.globalRequestId(),identity.operation(),fingerprint));
        if(global==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var payload=new LinkedHashMap<String,Object>(global);
        if(!identity.globalRequestId().toString().equals(payload.remove("requestId"))
                || !(payload.remove("replayed") instanceof Boolean) || !payload.equals(row))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        validateMaterialReferences(approval.material(),basis);
    }
    private void checkPaymentIssuance(ActionJournal.ReservedTx tx,StageCommand value,GrantSnapshot parent,Receipt parentReceipt,
                                      GrantSnapshot child,PaymentIssuanceProof proof) {
        if(proof==null)throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
        var basis=readReviewBasis(tx,value.identity());
        if(!basis.evaluation().loanGrant().equals(parent)
                ||!basis.evaluation().loanReceipt().equals(parentReceipt))throw stop(Status.IDENTITY_CONFLICT);
        var a=proof.approval();var stored=tx.get(PLAN_APPROVALS,a.approvalId().toString());
        if(stored==null||!approvalMap(a).equals(stored))throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
        requireReviewRecord(tx,a,basis);
        if(a.decision()!=ReviewDecision.APPROVE || a.state()==ApprovalPlanState.REJECTED || a.state()==ApprovalPlanState.CONSUMED
                ||proof.now().isBefore(a.createdAt())||!proof.now().isBefore(a.expiresAt()))
            throw stop(Status.REFUSED_BEFORE_ADMISSION);
        if(a.riskLimit()!=basis.workflow().riskLimit()
                ||a.extraRiskLimit()!=basis.workflow().terms().additionalApprovalLimit())
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var invalidation=tx.get("virtual_grant_profile_approval_invalidations",a.approvalId().toString());
        if(invalidation!=null) {
            if(!invalidation.keySet().equals(java.util.Set.of("approval","quarantineId")))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var historical=decodeApproval(castMap(invalidation.get("approval")));
            if(historical.state()!=ApprovalPlanState.AVAILABLE&&historical.state()!=ApprovalPlanState.RESERVED
                    ||!approvalMap(withApprovalState(a,historical.state())).equals(approvalMap(historical)))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            uuid(invalidation,"quarantineId"); throw stop(Status.REFUSED_BEFORE_ADMISSION);
        }
        var d=proof.intendedPlan();
        if(d!=null && (!d.grantId().equals(child.grantId())||!d.actionId().equals(child.actionId())||!d.targetRunId().equals(child.targetRunId())
                ||!d.workflowId().equals(child.workflowId())||d.generation()!=child.generation()||!d.customerId().equals(child.customerId())
                ||!d.approvalId().equals(a.approvalId())||!d.applicationId().equals(a.material().applicationId())
                ||d.amountKrw()!=a.material().amountKrw()||!d.payoutAccountId().equals(a.material().payoutAccountId())
                ||!d.securityPolicyVersion().equals(a.material().policyVersion())
                ||d.reservationState()!=ReservationState.RESERVED||d.approvalState()!=ApprovalState.RESERVED))
            throw stop(Status.IDENTITY_CONFLICT);
        if(a.state()==ApprovalPlanState.AVAILABLE) {
            validateMaterial(a.material(),basis);
            requirePlanState(tx,basis,"APPROVED");
            VirtualGrantWorkflowControl.requireApprovalUsable(tx,basis.workflow().scope(),a.approvalId());
        } else if(a.state()==ApprovalPlanState.RESERVED) {
            if(d==null)throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            requirePlanState(tx,basis,"PAYMENT_RESERVED");
            if(!paymentDomainMap(d).equals(tx.get(MP_PLANS,d.reservationId().toString())))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            VirtualGrantWorkflowControl.requirePaymentPlanUsable(tx,basis.workflow().scope(),d.reservationId());
            int points=basis.workflow().terms().payPoints(); verifyPaymentRisk(tx,d,points,"RESERVED");
            requireReservationRecord(tx,d,a,points);
            if(a.material().usedRisk()!=basis.workflow().usedRisk()
                    ||(long)a.material().reservedRisk()+points!=basis.workflow().reservedRisk())
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        } else throw stop(Status.REFUSED_BEFORE_ADMISSION);
    }
    private static void requirePlanState(TransactionalStore.Tx tx,ReviewBindings basis,String state) {
        var workflow=tx.get("virtual_workflows",basis.workflow().scope().workflowId().toString());
        if(workflow==null||!state.equals(workflow.get("state"))||workflow.get("activeJobId")!=null
                ||!basis.evaluation().kycReceipt().result().resultId().toString().equals(workflow.get("currentKycResultId"))
                ||!basis.evaluation().loanReceipt().result().resultId().toString().equals(workflow.get("currentLoanResultId")))
            throw stop(Status.REFUSED_BEFORE_ADMISSION);
    }
    private static boolean sameReview(ReviewBindings a,ReviewBindings b){return a.workflow().equals(b.workflow())&&a.evaluation().equals(b.evaluation());}
    private static boolean sameReservation(ReservationBindings a,ReservationBindings b){return sameReview(a.review(),b.review())&&a.approval().equals(b.approval())
            &&a.paymentGrant().equals(b.paymentGrant())&&a.paymentReference().equals(b.paymentReference());}
    private static ApprovalSnapshot withApprovalState(ApprovalSnapshot a,ApprovalPlanState state){
        return new ApprovalSnapshot(a.approvalId(),a.reviewRequestId(),a.reviewerActorId(),a.decision(),a.material(),a.reviewSnapshotHash(),
                a.createdAt(),a.expiresAt(),a.extraRiskLimit(),a.riskLimit(),state);
    }
    private static void validateMaterial(ReviewMaterial m,ReviewBindings b){
        validateMaterialReferences(m,b);
        if(m.usedRisk()!=b.workflow().usedRisk()||m.reservedRisk()!=b.workflow().reservedRisk())
            throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
    }
    private static void validateMaterialReferences(ReviewMaterial m,ReviewBindings b){
        var w=b.workflow();var e=b.evaluation();
        if(!m.scope().equals(w.scope())||m.amountKrw()!=w.amountKrw()||!m.payoutAccountId().equals(w.payoutAccountId())
                ||!m.kycResultId().equals(e.kycReceipt().result().resultId())||!m.loanResultId().equals(e.loanReceipt().result().resultId())
                ||!m.documentId().equals(w.documentId())||m.documentVersion()!=w.documentVersion()||!m.policyVersion().equals(w.terms().policyVersion())
                ||m.riskLimitAfterApproval()!=Math.addExact(w.terms().baseLimit(),w.terms().additionalApprovalLimit()))throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
    }
    private static void validateReviewPrepared(ReviewCommand c,ReviewBindings b,ApprovalSnapshot a){
        validateMaterial(a.material(),b);var g=b.evaluation().loanGrant();var terms=b.workflow().terms();
        int extra=c.decision()==ReviewDecision.APPROVE?terms.additionalApprovalLimit():0;
        int limit=Math.addExact(terms.baseLimit(),extra);
        if(!c.identity().grantId().equals(g.grantId())||!c.identity().actionId().equals(g.actionId())||!c.identity().targetRunId().equals(g.targetRunId())
                ||!c.approvalId().equals(a.approvalId())||!c.identity().globalRequestId().equals(a.reviewRequestId())
                ||!c.identity().actorId().equals(a.reviewerActorId())||a.decision()!=c.decision()
                ||a.state()!=(c.decision()==ReviewDecision.APPROVE?ApprovalPlanState.AVAILABLE:ApprovalPlanState.REJECTED)
                ||!c.now().equals(a.createdAt())||!c.expiresAt().equals(a.expiresAt())||!c.now().plus(terms.approvalLifetime()).equals(c.expiresAt())
                ||a.extraRiskLimit()!=extra||a.riskLimit()!=limit||!c.expectedReviewSnapshotHash().equals(a.reviewSnapshotHash())
                ||!a.reviewSnapshotHash().equals(SyntheticMockPaymentPlanBinding.reviewHash(a.material())))throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
    }
    private static void validateReservePrepared(ReserveCommand c,ReservationBindings b,PreparedReservation p){
        var a=b.approval();var w=b.review().workflow();var g=b.paymentGrant();var d=c.domain();var r=b.paymentReference();
        validateMaterial(a.material(),b.review());
        if(a.decision()!=ReviewDecision.APPROVE||a.state()!=ApprovalPlanState.AVAILABLE||!c.now().isBefore(a.expiresAt())
                ||!a.reviewSnapshotHash().equals(c.expectedReviewSnapshotHash())||!a.reviewSnapshotHash().equals(SyntheticMockPaymentPlanBinding.reviewHash(a.material()))
                ||a.extraRiskLimit()!=w.terms().additionalApprovalLimit()||a.riskLimit()!=a.material().riskLimitAfterApproval()||w.riskLimit()!=a.riskLimit()
                ||!withApprovalState(a,ApprovalPlanState.RESERVED).equals(p.approval())||p.riskPoints()!=w.terms().payPoints()
                ||!d.approvalId().equals(a.approvalId())||!d.applicationId().equals(a.material().applicationId())
                ||d.amountKrw()!=w.amountKrw()||!d.payoutAccountId().equals(w.payoutAccountId())||!d.securityPolicyVersion().equals(w.terms().policyVersion())
                ||!g.grantId().equals(c.identity().grantId())||!r.grantId().equals(g.grantId())||r.resultId()!=null
                ||!r.sourceRunId().equals(b.review().evaluation().loanGrant().targetRunId())
                ||!r.sourceResultId().equals(b.review().evaluation().loanReceipt().result().resultId())
                ||!r.documentId().equals(w.documentId())||r.documentVersion()!=w.documentVersion()
                ||Math.addExact(Math.addExact(w.usedRisk(),w.reservedRisk()),p.riskPoints())>a.riskLimit())throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
    }
    private static void requireReservationRecord(ActionJournal.ReservedTx tx,PaymentDomain domain,ApprovalSnapshot approval,int points) {
        var matching=tx.rows(PLAN_RECEIPTS).entrySet().stream().filter(e->
                "RESERVE".equals(e.getValue().get("purpose")) && paymentDomainMap(domain).equals(e.getValue().get("domain"))).toList();
        if(matching.size()!=1)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var entry=matching.get(0);var row=entry.getValue();var receipt=decodePlanReceipt(row);var identity=receipt.identity();
        if(!(row.get("commandFingerprint") instanceof String fingerprint)||!fingerprint.matches("[0-9a-f]{64}")
                ||!entry.getKey().equals(identity.globalRequestId().toString())||receipt.purpose()!=PlanOperation.RESERVE
                ||!domain.equals(receipt.domain())||receipt.riskPoints()!=points||!approval.equals(receipt.approval())
                ||!identity.grantId().equals(domain.grantId())||!identity.actionId().equals(domain.actionId())
                ||!identity.targetRunId().equals(domain.targetRunId())||!identity.workflowId().equals(domain.workflowId())
                ||identity.generation()!=domain.generation()||!identity.customerId().equals(domain.customerId())
                ||!planReceiptMap(receipt,fingerprint).equals(row))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var global=tx.completed(new ActionJournal.ActionIdentity(identity.actorId(),identity.globalRequestId(),identity.operation(),fingerprint));
        if(global==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var payload=new LinkedHashMap<String,Object>(global);
        if(!identity.globalRequestId().toString().equals(payload.remove("requestId"))
                ||!(payload.remove("replayed") instanceof Boolean)||!payload.equals(row))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
    }
    private void consumePaymentRisk(ActionJournal.ReservedTx tx,StageCommand value,PaymentDomain domain){
        var scope=new VirtualWorkflowLane.Scope(value.identity().workflowId(),value.identity().generation(),value.identity().customerId());
        var terms=rootRiskTerms(tx,scope);
        var counters=VirtualGrantEvaluationAccounting.readVerified(tx,scope);
        verifyPaymentRisk(tx,domain,terms.payPoints(),"RESERVED");
        var approvalRow=tx.get(PLAN_APPROVALS,domain.approvalId().toString());
        if(approvalRow==null)throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var approval=decodeApproval(approvalRow);
        var basis=readReviewBasis(tx,value.identity()); requireReviewRecord(tx,approval,basis);
        requireReservationRecord(tx,domain,approval,terms.payPoints());
        if(approval.state()!=ApprovalPlanState.RESERVED||approval.decision()!=ReviewDecision.APPROVE
                ||!approval.material().scope().equals(scope)||!approval.material().applicationId().equals(domain.applicationId())
                ||approval.material().amountKrw()!=domain.amountKrw()||!approval.material().payoutAccountId().equals(domain.payoutAccountId())
                ||!approval.material().policyVersion().equals(domain.securityPolicyVersion()))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var workflow=new LinkedHashMap<String,Object>(tx.get("virtual_workflows",scope.workflowId().toString()));
        if(!"PAYMENT_RESERVED".equals(workflow.get("state")) || workflow.get("activeJobId")!=null
                || counters.reservedRisk()<terms.payPoints()
                ||Math.addExact(counters.usedRisk(),counters.reservedRisk())>(Integer)workflow.get("riskLimit"))
            throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
        workflow.put("usedRisk",Math.addExact(counters.usedRisk(),terms.payPoints()));
        workflow.put("reservedRisk",Math.subtractExact(counters.reservedRisk(),terms.payPoints()));
        workflow.put("riskLimit",terms.baseLimit()); workflow.put("state","PAID");
        workflow.put("lastDecision","ALLOW"); workflow.put("reasonCodes",List.of("PAYMENT_COMMITTED"));
        workflow.put("activeJobId",null);
        tx.put("virtual_workflows",scope.workflowId().toString(),workflow);
        tx.put(PAYMENT_RISK,domain.reservationId().toString(),paymentRiskMap(domain,terms.payPoints(),"CONSUMED"));
        tx.put(PLAN_APPROVALS,domain.approvalId().toString(),approvalMap(withApprovalState(approval,ApprovalPlanState.CONSUMED)));
    }
    private static Map<String,Object> paymentRiskMap(PaymentDomain d,int points,String state){
        return map("reservationId",d.reservationId().toString(),"paymentId",d.paymentId().toString(),"approvalId",d.approvalId().toString(),
                "grantId",d.grantId().toString(),"actionId",d.actionId().toString(),"targetRunId",d.targetRunId().toString(),
                "workflowId",d.workflowId().toString(),"generation",d.generation(),"customerId",d.customerId(),
                "policyVersion",d.securityPolicyVersion(),"points",points,"state",state);
    }
    private static void verifyPaymentRisk(TransactionalStore.Tx tx,PaymentDomain d,int points,String state){
        if(!paymentRiskMap(d,points,state).equals(tx.get(PAYMENT_RISK,d.reservationId().toString())))throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
    }

    private final class Facade implements OwnedTx {
        private final ActionJournal.ReservedTx tx;
        private final StageCommand command;
        private final Thread owner = Thread.currentThread();
        private boolean open = true, lookedUp, admitted, completed, replayed;
        private UUID token, parentAttempt;
        private boolean kycPreparationChecked;
        private String checkedInputSnapshotHash;
        private Instant currentIssuanceTime;
        private Receipt emitted;
        private EvaluationRefusal emittedRefusal;
        Facade(ActionJournal.ReservedTx tx, StageCommand command) { this.tx = tx; this.command = command; }
        private void check() {
            if (!open || owner != Thread.currentThread()) throw new IllegalStateException("OWNED_GRANT_TRANSACTION_UNAVAILABLE");
        }
        private void bound(StageCommand value) {
            check(); if (!command.equals(value)) throw stop(Status.IDENTITY_CONFLICT);
        }
        @Override public StageOutcome lookupRecordedOutcome(StageCommand value) {
            bound(value); requireHistoricalLane(tx, value);
            if (admitted || completed) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            var row = tx.get(EVALUATION_REFUSALS, value.identity().globalRequestId().toString());
            if (row == null) {
                var receipt = lookup(value);
                return receipt == null ? null : StageOutcome.of(Status.VIRTUAL_REPLAYED_IN_PROCESS, receipt, EffectKnowledge.COMMITTED_IN_PROCESS);
            }
            lookedUp = true;
            if (context != Context.APPLICATION || value.action() != AllowedAction.CREATE_LOAN_RECOMMENDATION
                    || tx.get(RECEIPTS, value.identity().globalRequestId().toString()) != null)
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var refusal = new EvaluationRefusal(1, value.identity(), uuid(row, "retainedKycResultId"));
            if (!evaluationRefusalMap(refusal).equals(row)) throw stop(Status.IDENTITY_CONFLICT);
            var saved = tx.completed(journalIdentity(value));
            if (saved == null) throw stop(Status.RECONCILIATION_UNCONFIRMED);
            var payload = new LinkedHashMap<String,Object>(saved);
            if (!value.identity().globalRequestId().toString().equals(payload.remove("requestId"))
                    || !(payload.remove("replayed") instanceof Boolean) || !payload.equals(row))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var actual = grant(value.identity().grantId());
            if (actual == null || !matches(value, actual) || actual.state() != GrantState.ISSUED
                    || tx.get(BY_GRANT, actual.grantId().toString()) != null
                    || tx.get(BY_ACTION, actual.actionId().toString()) != null
                    || tx.get(BY_TARGET, actual.targetRunId().toString()) != null)
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var target = requireTarget(tx, actual);
            if (!refusal.retainedKycResultId().equals(target.sourceResultId()) || target.resultId() != null
                    || tx.get(RESULTS, refusal.retainedKycResultId().toString()) == null)
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            requireHistoricalArtifact(tx,new VirtualWorkflowLane.Scope(actual.workflowId(),actual.generation(),actual.customerId()),
                    actual.targetRunId(),null);
            epoch.attempts.remove(value.identity().globalRequestId());
            replayed = true; emittedRefusal = refusal; return refusalOutcome(refusal);
        }
        @Override public Receipt lookup(StageCommand value) {
            bound(value);
            if (tx.get(EVALUATION_REFUSALS, value.identity().globalRequestId().toString()) != null)
                throw stop(Status.RECONCILIATION_UNCONFIRMED);
            requireHistoricalLane(tx, value);
            if (admitted || completed) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            lookedUp = true;
            var saved = tx.completed(journalIdentity(value));
            var local = tx.get(RECEIPTS, value.identity().globalRequestId().toString());
            if (saved == null) {
                if (local != null || uncertain(value))
                    throw stop(Status.RECONCILIATION_UNCONFIRMED);
                // completed() cannot distinguish absent from pending; neither is fresh admission.
                return null;
            }
            Receipt receipt = decode(saved, value);
            if (local == null || !receiptMap(receipt).equals(local)) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            GrantSnapshot grant = grant(value.identity().grantId());
            if (grant == null || (receipt.kind() == ReceiptKind.CONSUMPTION && grant.state() != GrantState.CONSUMED))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            if (!matches(value, grant)) throw stop(Status.IDENTITY_CONFLICT);
            if (receipt.kind() == ReceiptKind.CONSUMPTION) {
                if (receipt.result() == null || receipt.parentGrantId() != null
                        || !resultMap(receipt.result()).equals(tx.get(RESULTS, receipt.result().resultId().toString())))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                if (RECEIPT_BINDING_PROFILE.equals(receipt.result().bindingProfile())) verifyPaymentRecord(value, receipt.result());
                for (String[] index : new String[][] {{BY_GRANT, grant.grantId().toString()},
                        {BY_ACTION, grant.actionId().toString()}, {BY_TARGET, grant.targetRunId().toString()}}) {
                    var pointer = tx.get(index[0], index[1]);
                    if (pointer == null || !value.identity().globalRequestId().toString().equals(pointer.get("requestId")))
                        throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                }
                var domains = tx.get(DOMAIN_LINKS, value.identity().globalRequestId().toString());
                if (domains == null) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                for (var entry : domains.entrySet())
                    if (!entry.getValue().equals(tx.get(DOMAIN, entry.getKey()))) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            } else {
                var link = receipt.parentGrantId() == null ? null : tx.get(SUCCESSORS, receipt.parentGrantId().toString());
                if (receipt.result() != null || link == null || !grant.grantId().toString().equals(link.get("childGrantId")))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            }
            requireHistoricalArtifact(tx,new VirtualWorkflowLane.Scope(grant.workflowId(),grant.generation(),grant.customerId()),
                    grant.targetRunId(),receipt.result()==null?null:receipt.result().resultId());
            epoch.attempts.remove(value.identity().globalRequestId());
            replayed = true; emitted = receipt; return receipt;
        }
        @Override public void admitFresh(StageCommand value) {
            bound(value);
            requireFreshLane(tx, value);
            if (!lookedUp || admitted || replayed || uncertain(value))
                throw stop(Status.RECONCILIATION_UNCONFIRMED);
            token = Objects.requireNonNull(tokens.get());
            var reservation = tx.reserve(journalIdentity(value), token);
            if (reservation.status() != ActionJournal.ReservationStatus.RESERVED)
                throw stop(Status.RECONCILIATION_UNCONFIRMED);
            admitted = true;
        }
        @Override public void requireKycPreparation(StageCommand value, String inputSnapshotHash) {
            bound(value);
            pending(value);
            requireFreshLane(tx, value);
            if (value.action() != AllowedAction.EVALUATE_KYC || inputSnapshotHash == null
                    || !inputSnapshotHash.matches("[0-9a-f]{64}")) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            if (context == Context.APPLICATION)
                VirtualGrantEvaluationAccounting.requirePrepared(tx, value, inputSnapshotHash);
            kycPreparationChecked = true; checkedInputSnapshotHash = inputSnapshotHash;
        }
        @Override public void bindCurrentIssuanceTime(StageCommand value, Instant snapshotTime) {
            pending(value); requireFreshLane(tx,value);
            if(value.action()!=AllowedAction.EXECUTE_MOCK_PAYMENT || snapshotTime==null
                    ||snapshotTime.getEpochSecond()<0||snapshotTime.getNano()!=0
                    ||currentIssuanceTime!=null&&!currentIssuanceTime.equals(snapshotTime))
                throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            currentIssuanceTime=snapshotTime;
        }
        @Override public GrantSnapshot grant(UUID id) {
            check(); Objects.requireNonNull(id); var row = tx.get(GRANTS, id.toString());
            if (row == null) return null;
            var result = decodeGrant(row);
            if (context == Context.APPLICATION) VirtualGrantGenerationHistory.validate(tx,
                    new VirtualWorkflowLane.Scope(result.workflowId(),result.generation(),result.customerId()));
            else if (tx.get("virtual_workflows",result.workflowId().toString())!=null
                    ||tx.get("virtual_workflow_lanes",result.workflowId().toString())!=null) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            return result;
        }
        private void pending(StageCommand value) {
            bound(value);
            if (!admitted || completed) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            tx.requirePending(journalIdentity(value), token);
        }
        private GrantSnapshot validatedEvaluation(StageCommand value, ResolvedStage stage) {
            pending(value); Objects.requireNonNull(stage);
            requireFreshLane(tx, value);
            var actual = grant(value.identity().grantId());
            if (actual == null || actual.state() != GrantState.ISSUED || !actual.equals(stage.grant())
                    || !matches(value, actual)) throw stop(Status.IDENTITY_CONFLICT);
            if (stage.runStatus() != com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.RunStatus.VALIDATED
                    || stage.resultStatus() != com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.ResultStatus.VALIDATED
                    || value.action() == AllowedAction.EXECUTE_MOCK_PAYMENT
                    || !"AGENT_RESULT_BINDING_RECORD_1".equals(stage.result().bindingProfile()))
                throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            var result = stage.result();
            if (context == Context.APPLICATION) {
                var i = value.identity(); var scope = new VirtualWorkflowLane.Scope(i.workflowId(), i.generation(), i.customerId());
                var workflow = tx.get("virtual_workflows", i.workflowId().toString());
                var terms = rootRiskTerms(tx, scope);
                if (workflow == null || !"KYC_PENDING".equals(workflow.get("state")) || workflow.get("activeJobId") != null)
                    throw stop(Status.REFUSED_BEFORE_ADMISSION);
                if (!Integer.valueOf(terms.baseLimit()).equals(workflow.get("riskLimit")))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            }
            if (context == Context.APPLICATION && value.action() == AllowedAction.EVALUATE_KYC) {
                if (!kycPreparationChecked || stage.inputSnapshotHash() == null
                        || !stage.inputSnapshotHash().equals(checkedInputSnapshotHash))
                    throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
                VirtualGrantEvaluationAccounting.requirePrepared(tx, value, checkedInputSnapshotHash);
            }
            if (result.businessConclusion() == BusinessConclusion.UNCONFIRMED
                    || result.bindingBytes().length > maxReceiptBytes || result.bindingDigest().length > maxReceiptBytes)
                throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            return actual;
        }
        @Override public Receipt commit(StageCommand value, ResolvedStage stage) {
            var actual = validatedEvaluation(value, stage);
            return recordConsumption(value, actual, stage.result(), stage.domainWrites());
        }
        @Override public StageOutcome commitEvaluation(StageCommand value, ResolvedStage stage) {
            var actual = validatedEvaluation(value, stage);
            if (context == Context.APPLICATION && value.action() == AllowedAction.CREATE_LOAN_RECOMMENDATION) {
                var i = value.identity(); var scope = new VirtualWorkflowLane.Scope(i.workflowId(), i.generation(), i.customerId());
                var counters = VirtualGrantEvaluationAccounting.readVerified(tx, scope);
                var terms = rootRiskTerms(tx, scope); var workflow = tx.get("virtual_workflows", i.workflowId().toString());
                var target = requireTarget(tx, actual);
                var parentMatches = typedReferences(tx).stream().filter(r -> r.targetRunId().equals(target.sourceRunId())
                        && r.workflowId().equals(i.workflowId()) && r.generation() == i.generation()
                        && r.customerId().equals(i.customerId()) && Objects.equals(r.resultId(), target.sourceResultId())).toList();
                if (parentMatches.size() != 1 || target.resultId() != null
                        || !Objects.equals(workflow.get("currentKycResultId"), target.sourceResultId() == null ? null : target.sourceResultId().toString()))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                var parentGrant = grantRow(tx, parentMatches.get(0).grantId());
                if (parentGrant == null || parentGrant.action() != AllowedAction.EVALUATE_KYC
                        || !coherentEvaluation(tx, parentGrant).result().resultId().equals(target.sourceResultId()))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                int cost = counters.loanCharged() ? 0 : terms.loanPoints();
                if ((long) counters.usedRisk() + counters.reservedRisk() + cost > (Integer) workflow.get("riskLimit")) {
                    if (tx.get(BY_GRANT, actual.grantId().toString()) != null || tx.get(BY_ACTION, actual.actionId().toString()) != null
                            || tx.get(BY_TARGET, actual.targetRunId().toString()) != null)
                        throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                    var refusal = new EvaluationRefusal(1, i, target.sourceResultId());
                    var changed = new LinkedHashMap<String,Object>(workflow);
                    changed.put("state", "ON_HOLD"); changed.put("lastDecision", "DENY");
                    changed.put("reasonCodes", List.of("RISK_LIMIT_EXCEEDED")); changed.put("activeJobId", null);
                    tx.put("virtual_workflows", i.workflowId().toString(), changed);
                    var row = evaluationRefusalMap(refusal);
                    if (CanonicalJson.write(row).getBytes(java.nio.charset.StandardCharsets.UTF_8).length > maxReceiptBytes)
                        throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
                    tx.put(EVALUATION_REFUSALS, i.globalRequestId().toString(), row);
                    var reply = new LinkedHashMap<String,Object>(row); reply.put("requestId", i.globalRequestId().toString());
                    tx.complete(journalIdentity(value), token, reply);
                    completed = true; emittedRefusal = refusal; return refusalOutcome(refusal);
                }
            }
            return StageOutcome.of(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                    recordConsumption(value, actual, stage.result(), stage.domainWrites()), EffectKnowledge.COMMITTED_IN_PROCESS);
        }
        private Receipt recordConsumption(StageCommand value, GrantSnapshot actual, OutsidePreparedResult result,
                                          java.util.List<DomainWrite> domainWrites) {
            if (result.businessConclusion() == BusinessConclusion.UNCONFIRMED
                    || result.bindingBytes().length > maxReceiptBytes || result.bindingDigest().length > maxReceiptBytes)
                throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            for (String[] index : new String[][] {{BY_GRANT, actual.grantId().toString()},
                    {BY_ACTION, actual.actionId().toString()}, {BY_TARGET, actual.targetRunId().toString()}})
                if (tx.get(index[0], index[1]) != null) throw stop(Status.IDENTITY_CONFLICT);
            if (tx.get(RESULTS, result.resultId().toString()) != null) throw stop(Status.IDENTITY_CONFLICT);
            var target = requireTarget(tx, actual);
            if (target != null && target.resultId() != null) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            var domainLinks = new LinkedHashMap<String, Object>();
            for (var write : domainWrites) {
                if (domainLinks.put(write.id().toString(), write.value()) != null
                        || tx.get(DOMAIN, write.id().toString()) != null) throw stop(Status.IDENTITY_CONFLICT);
                tx.put(DOMAIN, write.id().toString(), write.value());
            }
            tx.put(DOMAIN_LINKS, value.identity().globalRequestId().toString(), domainLinks);
            tx.put(RESULTS, result.resultId().toString(), resultMap(result));
            if (target != null) tx.put(TARGET_BINDINGS, target.targetRunId().toString(), targetMap(new TypedReference(
                    target.workflowId(), target.generation(), target.customerId(), target.targetRunId(), target.grantId(),
                    target.actionId(), target.documentId(), target.documentVersion(), target.agentId(), target.agentVersion(),
                    target.sourceRunId(), target.sourceResultId(), result.resultId())));
            tx.put(GRANTS, actual.grantId().toString(), grantMap(new GrantSnapshot(actual.grantId(), actual.actionId(),
                    actual.targetRunId(), actual.workflowId(), actual.generation(), actual.customerId(), actual.action(), GrantState.CONSUMED)));
            var indexValue = map("requestId", value.identity().globalRequestId().toString());
            tx.put(BY_GRANT, actual.grantId().toString(), indexValue);
            tx.put(BY_ACTION, actual.actionId().toString(), indexValue);
            tx.put(BY_TARGET, actual.targetRunId().toString(), indexValue);
            if (context == Context.APPLICATION) {
                if (value.action() == AllowedAction.CREATE_LOAN_RECOMMENDATION) {
                    var phase = new AccountingPhase(tx, journalIdentity(value), value.identity(), token,
                            null, result.resultId());
                    try { VirtualGrantEvaluationAccounting.recordLoanObservation(tx, value, result.resultId(), phase); }
                    finally { phase.open = false; }
                    var workflow = new LinkedHashMap<String,Object>(tx.get("virtual_workflows", value.identity().workflowId().toString()));
                    workflow.put("currentLoanResultId", result.resultId().toString()); workflow.put("activeJobId", null);
                    boolean positive = result.businessConclusion() == BusinessConclusion.POSITIVE;
                    workflow.put("state", positive ? "WAIT_APPROVAL" : "REJECTED");
                    workflow.put("lastDecision", positive ? "WAIT_APPROVAL" : "DENY");
                    workflow.put("reasonCodes", List.of(positive ? "HUMAN_APPROVAL_REQUIRED" : "LOAN_RULE_REJECTED"));
                    tx.put("virtual_workflows", value.identity().workflowId().toString(), workflow);
                } else if (value.action() == AllowedAction.EVALUATE_KYC) {
                    var workflow = new LinkedHashMap<String,Object>(tx.get("virtual_workflows", value.identity().workflowId().toString()));
                    workflow.put("currentKycResultId", result.resultId().toString()); workflow.put("activeJobId", null);
                    if (result.businessConclusion() == BusinessConclusion.NEGATIVE) {
                        workflow.put("state", "BLOCKED"); workflow.put("lastDecision", "DENY");
                        workflow.put("reasonCodes", List.of("KYC_NEGATIVE_EVALUATION"));
                    }
                    tx.put("virtual_workflows", value.identity().workflowId().toString(), workflow);
                }
            }
            return finish(new Receipt(value.identity(), ReceiptKind.CONSUMPTION, result, null));
        }
        @Override public PaymentDomain paymentDomain(UUID reservationId) {
            check(); Objects.requireNonNull(reservationId);
            var row = tx.get(MP_PLANS, reservationId.toString());
            return row == null ? null : decodePaymentDomain(row);
        }
        @Override public Receipt commitMockPayment(StageCommand value, ResolvedPayment resolved) {
            pending(value); Objects.requireNonNull(resolved);
            requireFreshLane(tx, value);
            var actual = grant(value.identity().grantId());
            if (actual == null || actual.state() != GrantState.ISSUED || !matches(value, actual)
                    || value.action() != AllowedAction.EXECUTE_MOCK_PAYMENT) throw stop(Status.IDENTITY_CONFLICT);
            var stored = paymentDomain(resolved.domain().reservationId());
            if (!resolved.domain().equals(stored) || tx.get(MP_PAYMENTS, resolved.domain().paymentId().toString()) != null)
                throw stop(Status.IDENTITY_CONFLICT);
            var command = new PaymentCommand(value, resolved.commandDigest(), resolved.receiptInput());
            var prepared = checkResolved(command, resolved);
            if (context == Context.APPLICATION) {
                var i = value.identity();
                VirtualGrantWorkflowControl.requirePaymentPlanUsable(tx,
                        new VirtualWorkflowLane.Scope(i.workflowId(), i.generation(), i.customerId()),
                        resolved.domain().reservationId());
            }
            if (context == Context.APPLICATION) consumePaymentRisk(tx, value, resolved.domain());
            var finalDomain = committed(resolved.domain());
            tx.put(MP_PLANS, finalDomain.reservationId().toString(), paymentDomainMap(finalDomain));
            tx.put(MP_PAYMENTS, finalDomain.paymentId().toString(), paymentRecord(command, finalDomain, prepared));
            var result = new OutsidePreparedResult(finalDomain.paymentId(), BusinessConclusion.POSITIVE,
                    RECEIPT_BINDING_PROFILE, prepared.canonicalBytes(), prepared.receiptDigest());
            return recordConsumption(value, actual, result, resolved.applicableDomainWrites());
        }
        @Override public Receipt issueSuccessor(StageCommand value, UUID parentGrantId, GrantSnapshot child) {
            return issueSuccessor(value,parentGrantId,child,null);
        }
        @Override public Receipt issueSuccessor(StageCommand value, UUID parentGrantId, GrantSnapshot child, PaymentIssuanceProof proof) {
            pending(value); Objects.requireNonNull(child); Objects.requireNonNull(parentGrantId);
            requireFreshLane(tx, value);
            parentAttempt = parentGrantId;
            if (epoch.attempts.values().stream().anyMatch(attempt -> parentGrantId.equals(attempt.parent()))) throw stop(Status.RECONCILIATION_UNCONFIRMED);
            var parent = grant(parentGrantId);
            var index = tx.get(BY_GRANT, parentGrantId.toString());
            if (parent == null || parent.state() != GrantState.CONSUMED || index == null
                    || child.state() != GrantState.ISSUED || !matches(value, child)
                    || !parent.workflowId().equals(child.workflowId()) || parent.generation() != child.generation()
                    || !parent.customerId().equals(child.customerId()) || parent.actionId().equals(child.actionId())
                    || parent.targetRunId().equals(child.targetRunId()) || tx.get(SUCCESSORS, parentGrantId.toString()) != null
                    || !((parent.action() == AllowedAction.EVALUATE_KYC && child.action() == AllowedAction.CREATE_LOAN_RECOMMENDATION)
                        || (parent.action() == AllowedAction.CREATE_LOAN_RECOMMENDATION && child.action() == AllowedAction.EXECUTE_MOCK_PAYMENT)))
                throw stop(Status.IDENTITY_CONFLICT);
            var parentRow = tx.get(RECEIPTS, (String) index.get("requestId"));
            if (parentRow == null) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            Receipt parentReceipt = decodeLocal(parentRow);
            var parentCommand = new StageCommand(parentReceipt.identity(), parent.action());
            var global = tx.completed(journalIdentity(parentCommand));
            if (parentReceipt.kind() != ReceiptKind.CONSUMPTION || parentReceipt.result() == null || global == null
                    || !matches(parentCommand, parent)
                    || !parentReceipt.identity().globalRequestId().toString().equals(index.get("requestId"))
                    || !resultMap(parentReceipt.result()).equals(tx.get(RESULTS, parentReceipt.result().resultId().toString()))
                    || !receiptMap(decode(global, parentCommand)).equals(parentRow))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            // Consumption history alone is not positive business eligibility for a child.
            if (parentReceipt.result().businessConclusion() != BusinessConclusion.POSITIVE)
                throw stop(Status.REFUSED_BEFORE_ADMISSION);
            var parentTarget = requireTarget(tx, parent);
            if (parentTarget != null && !parentReceipt.result().resultId().equals(parentTarget.resultId()))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            if (context == Context.APPLICATION && child.action() == AllowedAction.EXECUTE_MOCK_PAYMENT) {
                if(proof==null||currentIssuanceTime==null||!currentIssuanceTime.equals(proof.now()))
                    throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
                checkPaymentIssuance(tx,value,parent,parentReceipt,child,proof);
            }
            uniqueGrant(tx, child);
            recordTarget(tx, child, parent.targetRunId(), parentReceipt.result().resultId());
            tx.put(GRANTS, child.grantId().toString(), grantMap(child));
            tx.put(SUCCESSORS, parentGrantId.toString(), map("childGrantId", child.grantId().toString()));
            return finish(new Receipt(value.identity(), ReceiptKind.ISSUANCE, null, parentGrantId));
        }
        private void verifyPaymentRecord(StageCommand command, OutsidePreparedResult result) {
            var row = tx.get(MP_PAYMENTS, result.resultId().toString());
            if (row == null || !row.keySet().equals(java.util.Set.of("input", "domain", "digestReference", "profileName", "profileVersion", "canonicalBytes", "receiptDigest")))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            try {
                var input = decodePaymentInput(castMap(row.get("input")));
                var domain = decodePaymentDomain(castMap(row.get("domain")));
                var stored = paymentDomain(input.reservationId());
                var described = new PaymentCommand(command, new DigestBinding((String) row.get("digestReference"),
                        input.canonicalBodyDigestAlgorithm(), input.canonicalBodyDigest()), input);
                var prepared = prepareRequested(described);
                checkDomain(input, domain);
                if (result.businessConclusion() != BusinessConclusion.POSITIVE
                        || !domain.equals(stored) || domain.reservationState() != ReservationState.COMMITTED
                        || domain.approvalState() != ApprovalState.CONSUMED || !input.paymentId().equals(result.resultId())
                        || !SyntheticMockPaymentReceiptCodec.PROFILE_NAME.equals(row.get("profileName"))
                        || !Integer.valueOf(SyntheticMockPaymentReceiptCodec.PROFILE_VERSION).equals(row.get("profileVersion"))
                        || !HexFormat.of().formatHex(prepared.canonicalBytes()).equals(row.get("canonicalBytes"))
                        || !HexFormat.of().formatHex(prepared.receiptDigest()).equals(row.get("receiptDigest"))
                        || !java.util.Arrays.equals(prepared.canonicalBytes(), result.bindingBytes())
                        || !java.util.Arrays.equals(prepared.receiptDigest(), result.bindingDigest()))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            } catch (RuntimeException malformed) { throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED); }
        }
        private Receipt finish(Receipt receipt) {
            var row = receiptMap(receipt);
            if (CanonicalJson.write(row).getBytes(java.nio.charset.StandardCharsets.UTF_8).length > maxReceiptBytes)
                throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            tx.put(RECEIPTS, receipt.identity().globalRequestId().toString(), row);
            var reply = new LinkedHashMap<String, Object>(row);
            reply.put("requestId", receipt.identity().globalRequestId().toString());
            tx.complete(journalIdentity(command), token, reply);
            completed = true; emitted = receipt; return receipt;
        }
    }

    /** Typed reference associations only; these rows never establish actual run/result authority. */
    public record TypedReference(UUID workflowId, int generation, String customerId, UUID targetRunId,
                                 UUID grantId, UUID actionId, UUID documentId, int documentVersion,
                                 String agentId, int agentVersion, UUID sourceRunId, UUID sourceResultId,
                                 UUID resultId) {
        public TypedReference {
            if (workflowId == null || generation < 1 || customerId == null || customerId.isBlank()
                    || targetRunId == null || grantId == null || actionId == null || documentId == null
                    || documentVersion < 1 || agentId == null || agentId.isBlank() || agentVersion < 1
                    || ((sourceRunId == null) != (sourceResultId == null)))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        }
        @Override public String toString() { return "TypedReference[SUPPLIED_REDACTED]"; }
    }

    public static List<TypedReference> typedReferences(TransactionalStore.Tx tx) {
        Objects.requireNonNull(tx);
        var result = new java.util.ArrayList<TypedReference>();
        for (var entry : tx.rows(TARGET_BINDINGS).entrySet()) {
            var reference = decodeTarget(entry.getValue());
            if (!entry.getKey().equals(reference.targetRunId().toString()))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            result.add(reference);
        }
        return List.copyOf(result);
    }

    /** Coherent committed reference payment scopes only; never durable payment proof. */
    public static List<PaymentDomain> committedPaymentDomains(TransactionalStore.Tx tx) {
        Objects.requireNonNull(tx);
        var result = new java.util.ArrayList<PaymentDomain>();
        try {
            for (var entry : tx.rows(MP_PAYMENTS).entrySet()) {
                var row = entry.getValue();
                if (!row.keySet().equals(java.util.Set.of("input", "domain", "digestReference", "profileName", "profileVersion", "canonicalBytes", "receiptDigest")))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                var input = decodePaymentInput(castMap(row.get("input")));
                var domain = decodePaymentDomain(castMap(row.get("domain")));
                if (!entry.getKey().equals(domain.paymentId().toString())
                        || domain.reservationState() != ReservationState.COMMITTED || domain.approvalState() != ApprovalState.CONSUMED
                        || !paymentDomainMap(domain).equals(tx.get(MP_PLANS, domain.reservationId().toString())))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                checkDomain(input, domain);
                var identity = new CommandIdentity(input.authenticatedActor(), input.globalRequestId(), input.operation(),
                        input.canonicalizationVersion(), (String) row.get("digestReference"), input.grantId(), input.actionId(),
                        input.targetRunId(), input.workflowId(), input.generation(), input.customerId());
                var command = new PaymentCommand(new StageCommand(identity, AllowedAction.EXECUTE_MOCK_PAYMENT),
                        new DigestBinding((String) row.get("digestReference"), input.canonicalBodyDigestAlgorithm(), input.canonicalBodyDigest()), input);
                var prepared = prepareRequested(command);
                var expected = paymentRecord(command, domain, prepared);
                var grant = grantRow(tx, domain.grantId());
                if (!expected.equals(row) || grant == null || grant.state() != GrantState.CONSUMED || !matches(command.stage(), grant))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                var material = new OutsidePreparedResult(domain.paymentId(), BusinessConclusion.POSITIVE,
                        RECEIPT_BINDING_PROFILE, prepared.canonicalBytes(), prepared.receiptDigest());
                var receiptRow = tx.get(RECEIPTS, identity.globalRequestId().toString());
                if (!resultMap(material).equals(tx.get(RESULTS, domain.paymentId().toString())) || receiptRow == null
                        || !receiptMap(new Receipt(identity, ReceiptKind.CONSUMPTION, material, null)).equals(receiptRow))
                    throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                requireAccountingReply(tx,journalIdentity(command.stage()),receiptRow);
                result.add(domain);
            }
        } catch (RuntimeException malformed) { throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED); }
        return List.copyOf(result);
    }

    private static Map<String, Object> targetMap(TypedReference r) {
        return map("workflowId", r.workflowId().toString(), "generation", r.generation(), "customerId", r.customerId(),
                "targetRunId", r.targetRunId().toString(), "grantId", r.grantId().toString(), "actionId", r.actionId().toString(),
                "documentId", r.documentId().toString(), "documentVersion", r.documentVersion(),
                "agentId", r.agentId(), "agentVersion", r.agentVersion(),
                "sourceRunId", r.sourceRunId() == null ? null : r.sourceRunId().toString(),
                "sourceResultId", r.sourceResultId() == null ? null : r.sourceResultId().toString(),
                "resultId", r.resultId() == null ? null : r.resultId().toString());
    }
    private static TypedReference decodeTarget(Map<String, Object> r) {
        try {
            if (!r.keySet().equals(java.util.Set.of("workflowId", "generation", "customerId", "targetRunId", "grantId",
                    "actionId", "documentId", "documentVersion", "agentId", "agentVersion", "sourceRunId", "sourceResultId", "resultId")))
                throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            return new TypedReference(uuid(r, "workflowId"), (Integer) r.get("generation"), (String) r.get("customerId"),
                    uuid(r, "targetRunId"), uuid(r, "grantId"), uuid(r, "actionId"), uuid(r, "documentId"),
                    (Integer) r.get("documentVersion"), (String) r.get("agentId"), (Integer) r.get("agentVersion"),
                    r.get("sourceRunId") == null ? null : uuid(r, "sourceRunId"),
                    r.get("sourceResultId") == null ? null : uuid(r, "sourceResultId"),
                    r.get("resultId") == null ? null : uuid(r, "resultId"));
        } catch (RuntimeException malformed) { throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED); }
    }

    private void recordTarget(TransactionalStore.Tx tx, GrantSnapshot grant, UUID sourceRun, UUID sourceResult) {
        if (context != Context.APPLICATION) return;
        var workflow = tx.get("virtual_workflows", grant.workflowId().toString());
        if (workflow == null || tx.get(TARGET_BINDINGS, grant.targetRunId().toString()) != null)
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var agents = castMap(workflow.get("typedStageAgents"));
        var agent = castMap(agents.get(grant.action().name()));
        if (!agent.keySet().equals(java.util.Set.of("agentId", "agentVersion")))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var reference = new TypedReference(grant.workflowId(), grant.generation(), grant.customerId(), grant.targetRunId(),
                grant.grantId(), grant.actionId(), uuid(workflow, "documentId"), (Integer) workflow.get("documentVersion"),
                (String) agent.get("agentId"), (Integer) agent.get("agentVersion"), sourceRun, sourceResult, null);
        tx.put(TARGET_BINDINGS, grant.targetRunId().toString(), targetMap(reference));
    }
    private TypedReference requireTarget(TransactionalStore.Tx tx, GrantSnapshot grant) {
        if (context != Context.APPLICATION) return null;
        var row = tx.get(TARGET_BINDINGS, grant.targetRunId().toString());
        if (row == null) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var r = decodeTarget(row);
        if (!r.workflowId().equals(grant.workflowId()) || r.generation() != grant.generation()
                || !r.customerId().equals(grant.customerId()) || !r.grantId().equals(grant.grantId())
                || !r.actionId().equals(grant.actionId()) || !r.targetRunId().equals(grant.targetRunId()))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return r;
    }

    private boolean uncertainRoot(RootCommand command) {
        return epoch.continuationAttempts.values().stream().anyMatch(previous -> previous.identity().workflowId().equals(command.identity().workflowId()))
                || uncertain(rootStage(command)) || epoch.rootAttempts.values().stream().anyMatch(previous ->
                command.identity().workflowId().equals(previous.identity().workflowId())
                || command.workflowPlan().application().businessReference()
                    .equals(previous.workflowPlan().application().businessReference()));
    }
    private boolean uncertain(StageCommand command) {
        var i = command.identity();
        return epoch.attempts.values().stream().anyMatch(attempt -> {
            var previous = attempt.command(); var p = previous.identity();
            return i.globalRequestId().equals(p.globalRequestId()) || i.grantId().equals(p.grantId())
                    || i.actionId().equals(p.actionId()) || i.targetRunId().equals(p.targetRunId());
        });
    }
    private static boolean matches(StageCommand command, GrantSnapshot grant) {
        var i = command.identity();
        return i.grantId().equals(grant.grantId()) && i.actionId().equals(grant.actionId())
                && i.targetRunId().equals(grant.targetRunId()) && i.workflowId().equals(grant.workflowId())
                && i.generation() == grant.generation() && i.customerId().equals(grant.customerId()) && command.action() == grant.action();
    }
    private static void uniqueGrant(TransactionalStore.Tx tx, GrantSnapshot grant) {
        if (tx.get(GRANTS, grant.grantId().toString()) != null || tx.rows(GRANTS).values().stream().anyMatch(row ->
                grant.actionId().toString().equals(row.get("actionId")) || grant.targetRunId().toString().equals(row.get("targetRunId"))))
            throw stop(Status.IDENTITY_CONFLICT);
    }
    private static ActionJournal.ActionIdentity journalIdentity(StageCommand command) {
        var i = command.identity();
        // Internal fingerprint of all eleven fields, not verification of the admitted body digest.
        return new ActionJournal.ActionIdentity(i.actorId(), i.globalRequestId(), i.operation(), CanonicalJson.sha256(identityMap(i)));
    }
    private static Map<String, Object> paymentDomainMap(PaymentDomain d) {
        return map("grantId", d.grantId().toString(), "actionId", d.actionId().toString(), "paymentId", d.paymentId().toString(),
                "targetRunId", d.targetRunId().toString(), "approvalId", d.approvalId().toString(), "reservationId", d.reservationId().toString(),
                "workflowId", d.workflowId().toString(), "generation", d.generation(), "customerId", d.customerId(),
                "applicationId", d.applicationId().toString(), "amountKrw", d.amountKrw(), "payoutAccountId", d.payoutAccountId().toString(),
                "securityPolicyVersion", d.securityPolicyVersion(), "reservationState", d.reservationState().name(), "approvalState", d.approvalState().name());
    }
    private static PaymentDomain decodePaymentDomain(Map<String, Object> d) {
        if (!d.keySet().equals(java.util.Set.of("grantId", "actionId", "paymentId", "targetRunId", "approvalId", "reservationId",
                "workflowId", "generation", "customerId", "applicationId", "amountKrw", "payoutAccountId", "securityPolicyVersion",
                "reservationState", "approvalState"))) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return new PaymentDomain(uuid(d, "grantId"), uuid(d, "actionId"), uuid(d, "paymentId"), uuid(d, "targetRunId"),
                uuid(d, "approvalId"), uuid(d, "reservationId"), uuid(d, "workflowId"), (Integer) d.get("generation"),
                (String) d.get("customerId"), uuid(d, "applicationId"), (Long) d.get("amountKrw"), uuid(d, "payoutAccountId"),
                (String) d.get("securityPolicyVersion"), ReservationState.valueOf((String) d.get("reservationState")),
                ApprovalState.valueOf((String) d.get("approvalState")));
    }
    private static Map<String, Object> paymentInputMap(SyntheticMockPaymentReceiptCodec.Input i) {
        return map("globalRequestId", i.globalRequestId().toString(), "authenticatedActor", i.authenticatedActor(),
                "operation", i.operation(), "canonicalizationVersion", i.canonicalizationVersion(),
                "canonicalBodyDigestAlgorithm", i.canonicalBodyDigestAlgorithm(), "canonicalBodyDigest", HexFormat.of().formatHex(i.canonicalBodyDigest()),
                "grantId", i.grantId().toString(), "actionId", i.actionId().toString(), "paymentId", i.paymentId().toString(),
                "targetRunId", i.targetRunId().toString(), "approvalId", i.approvalId().toString(), "reservationId", i.reservationId().toString(),
                "workflowId", i.workflowId().toString(), "generation", i.generation(), "customerId", i.customerId(),
                "applicationId", i.applicationId().toString(), "amountKrw", i.amountKrw(), "payoutAccountId", i.payoutAccountId().toString(),
                "securityPolicyVersion", i.securityPolicyVersion(), "grantAction", i.grantAction(),
                "reservationStateAtCommit", i.reservationStateAtCommit(), "approvalStateAtCommit", i.approvalStateAtCommit());
    }
    private static SyntheticMockPaymentReceiptCodec.Input decodePaymentInput(Map<String, Object> i) {
        if (!i.keySet().equals(java.util.Set.of("globalRequestId", "authenticatedActor", "operation", "canonicalizationVersion",
                "canonicalBodyDigestAlgorithm", "canonicalBodyDigest", "grantId", "actionId", "paymentId", "targetRunId", "approvalId",
                "reservationId", "workflowId", "generation", "customerId", "applicationId", "amountKrw", "payoutAccountId",
                "securityPolicyVersion", "grantAction", "reservationStateAtCommit", "approvalStateAtCommit")))
            throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return new SyntheticMockPaymentReceiptCodec.Input(uuid(i, "globalRequestId"), (String) i.get("authenticatedActor"),
                (String) i.get("operation"), (String) i.get("canonicalizationVersion"), (String) i.get("canonicalBodyDigestAlgorithm"),
                HexFormat.of().parseHex((String) i.get("canonicalBodyDigest")), uuid(i, "grantId"), uuid(i, "actionId"), uuid(i, "paymentId"),
                uuid(i, "targetRunId"), uuid(i, "approvalId"), uuid(i, "reservationId"), uuid(i, "workflowId"), (Integer) i.get("generation"),
                (String) i.get("customerId"), uuid(i, "applicationId"), (Long) i.get("amountKrw"), uuid(i, "payoutAccountId"),
                (String) i.get("securityPolicyVersion"), (String) i.get("grantAction"), (String) i.get("reservationStateAtCommit"),
                (String) i.get("approvalStateAtCommit"));
    }
    private static Map<String, Object> paymentRecord(PaymentCommand command, PaymentDomain domain,
                                                  SyntheticMockPaymentReceiptCodec.Prepared prepared) {
        return map("input", paymentInputMap(command.expectedReceipt()), "domain", paymentDomainMap(domain),
                "digestReference", command.admittedCommandDigest().identityDigestReference(), "profileName", prepared.profileName(),
                "profileVersion", prepared.profileVersion(), "canonicalBytes", HexFormat.of().formatHex(prepared.canonicalBytes()),
                "receiptDigest", HexFormat.of().formatHex(prepared.receiptDigest()));
    }
    @SuppressWarnings("unchecked") private static Map<String, Object> castMap(Object value) {
        if (!(value instanceof Map<?, ?>)) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return (Map<String, Object>) value;
    }
    private static Map<String,Object> evaluationRefusalMap(EvaluationRefusal r) {
        return map("recordVersion", r.version(), "recordProfile", "VIRTUAL_LOAN_EVALUATION_REFUSAL_1", "identity", identityMap(r.identity()),
                "retainedKycResultId", r.retainedKycResultId().toString(), "reason", r.reason(), "state", r.state(), "decision", r.decision());
    }
    private static StageOutcome refusalOutcome(EvaluationRefusal refusal) {
        return new StageOutcome(Status.REFUSED_BEFORE_ADMISSION, null,
                EffectKnowledge.NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION, refusal);
    }
    private static Map<String, Object> identityMap(CommandIdentity i) {
        return map("actorId", i.actorId(), "globalRequestId", i.globalRequestId().toString(), "operation", i.operation(),
                "canonicalizationVersion", i.canonicalizationVersion(), "canonicalBodyDigest", i.canonicalBodyDigest(),
                "grantId", i.grantId().toString(), "actionId", i.actionId().toString(), "targetRunId", i.targetRunId().toString(),
                "workflowId", i.workflowId().toString(), "generation", i.generation(), "customerId", i.customerId());
    }
    private static CommandIdentity decodeIdentity(Map<String, Object> r) {
        return new CommandIdentity((String) r.get("actorId"), uuid(r, "globalRequestId"), (String) r.get("operation"),
                (String) r.get("canonicalizationVersion"), (String) r.get("canonicalBodyDigest"), uuid(r, "grantId"),
                uuid(r, "actionId"), uuid(r, "targetRunId"), uuid(r, "workflowId"), (Integer) r.get("generation"), (String) r.get("customerId"));
    }
    private static Map<String, Object> grantMap(GrantSnapshot g) {
        return map("grantId", g.grantId().toString(), "actionId", g.actionId().toString(), "targetRunId", g.targetRunId().toString(),
                "workflowId", g.workflowId().toString(), "generation", g.generation(), "customerId", g.customerId(), "action", g.action().name(), "state", g.state().name());
    }
    private static GrantSnapshot decodeGrant(Map<String, Object> g) {
        return new GrantSnapshot(uuid(g, "grantId"), uuid(g, "actionId"), uuid(g, "targetRunId"), uuid(g, "workflowId"),
                (Integer) g.get("generation"), (String) g.get("customerId"), AllowedAction.valueOf((String) g.get("action")), GrantState.valueOf((String) g.get("state")));
    }
    private static Map<String, Object> resultMap(OutsidePreparedResult r) {
        return map("resultId", r.resultId().toString(), "businessConclusion", r.businessConclusion().name(),
                "bindingProfile", r.bindingProfile(), "bindingBytes", HexFormat.of().formatHex(r.bindingBytes()),
                "bindingDigest", HexFormat.of().formatHex(r.bindingDigest()));
    }
    private static OutsidePreparedResult decodeResult(Map<String, Object> r) {
        return new OutsidePreparedResult(uuid(r, "resultId"), BusinessConclusion.valueOf((String) r.get("businessConclusion")),
                (String) r.get("bindingProfile"), HexFormat.of().parseHex((String) r.get("bindingBytes")), HexFormat.of().parseHex((String) r.get("bindingDigest")));
    }
    private static Map<String, Object> receiptMap(Receipt r) {
        return map("recordVersion", 1, "recordProfile", "VIRTUAL_GRANT_RECEIPT_1", "identity", identityMap(r.identity()), "kind", r.kind().name(),
                "result", r.result() == null ? null : resultMap(r.result()), "parentGrantId", r.parentGrantId() == null ? null : r.parentGrantId().toString());
    }
    @SuppressWarnings("unchecked") private static Receipt decodeLocal(Map<String, Object> row) {
        if (!row.keySet().equals(java.util.Set.of("recordVersion", "recordProfile", "identity", "kind", "result", "parentGrantId"))
                || !Integer.valueOf(1).equals(row.get("recordVersion"))
                || !"VIRTUAL_GRANT_RECEIPT_1".equals(row.get("recordProfile"))) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return new Receipt(decodeIdentity((Map<String, Object>) row.get("identity")), ReceiptKind.valueOf((String) row.get("kind")),
                row.get("result") == null ? null : decodeResult((Map<String, Object>) row.get("result")),
                row.get("parentGrantId") == null ? null : uuid(row, "parentGrantId"));
    }
    private static Receipt decode(Map<String, Object> row, StageCommand command) {
        if (!row.keySet().equals(java.util.Set.of("recordVersion", "recordProfile", "identity", "kind", "result", "parentGrantId", "requestId", "replayed"))
                || !command.identity().globalRequestId().toString().equals(row.get("requestId"))
                || !(row.get("replayed") instanceof Boolean)) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        var payload = new LinkedHashMap<String, Object>(row); payload.remove("requestId"); payload.remove("replayed");
        Receipt receipt = decodeLocal(payload);
        if (!receipt.identity().equals(command.identity())) throw stop(Status.IDENTITY_CONFLICT);
        return receipt;
    }
    private static UUID uuid(Map<String, Object> row, String name) { return UUID.fromString((String) row.get(name)); }
    private static Map<String, Object> map(Object... fields) {
        var result = new LinkedHashMap<String, Object>();
        for (int i = 0; i < fields.length; i += 2) result.put((String) fields[i], fields[i + 1]);
        return CanonicalJson.immutableObject(result);
    }
}
