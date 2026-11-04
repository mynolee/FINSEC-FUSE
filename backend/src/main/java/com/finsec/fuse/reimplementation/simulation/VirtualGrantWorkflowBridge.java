package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.auth.SyntheticGrantIssuerBindings;
import com.finsec.fuse.reimplementation.grant.*;
import java.util.Objects;
import java.util.UUID;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.*;

/** Explicit non-HTTP virtual caller. Construction never initializes a workflow or dispatches work. */
public final class VirtualGrantWorkflowBridge {
    /** One local source for root, stage and payment; no provider/IO/key acquisition inside a transaction. */
    public interface Facts extends VirtualMockPaymentFactResolver.LocalPaymentFacts,
            SyntheticRootProvisionService.CurrentRootFactResolver,
            SyntheticKycPreparationBinding.PreparationResolver,
            SyntheticMockPaymentPlanService.LocalPlanFacts { }
    /** Explicit same-source continuation capability; existing Facts remains source compatible. */
    public interface ContinuationFacts extends Facts,
            SyntheticTypedContinuationService.CurrentContinuationFactResolver { }
    private final SyntheticRootProvisionService roots;
    private final GrantStageTransactionService stages;
    private final SyntheticMockPaymentTransactionService payments;
    private final SyntheticKycPreparationService preparations;
    private final SyntheticMockPaymentPlanService plans;
    private final SyntheticTypedContinuationService continuations;

    public VirtualGrantWorkflowBridge(VirtualGrantTransactionJournal journal,
            SyntheticGrantIssuerBindings.Prepared registry, Facts facts) {
        this(journal, registry, facts, null, null, false);
    }
    public VirtualGrantWorkflowBridge(VirtualGrantTransactionJournal journal,
            SyntheticGrantIssuerBindings.Prepared registry, Facts facts, ContinuationFacts continuationFacts) {
        this(journal, registry, facts, Objects.requireNonNull(continuationFacts), null, true);
    }
    public VirtualGrantWorkflowBridge(VirtualGrantTransactionJournal journal,
            SyntheticGrantIssuerBindings.Prepared registry, Facts facts, ContinuationFacts continuationFacts,
            SimulationSpec.Catalog catalog) {
        this(journal, registry, facts, Objects.requireNonNull(continuationFacts), Objects.requireNonNull(catalog), true);
    }
    private VirtualGrantWorkflowBridge(VirtualGrantTransactionJournal journal,
            SyntheticGrantIssuerBindings.Prepared registry, Facts facts,
            ContinuationFacts continuationFacts, SimulationSpec.Catalog catalog, boolean continuationEnabled) {
        Objects.requireNonNull(journal); Objects.requireNonNull(registry); Objects.requireNonNull(facts);
        if (continuationEnabled && facts != continuationFacts)
            throw new IllegalArgumentException("CONTINUATION_FACT_SOURCE_MISMATCH");
        journal.requireApplicationContext();
        roots = new SyntheticRootProvisionService(journal, new SyntheticRootProvisionService.CurrentRootFactResolver() {
            @Override public Gate current(SyntheticRootProvisionService.RootServerContext context,
                    RootCommand command, OwnedRootProvisionPort.OwnedRootTx tx) {
                return facts.current(context, command, tx);
            }
            @Override public ResolvedRootProvision resolve(SyntheticRootProvisionService.RootServerContext context,
                    RootCommand command, CurrentBindings bindings, OwnedRootProvisionPort.OwnedRootTx tx) {
                ResolvedRootProvision resolved = facts.resolve(context, command, bindings, tx);
                if (resolved == null || resolved.issuerFacts().registry() != registry)
                    throw OwnedGrantTransactionPort.stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
                return resolved;
            }
        });
        stages = new GrantStageTransactionService(journal, new VirtualGrantFactResolver(registry, facts));
        payments = new SyntheticMockPaymentTransactionService(journal, new VirtualMockPaymentFactResolver(registry, facts));
        preparations = new SyntheticKycPreparationService(journal, facts);
        plans = new SyntheticMockPaymentPlanService(journal, facts);
        var continuationResolver = new SyntheticTypedContinuationService.CurrentContinuationFactResolver() {
            @Override public Gate current(SyntheticTypedContinuationService.ContinuationServerContext context,
                    SyntheticTypedContinuationBinding.ContinuationCommand command,
                    OwnedTypedContinuationPort.OwnedContinuationTx tx) {
                return continuationFacts.current(context, command, tx);
            }
            @Override public SyntheticTypedContinuationBinding.ResolvedContinuation resolve(
                    SyntheticTypedContinuationService.ContinuationServerContext context,
                    SyntheticTypedContinuationBinding.ContinuationCommand command,
                    SyntheticTypedContinuationBinding.CurrentBindings bindings,
                    OwnedTypedContinuationPort.OwnedContinuationTx tx) {
                var resolved = continuationFacts.resolve(context, command, bindings, tx);
                if (resolved == null || resolved.issuerFacts() == null
                        || resolved.issuerFacts().registry() != registry)
                    throw OwnedGrantTransactionPort.stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
                return resolved;
            }
        };
        continuations = !continuationEnabled ? null : catalog == null
                ? new SyntheticTypedContinuationService(journal, continuationResolver)
                : new SyntheticTypedContinuationService(journal, continuationResolver, catalog);
    }
    public RootOutcome startTyped(SyntheticRootProvisionService.RootServerContext context, RootCommand command) {
        return roots.provisionRoot(context, command);
    }
    public StageOutcome completeAgentStage(ServerContext context, StageCommand command, OutsidePreparedResult prepared) {
        return stages.completeStage(context, command, prepared);
    }
    public StageOutcome completeMockPayment(ServerContext context, PaymentCommand command) {
        return payments.completePayment(context, command);
    }
    public StageOutcome issueSuccessor(ServerContext context, StageCommand command, UUID parentGrantId, GrantSnapshot child) {
        return issueSuccessor(context, command, parentGrantId, child, null);
    }
    public StageOutcome issueSuccessor(ServerContext context, StageCommand command, UUID parentGrantId, GrantSnapshot child,
            PaymentIssuanceProof proof) {
        return stages.issueSuccessor(context, command, parentGrantId, child, proof);
    }
    public RootOutcome reconcileRoot(SyntheticRootProvisionService.RootServerContext context, RootCommand command) {
        return roots.reconcileRoot(context, command);
    }
    public StageOutcome reconcileStage(ServerContext context, StageCommand command) {
        return stages.reconcile(context, command);
    }
    public StageOutcome reconcilePayment(ServerContext context, PaymentCommand command) {
        return payments.reconcile(context, command);
    }
    public SyntheticKycPreparationBinding.PreparationOutcome prepareKyc(ServerContext context,
            SyntheticKycPreparationBinding.PreparationCommand command) {
        return preparations.prepare(context, command);
    }
    public SyntheticKycPreparationBinding.PreparationOutcome reconcilePreparation(ServerContext context,
            SyntheticKycPreparationBinding.PreparationCommand command) {
        return preparations.reconcile(context, command);
    }
    public SyntheticMockPaymentPlanBinding.PlanOutcome reviewPayment(SyntheticMockPaymentPlanService.PlanServerContext context,
            SyntheticMockPaymentPlanBinding.ReviewCommand command) {
        return plans.review(context, command);
    }
    public SyntheticMockPaymentPlanBinding.PlanOutcome reservePayment(SyntheticMockPaymentPlanService.PlanServerContext context,
            SyntheticMockPaymentPlanBinding.ReserveCommand command) {
        return plans.reserve(context, command);
    }
    public SyntheticMockPaymentPlanBinding.PlanOutcome reconcilePaymentReview(SyntheticMockPaymentPlanService.PlanServerContext context,
            SyntheticMockPaymentPlanBinding.ReviewCommand command) {
        return plans.reconcileReview(context, command);
    }
    public SyntheticMockPaymentPlanBinding.PlanOutcome reconcilePaymentReservation(SyntheticMockPaymentPlanService.PlanServerContext context,
            SyntheticMockPaymentPlanBinding.ReserveCommand command) {
        return plans.reconcileReservation(context, command);
    }
    public SyntheticTypedContinuationBinding.ContinuationOutcome continueTyped(
            SyntheticTypedContinuationService.ContinuationServerContext context,
            SyntheticTypedContinuationBinding.ContinuationCommand command) {
        return continuationService().continueWorkflow(context, command);
    }
    public SyntheticTypedContinuationBinding.ContinuationOutcome reconcileContinuation(
            SyntheticTypedContinuationService.ContinuationServerContext context,
            SyntheticTypedContinuationBinding.ContinuationCommand command) {
        return continuationService().reconcileContinuation(context, command);
    }
    private SyntheticTypedContinuationService continuationService() {
        if (continuations == null) throw new IllegalStateException("TYPED_CONTINUATION_NOT_CONFIGURED");
        return continuations;
    }
    public boolean actualAuthorityEstablished() { return false; }
    public boolean durable() { return false; }
    @Override public String toString() { return "VirtualGrantWorkflowBridge[NON_AUTHORIZING]"; }
}
