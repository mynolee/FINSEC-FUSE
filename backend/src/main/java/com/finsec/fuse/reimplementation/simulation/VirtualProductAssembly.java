package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Manual, explicitly virtual composition of one product graph. Construction has no
 * model, network, server, actor registry, database, seed, worker or authority side effects.
 * Production identities/policies/providers are never inferred.
 */
public final class VirtualProductAssembly {
    public record Inputs(VirtualTransactionalStore store, SimulationSpec.Catalog catalog,
                         SimulationSpec.RiskTerms riskTerms, SimulationAccess.Authority authority,
                         VirtualQuarantineService.RemediationVerifier remediationVerifier,
                         List<VirtualExperimentService.FixtureSet> fixtureSets,
                         VirtualExperimentService.PairEvaluator pairEvaluator, Clock clock,
                         Supplier<UUID> ids, WorkflowHttpController.ActorPort startResumeActors,
                         SimulationApiController.HttpActors otherActors, HttpLimits httpLimits) {
        public Inputs {
            Objects.requireNonNull(store); Objects.requireNonNull(catalog); Objects.requireNonNull(riskTerms);
            Objects.requireNonNull(authority); Objects.requireNonNull(remediationVerifier);
            fixtureSets = List.copyOf(Objects.requireNonNull(fixtureSets));
            Objects.requireNonNull(pairEvaluator); Objects.requireNonNull(clock); Objects.requireNonNull(ids);
            Objects.requireNonNull(startResumeActors); Objects.requireNonNull(otherActors); Objects.requireNonNull(httpLimits);
        }
    }
    public record TypedInputs(
            com.finsec.fuse.reimplementation.auth.SyntheticGrantIssuerBindings.Prepared issuerRegistry,
            VirtualGrantWorkflowBridge.Facts facts, Supplier<UUID> journalTokens, int maximumReceiptBytes) {
        public TypedInputs {
            Objects.requireNonNull(issuerRegistry); Objects.requireNonNull(facts); Objects.requireNonNull(journalTokens);
            if (maximumReceiptBytes < 1) throw new IllegalArgumentException("INVALID_TYPED_WORKFLOW_INPUTS");
        }
        @Override public String toString() { return "TypedInputs[EXPLICIT_REFERENCE_ONLY]"; }
    }
    public record ContinuationInputs(VirtualGrantWorkflowBridge.ContinuationFacts facts, SimulationSpec.Catalog catalog) {
        public ContinuationInputs { Objects.requireNonNull(facts); Objects.requireNonNull(catalog); }
        @Override public String toString() { return "ContinuationInputs[EXPLICIT_REFERENCE_ONLY]"; }
    }
    public record DeliveryInputs(java.util.concurrent.Executor executor,
            com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef workflowActor,
            VirtualKycJobAdapter.ProviderPort provider, Supplier<UUID> actionIds, int maximumInFlight) {
        public DeliveryInputs {
            Objects.requireNonNull(executor); Objects.requireNonNull(workflowActor);
            Objects.requireNonNull(provider); Objects.requireNonNull(actionIds);
            if (maximumInFlight < 1) throw new IllegalArgumentException("INVALID_DELIVERY_CAPACITY");
        }
        @Override public String toString() { return "DeliveryInputs[EXPLICIT_REDACTED]"; }
    }
    private final VirtualGrantWorkflowBridge typedWorkflows;
    private final VirtualTransactionalStore store;
    private final VirtualWorkflowService workflows;
    private final VirtualQuarantineService quarantines;
    private final VirtualExperimentService experiments;
    private final VirtualAgentBridge agentBridge;
    private final SimulationHarness http;
    private final VirtualDeliveryCoordinator deliveries;

    private VirtualProductAssembly(Inputs input) { this(input, null); }
    private VirtualProductAssembly(Inputs input, TypedInputs typed) { this(input, typed, null); }
    private VirtualProductAssembly(Inputs input, TypedInputs typed, ContinuationInputs continuation) {
        this(input, typed, continuation, null);
    }
    private VirtualProductAssembly(Inputs input, TypedInputs typed, ContinuationInputs continuation, DeliveryInputs delivery) {
        store = input.store();
        var link = delivery == null ? null : new DeliveryLink();
        if (continuation != null && (typed == null || typed.facts() != continuation.facts()))
            throw new IllegalArgumentException("CONTINUATION_FACT_SOURCE_MISMATCH");
        if (continuation != null && continuation.catalog() != input.catalog())
            throw new IllegalArgumentException("CONTINUATION_CATALOG_SOURCE_MISMATCH");
        if (typed == null) typedWorkflows = null;
        else {
            var journal = new com.finsec.fuse.reimplementation.grant.VirtualGrantTransactionJournal(
                    store, typed.journalTokens(), typed.maximumReceiptBytes());
            typedWorkflows = continuation == null
                    ? new VirtualGrantWorkflowBridge(journal, typed.issuerRegistry(), typed.facts())
                    : new VirtualGrantWorkflowBridge(journal, typed.issuerRegistry(), typed.facts(), continuation.facts(), continuation.catalog());
        }
        var access = new SimulationAccess(input.authority());
        workflows = new VirtualWorkflowService(store, input.catalog(), input.riskTerms(), access, input.clock(), input.ids(), link);
        quarantines = new VirtualQuarantineService(store, input.catalog(), access, workflows,
                input.remediationVerifier(), input.clock(), input.ids());
        experiments = new VirtualExperimentService(store, access, input.fixtureSets(), input.pairEvaluator(), input.ids(), link);
        agentBridge = new VirtualAgentBridge(workflows);
        deliveries = delivery == null ? null : new VirtualDeliveryCoordinator(delivery.executor(), delivery.workflowActor(),
                workflows, new VirtualKycJobAdapter(store, agentBridge, delivery.provider()), experiments,
                delivery.actionIds(), delivery.maximumInFlight());
        if (link != null) link.bind(deliveries);
        http = SimulationHarness.compose(workflows, quarantines, experiments,
                input.startResumeActors(), input.otherActors(), input.httpLimits());
    }

    private static final class DeliveryLink implements VirtualDeliveryCoordinator.Notifications {
        private volatile VirtualDeliveryCoordinator target;
        private void bind(VirtualDeliveryCoordinator value) {
            if (target != null || value == null) throw new IllegalStateException("DELIVERY_LINK_ALREADY_BOUND");
            target = value;
        }
        private VirtualDeliveryCoordinator target() { return Objects.requireNonNull(target, "Delivery link is not bound"); }
        @Override public void kycCommitted(UUID workflowId, int generation) { target().enqueueKyc(workflowId, generation); }
        @Override public void paymentCommitted(UUID workflowId, int generation) { target().enqueuePayment(workflowId, generation); }
        @Override public void experimentCommitted(com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef owner, UUID experimentId) {
            target().enqueueExperiment(owner, experimentId);
        }
    }
    /** Explicit configured legacy delivery; constructing the graph starts no executor or provider. */
    public static VirtualProductAssembly composeWithDelivery(Inputs input, DeliveryInputs delivery) {
        return new VirtualProductAssembly(Objects.requireNonNull(input), null, null, Objects.requireNonNull(delivery));
    }
    public static VirtualProductAssembly compose(Inputs input) {
        return new VirtualProductAssembly(Objects.requireNonNull(input));
    }
    /** Explicit opt-in; existing compose/HTTP paths remain the legacy graph. No root or job is created here. */
    public static VirtualProductAssembly composeTyped(Inputs input, TypedInputs typed) {
        return new VirtualProductAssembly(Objects.requireNonNull(input), Objects.requireNonNull(typed));
    }
    /** Separate explicit continuation opt-in over the same store, facts and prepared registry. */
    public static VirtualProductAssembly composeTyped(Inputs input, TypedInputs typed, ContinuationInputs continuation) {
        return new VirtualProductAssembly(Objects.requireNonNull(input), Objects.requireNonNull(typed),
                Objects.requireNonNull(continuation));
    }
    public VirtualGrantWorkflowBridge grantWorkflows() {
        if (typedWorkflows == null) throw new IllegalStateException("TYPED_WORKFLOW_NOT_CONFIGURED");
        return typedWorkflows;
    }
    /** Explicit host-owned recovery/diagnostic access; not an HTTP operation or authority grant. */
    public VirtualDeliveryCoordinator deliveries() {
        if (deliveries == null) throw new IllegalStateException("VIRTUAL_DELIVERY_NOT_CONFIGURED");
        return deliveries;
    }
    public String mode() { return VirtualTransactionalStore.MODE; }
    public VirtualTransactionalStore store() { return store; }
    public VirtualWorkflowService workflows() { return workflows; }
    public VirtualQuarantineService quarantines() { return quarantines; }
    public VirtualExperimentService experiments() { return experiments; }
    public VirtualAgentBridge agentBridge() { return agentBridge; }
    public SimulationHarness http() { return http; }
    /** A synchronous synthetic provider is mandatory; constructing this adapter dispatches nothing. */
    public VirtualKycJobAdapter kycJobs(VirtualKycJobAdapter.ProviderPort provider) {
        return new VirtualKycJobAdapter(store, agentBridge, Objects.requireNonNull(provider));
    }
}
