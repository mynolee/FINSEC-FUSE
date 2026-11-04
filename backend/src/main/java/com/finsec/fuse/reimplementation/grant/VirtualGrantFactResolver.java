package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.*;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.Fact;

/** Local in-process composition of supplied facts; never actual authorization or key custody. */
public final class VirtualGrantFactResolver implements CurrentFactResolver {
    public record Descriptor(String actorAlias, SyntheticGrantIssuerBindings.Binding issuerBinding,
                             String keyOwnerReference, String keyVersion) {
        public Descriptor {
            if (actorAlias == null || actorAlias.isBlank() || keyOwnerReference == null || keyOwnerReference.isBlank()
                    || keyVersion == null || keyVersion.isBlank()) throw invalid();
            Objects.requireNonNull(issuerBinding);
        }
        @Override public String toString() { return "VirtualDescriptor[REDACTED]"; }
    }
    public record KeyFacts(SyntheticGrantKeyLifecycleAssessment.KeyBinding expected,
                           SyntheticGrantKeyLifecycleAssessment.KeySnapshot snapshot,
                           SyntheticGrantKeyLifecycleAssessment.Ordering ordering,
                           SyntheticGrantKeyLifecycleAssessment.MaterialFact material,
                           Fact issuanceBindingChanged,
                           SyntheticGrantKeyLifecycleAssessment.CurrentUseFacts currentUse) {
        @Override public String toString() { return "VirtualKeyFacts[REDACTED]"; }
    }
    public record AgentFacts(SyntheticGrantV2Codec.Profile codecProfile,
                             List<SyntheticGrantChainStructure.Node> nodes,
                             SyntheticGrantStageBinding.BindingProfile bindingProfile,
                             SyntheticGrantStageBinding.RunSnapshot run,
                             SyntheticGrantStageBinding.ResultSnapshot result,
                             SyntheticGrantStageBinding.WorkflowSnapshot workflow,
                             SyntheticGrantStageBinding.ExpectedResultBinding expectedResult,
                             ResolvedStage resolved) {
        public AgentFacts { nodes = List.copyOf(nodes); }
        @Override public String toString() { return "VirtualAgentFacts[REDACTED]"; }
    }
    public record IssuanceFacts(UUID parentGrantId, GrantSnapshot child,
                                SyntheticGrantV2Codec.Profile codecProfile,
                                List<SyntheticGrantChainStructure.Node> nodes) {
        public IssuanceFacts { nodes = List.copyOf(nodes); }
        @Override public String toString() { return "VirtualIssuanceFacts[REDACTED]"; }
    }
    public record Snapshot(String version, Descriptor descriptor,
                           SyntheticGrantReplayAssessment.CurrentReadFacts currentRead,
                           SyntheticGrantTemporalAssessment.TemporalFacts temporal,
                           SyntheticGrantTemporalAssessment.RevocationFacts revocation,
                           KeyFacts key, AgentFacts agent, IssuanceFacts issuance) {
        public Snapshot { if (version == null || version.isBlank()) throw invalid(); }
        @Override public String toString() { return "VirtualFactSnapshot[REDACTED]"; }
    }
    /** Local immutable observation and version comparison in this exact owned transaction; no IO/provider. */
    public interface LocalFacts {
        Snapshot load(ServerContext context, StageCommand command, OwnedTx tx);
        Fact versionChanged(ServerContext context, StageCommand command, OwnedTx tx, String expectedVersion);
    }
    private final SyntheticGrantIssuerBindings.Prepared registry;
    private final LocalFacts facts;
    public VirtualGrantFactResolver(SyntheticGrantIssuerBindings.Prepared registry, LocalFacts facts) {
        this.registry = Objects.requireNonNull(registry); this.facts = Objects.requireNonNull(facts);
    }
    public boolean actualAuthorizationEstablished() { return false; }
    public boolean actualRegistryProvenanceEstablished() { return false; }
    public boolean executionAuthorityGranted() { return false; }
    @Override public String toString() { return "VirtualGrantFactResolver[NON_AUTHORIZING]"; }

    @Override public Gate current(ServerContext context, StageCommand command, OwnedTx tx) {
        try {
            Snapshot s = load(context, command, tx);
            Gate common = common(context, command, s);
            if (common != Gate.CLEAR) return common;
            if (version(context, command, tx, s) != Gate.CLEAR) return Gate.UNKNOWN;
            // Common access has been checked before the first historical lookup.
            StageOutcome recorded = tx.lookupRecordedOutcome(command);
            Receipt receipt = recorded == null ? null : recorded.receipt();
            Gate history = Gate.CLEAR;
            if (recorded != null && recorded.evaluationRefusal() != null) {
                if (command.action() != GrantStorageShape.AllowedAction.CREATE_LOAN_RECOMMENDATION
                        || !recorded.evaluationRefusal().identity().equals(command.identity())) return Gate.UNKNOWN;
                // A nonconsuming refusal never borrows consumed-grant expiry grace.
                history = SyntheticGrantTemporalAssessment.assess(s.temporal(), s.revocation()).blockers().isEmpty()
                        ? Gate.CLEAR : Gate.UNKNOWN;
            } else if (recorded != null && receipt == null) return Gate.UNKNOWN;
            else if (receipt != null) {
                if (!receipt.identity().equals(command.identity())) return Gate.UNKNOWN;
                if (receipt.kind() == ReceiptKind.CONSUMPTION) {
                    GrantSnapshot grant = tx.grant(command.identity().grantId());
                    if (grant == null || grant.state() != GrantState.CONSUMED) return Gate.UNKNOWN;
                    var supplied = new SyntheticGrantReplayAssessment.SuppliedReceipt(
                            SyntheticGrantReplayAssessment.ReceiptState.COMMITTED, receipt.identity(),
                            SyntheticGrantReplayAssessment.GrantLifecycle.CONSUMED);
                    history = SyntheticGrantKeyLifecycleAssessment.assessHistoricalRead(s.key().expected(),
                            s.key().snapshot(), command.identity(), supplied, s.temporal(), s.revocation(), s.currentRead())
                            .suppliedConditionsSatisfied() ? Gate.CLEAR : Gate.UNKNOWN;
                } else {
                    // Issuance is not own-consumed-grant history; do not borrow its expiry exception.
                    history = SyntheticGrantTemporalAssessment.assess(s.temporal(), s.revocation()).blockers().isEmpty()
                            ? Gate.CLEAR : Gate.UNKNOWN;
                }
            }
            return history == Gate.CLEAR ? version(context, command, tx, s) : history;
        } catch (IllegalArgumentException | NullPointerException malformed) { return Gate.UNKNOWN; }
    }
    @Override public ResolvedStage resolve(ServerContext context, StageCommand command,
                                           OutsidePreparedResult prepared, OwnedTx tx) {
        try {
            Snapshot s = load(context, command, tx);
            require(common(context, command, s));
            if (tx.grant(command.identity().grantId()) == null || s.agent() == null) throw invalid();
            KeyFacts k = s.key();
            if (!SyntheticGrantKeyLifecycleAssessment.assessOutstanding(k.expected(), k.snapshot(),
                    SyntheticGrantReplayAssessment.GrantLifecycle.ISSUED, k.ordering(), k.material(),
                    s.temporal(), s.revocation(), k.currentUse()).suppliedConditionsSatisfied()) throw invalid();
            AgentFacts a = s.agent();
            var identity = command.identity();
            var stageCommand = new SyntheticGrantStageBinding.StageCommand(identity.actorId(), identity.globalRequestId(),
                    identity.operation(), identity.canonicalizationVersion(), identity.canonicalBodyDigest(), identity.grantId(),
                    identity.actionId(), identity.targetRunId(), new SyntheticGrantStageBinding.Scope(identity.workflowId(),
                    identity.generation(), identity.customerId()));
            var checked = SyntheticGrantV2Codec.prepareAgentResultStage(a.codecProfile(), a.nodes(), a.bindingProfile(),
                    stageCommand, a.run(), a.result(), a.workflow(), a.expectedResult());
            bindLeaf(command, s, a.nodes());
            ResolvedStage r = a.resolved();
            if (!r.grant().equals(tx.grant(identity.grantId())) || r.grant().state() != GrantState.ISSUED
                    || !r.result().equals(prepared) || !r.result().resultId().equals(a.result().resultId())
                    || r.result().businessConclusion() != checked.businessConclusion()
                    || r.runStatus() != a.run().status() || r.resultStatus() != a.result().status()
                    || (r.inputSnapshotHash() != null
                        && !r.inputSnapshotHash().equals(a.result().binding().inputSnapshotHash()))) throw invalid();
            if (command.action() == GrantStorageShape.AllowedAction.EVALUATE_KYC)
                tx.requireKycPreparation(command, a.result().binding().inputSnapshotHash());
            require(version(context, command, tx, s));
            return new ResolvedStage(r.grant(), r.result(), r.runStatus(), r.resultStatus(), r.domainWrites(),
                    a.result().binding().inputSnapshotHash());
        } catch (IllegalArgumentException | NullPointerException malformed) {
            throw OwnedGrantTransactionPort.stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
        }
    }
    @Override public Gate checkIssuance(ServerContext context, StageCommand command, UUID parentGrantId,
                                        GrantSnapshot child, OwnedTx tx) {
        try {
            Snapshot s = load(context, command, tx);
            Gate common = common(context, command, s);
            if (common != Gate.CLEAR) return common;
            IssuanceFacts i = s.issuance();
            if (i == null || !Objects.equals(parentGrantId, i.parentGrantId()) || !Objects.equals(child, i.child())
                    || child.state() != GrantState.ISSUED) return Gate.UNKNOWN;
            SyntheticGrantV2Codec.prepareChain(i.codecProfile(), i.nodes());
            bindLeaf(command, s, i.nodes());
            var leaf = i.nodes().get(i.nodes().size() - 1).claims();
            if (!Objects.equals(leaf.parentGrantId(), parentGrantId)) return Gate.UNKNOWN;
            KeyFacts k = s.key();
            if (!SyntheticGrantKeyLifecycleAssessment.assessNewIssuance(k.expected(), k.snapshot(),
                    k.issuanceBindingChanged(), k.material(), s.temporal(), s.revocation(), k.currentUse())
                    .suppliedConditionsSatisfied()) return Gate.UNKNOWN;
            if (command.action() == GrantStorageShape.AllowedAction.EXECUTE_MOCK_PAYMENT)
                tx.bindCurrentIssuanceTime(command, java.time.Instant.ofEpochSecond(s.temporal().nowEpochSecond()));
            return version(context, command, tx, s);
        } catch (IllegalArgumentException | NullPointerException | java.time.DateTimeException malformed) { return Gate.UNKNOWN; }
    }
    private Snapshot load(ServerContext context, StageCommand command, OwnedTx tx) {
        Objects.requireNonNull(context); Objects.requireNonNull(command); Objects.requireNonNull(tx);
        return Objects.requireNonNull(facts.load(context, command, tx));
    }
    private Gate common(ServerContext context, StageCommand command, Snapshot s) {
        Descriptor d = Objects.requireNonNull(s.descriptor());
        var i = command.identity(); var b = d.issuerBinding(); var k = Objects.requireNonNull(s.key());
        if (!i.actorId().equals(context.actorId()) || !i.actorId().equals(d.actorAlias())) return Gate.REFUSED;
        if (!registry.assess(b).suppliedConsistencyMatched() || b.action() != command.action()
                || !b.workflowId().equals(i.workflowId()) || !b.customerId().equals(i.customerId())
                || !d.keyOwnerReference().equals(b.keyReference().ownerReference())
                || !b.keyReference().keyId().equals(k.expected().kid())
                || !b.keyReference().algorithmId().equals(k.expected().algorithm())
                || !b.issuerId().equals(k.expected().issuer()) || !d.keyVersion().equals(k.expected().keyVersion())) return Gate.UNKNOWN;
        if (k.snapshot().lifecycle() == SyntheticGrantKeyLifecycleAssessment.Lifecycle.REVOKED) return Gate.REFUSED;
        if (k.snapshot().lifecycle() == SyntheticGrantKeyLifecycleAssessment.Lifecycle.UNKNOWN
                || !k.expected().equals(k.snapshot().binding())) return Gate.UNKNOWN;
        Objects.requireNonNull(s.temporal()); Objects.requireNonNull(s.temporal().chainPosition());
        var r = Objects.requireNonNull(s.currentRead()); var v = Objects.requireNonNull(s.revocation());
        return gates(r.credentialInvalid(), r.actorMismatch(), r.ownerDenied(), r.operationDenied(), r.disclosureDenied(),
                r.ancestorExpiryBlocked(), r.resultInvalidationDisclosureBlocked(), v.grantRevoked(),
                v.rootAuthorizationRevoked(), v.keyRevoked(),
                s.temporal().chainPosition() == SyntheticGrantTemporalAssessment.ChainPosition.CHILD
                        ? v.parentRevoked() : Fact.CLEAR, v.workflowQuarantined(),
                v.sourceVersionQuarantined(), v.agentVersionQuarantined(), v.ancestorRunQuarantined(), v.ancestorResultQuarantined());
    }
    private static Gate gates(Fact... values) {
        boolean unknown = false;
        for (Fact value : values) { if (value == Fact.ACTIVE) return Gate.REFUSED; if (value != Fact.CLEAR) unknown = true; }
        return unknown ? Gate.UNKNOWN : Gate.CLEAR;
    }
    private Gate version(ServerContext c, StageCommand command, OwnedTx tx, Snapshot s) {
        return facts.versionChanged(c, command, tx, s.version()) == Fact.CLEAR ? Gate.CLEAR : Gate.UNKNOWN;
    }
    private static void require(Gate gate) { if (gate != Gate.CLEAR) throw invalid(); }
    private static void bindLeaf(StageCommand command, Snapshot s, List<SyntheticGrantChainStructure.Node> nodes) {
        var leaf = nodes.get(nodes.size() - 1).claims(); var i = command.identity(); var b = s.descriptor().issuerBinding();
        boolean root = nodes.size() == 1;
        if (root) {
            if (s.temporal().chainPosition() != SyntheticGrantTemporalAssessment.ChainPosition.ROOT
                    || s.temporal().parentExpiresAtEpochSecond() != null) throw invalid();
        } else {
            long parentExpiry = nodes.get(nodes.size() - 2).claims().expiresAt();
            if (s.temporal().chainPosition() != SyntheticGrantTemporalAssessment.ChainPosition.CHILD
                    || !Long.valueOf(parentExpiry).equals(s.temporal().parentExpiresAtEpochSecond())) throw invalid();
        }
        if (!leaf.grantId().equals(i.grantId()) || !leaf.actionId().equals(i.actionId())
                || !leaf.targetRunId().equals(i.targetRunId()) || leaf.allowedAction() != command.action()
                || !leaf.workflowId().equals(i.workflowId()) || leaf.generation() != i.generation()
                || !leaf.customerId().equals(i.customerId()) || !leaf.principalId().equals(b.principalId())
                || !leaf.issuer().equals(b.issuerId()) || !leaf.rootAuthorizationId().equals(b.rootAuthorizationId())
                || !leaf.originIntent().equals(b.intent()) || !leaf.kid().equals(s.key().expected().kid())
                || !leaf.algorithm().equals(s.key().expected().algorithm())
                || leaf.issuedAt() != s.temporal().issuedAtEpochSecond() || leaf.expiresAt() != s.temporal().expiresAtEpochSecond()) throw invalid();
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("VIRTUAL_GRANT_FACTS_UNCONFIRMED", null); }
}
