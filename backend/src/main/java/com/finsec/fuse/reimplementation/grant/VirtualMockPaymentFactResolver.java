package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.*;
import java.util.List;
import java.util.Objects;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.Fact;

/** Explicit virtual MP composition only; supplied facts never establish operational authority. */
public final class VirtualMockPaymentFactResolver implements PaymentFactResolver {
    public record PaymentSnapshot(String baseVersion, SyntheticGrantV2Codec.Profile codecProfile,
                                   List<SyntheticGrantChainStructure.Node> nodes, ResolvedPayment resolved) {
        public PaymentSnapshot {
            if (baseVersion == null || baseVersion.isBlank()) throw invalid();
            nodes = List.copyOf(nodes); Objects.requireNonNull(codecProfile); Objects.requireNonNull(resolved);
        }
        @Override public String toString() { return "VirtualPaymentSnapshot[REDACTED]"; }
    }
    /** Same local source supplies BOTH phases; no IO, provider, signing or external registry lookup. */
    public interface LocalPaymentFacts extends VirtualGrantFactResolver.LocalFacts {
        PaymentSnapshot loadPayment(ServerContext context, PaymentCommand command, OwnedTx tx,
                                    VirtualGrantFactResolver.Snapshot baseSnapshot);
    }
    private final SyntheticGrantIssuerBindings.Prepared registry;
    private final LocalPaymentFacts facts;
    private final VirtualGrantFactResolver commonResolver;
    public VirtualMockPaymentFactResolver(SyntheticGrantIssuerBindings.Prepared registry, LocalPaymentFacts facts) {
        this.registry = Objects.requireNonNull(registry); this.facts = Objects.requireNonNull(facts);
        this.commonResolver = new VirtualGrantFactResolver(registry, facts);
    }
    public boolean actualAuthorizationEstablished() { return false; }
    public boolean actualRegistryProvenanceEstablished() { return false; }
    public boolean executionAuthorityGranted() { return false; }
    @Override public String toString() { return "VirtualMockPaymentFactResolver[NON_AUTHORIZING]"; }

    @Override public Gate current(ServerContext context, PaymentCommand command, OwnedTx tx) {
        if (command == null) return Gate.UNKNOWN;
        return commonResolver.current(context, command.stage(), tx);
    }
    @Override public ResolvedPayment resolve(ServerContext context, PaymentCommand command, OwnedTx tx) {
        try {
            Objects.requireNonNull(command); Objects.requireNonNull(context); Objects.requireNonNull(tx);
            var stage = command.stage();
            var base = Objects.requireNonNull(facts.load(context, stage, tx));
            Gate common = common(context, stage, base);
            if (common != Gate.CLEAR) throw stop(common == Gate.REFUSED ? Status.REFUSED_BEFORE_ADMISSION
                    : Status.UNCONFIRMED_BEFORE_ADMISSION);
            requireVersion(context, stage, tx, base.version());
            // Fresh admission has already happened: lookup is deliberately NOT called here.
            var payment = Objects.requireNonNull(facts.loadPayment(context, command, tx, base));
            if (!base.version().equals(payment.baseVersion())) throw invalid();
            var k = base.key();
            var storedGrant = tx.grant(stage.identity().grantId());
            if (storedGrant == null || storedGrant.state() != GrantState.ISSUED
                    || storedGrant.action() != GrantStorageShape.AllowedAction.EXECUTE_MOCK_PAYMENT) throw invalid();
            if (!SyntheticGrantKeyLifecycleAssessment.assessOutstanding(k.expected(), k.snapshot(),
                    SyntheticGrantReplayAssessment.GrantLifecycle.ISSUED, k.ordering(), k.material(),
                    base.temporal(), base.revocation(), k.currentUse()).suppliedConditionsSatisfied()) throw invalid();
            SyntheticGrantV2Codec.prepareChain(payment.codecProfile(), payment.nodes());
            bindLeaf(stage, base, payment.nodes());
            var resolved = payment.resolved();
            var d = resolved.domain(); var i = stage.identity();
            var leaf = payment.nodes().get(payment.nodes().size() - 1).claims();
            if (leaf.amountKrw() != d.amountKrw() || !Objects.equals(leaf.payoutAccountId(), d.payoutAccountId())
                    || !Objects.equals(leaf.approvalId(), d.approvalId())
                    || !Objects.equals(leaf.policyVersion(), d.securityPolicyVersion())) throw invalid();
            if (!Objects.equals(tx.paymentDomain(d.reservationId()), d)
                    || !storedGrant.grantId().equals(d.grantId()) || !storedGrant.actionId().equals(d.actionId())
                    || !storedGrant.targetRunId().equals(d.targetRunId()) || !storedGrant.workflowId().equals(d.workflowId())
                    || storedGrant.generation() != d.generation() || !storedGrant.customerId().equals(d.customerId())
                    || !i.grantId().equals(d.grantId()) || !i.actionId().equals(d.actionId())
                    || !i.targetRunId().equals(d.targetRunId()) || !i.workflowId().equals(d.workflowId())
                    || i.generation() != d.generation() || !i.customerId().equals(d.customerId())) throw invalid();
            // Selected MP22 material and RESERVED prestate, never an agent VALIDATED result.
            checkResolved(command, resolved);
            requireVersion(context, stage, tx, base.version());
            return resolved;
        } catch (IllegalArgumentException | NullPointerException malformed) {
            throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
        }
    }
    private Gate common(ServerContext context, StageCommand command, VirtualGrantFactResolver.Snapshot s) {
        var d = Objects.requireNonNull(s.descriptor()); var i = command.identity(); var b = d.issuerBinding();
        var k = Objects.requireNonNull(s.key());
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
    private void requireVersion(ServerContext context, StageCommand stage, OwnedTx tx, String version) {
        if (facts.versionChanged(context, stage, tx, version) != Fact.CLEAR) throw invalid();
    }
    private static void bindLeaf(StageCommand command, VirtualGrantFactResolver.Snapshot s,
                                 List<SyntheticGrantChainStructure.Node> nodes) {
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
                || leaf.issuedAt() != s.temporal().issuedAtEpochSecond()
                || leaf.expiresAt() != s.temporal().expiresAtEpochSecond()) throw invalid();
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("VIRTUAL_PAYMENT_FACTS_UNCONFIRMED", null); }
}
