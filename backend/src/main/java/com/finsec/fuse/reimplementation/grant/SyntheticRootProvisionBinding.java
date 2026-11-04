package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.SyntheticGrantV2Codec;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantChainStructure;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantIssuerBindings;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantKeyLifecycleAssessment;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import java.util.Objects;
import java.util.UUID;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.Status;

/** Immutable supplied-data root initialization; never a signer or operational authority. */
public final class SyntheticRootProvisionBinding {
    private SyntheticRootProvisionBinding() { }
    static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_GRANT_COMMAND", null); }
    private static void required(Object value) { if (value == null) throw invalid(); }
    private static void text(String value) { if (value == null || value.isBlank()) throw invalid(); }

    public static final class RootInputs {
        private final SyntheticGrantV2Codec.Profile profile;
        private final SyntheticGrantV2Codec.Claims claims;
        private final SyntheticGrantV2Codec.Action action;
        private final SyntheticGrantV2Codec.Prepared prepared;
        public RootInputs(SyntheticGrantV2Codec.Profile profile, SyntheticGrantV2Codec.Claims claims,
                          SyntheticGrantV2Codec.Action action, SyntheticGrantV2Codec.Prepared prepared) {
            try {
                required(profile); required(claims); required(action); required(prepared);
                var recomputed = SyntheticGrantV2Codec.prepare(profile, claims, action);
                SyntheticGrantV2Codec.prepareChain(profile, List.of(new SyntheticGrantChainStructure.Node(claims, action)));
                if (!samePrepared(recomputed, prepared)) throw invalid();
                this.profile = profile; this.claims = claims; this.action = action; this.prepared = recomputed;
            } catch (IllegalArgumentException | NullPointerException rejected) { throw invalid(); }
        }
        public SyntheticGrantV2Codec.Profile profile() { return profile; }
        public SyntheticGrantV2Codec.Claims claims() { return claims; }
        public SyntheticGrantV2Codec.Action action() { return action; }
        public SyntheticGrantV2Codec.Prepared prepared() { return prepared; }
        @Override public boolean equals(Object other) {
            return other instanceof RootInputs r && profile.equals(r.profile) && claims.equals(r.claims)
                    && action.equals(r.action) && samePrepared(prepared, r.prepared);
        }
        @Override public int hashCode() { return Objects.hash(profile, claims, action, Arrays.hashCode(prepared.unsignedFrame())); }
        @Override public String toString() { return "RootInputs[UNSIGNED_REDACTED]"; }
    }
    private static boolean samePrepared(SyntheticGrantV2Codec.Prepared a, SyntheticGrantV2Codec.Prepared b) {
        return a.payloadSha256().equals(b.payloadSha256()) && Arrays.equals(a.claimsBytes(), b.claimsBytes())
                && Arrays.equals(a.actionBytes(), b.actionBytes()) && Arrays.equals(a.unsignedFrame(), b.unsignedFrame());
    }

    public record AgentReference(String agentId, int version) {
        public AgentReference { text(agentId); if (version < 1) throw invalid(); }
        @Override public String toString() { return "AgentReference[SUPPLIED_REDACTED]"; }
    }

    /** Initialization only: no job, result, dispatch or implicit clock/identifier allocation. */
    public record TypedWorkflowPlan(UUID workflowId, int generation, SimulationSpec.Application application,
                                    SimulationSpec.RiskTerms riskTerms, String laneReference, UUID targetRunId,
                                    Map<AllowedAction, AgentReference> stageAgents) {
        public TypedWorkflowPlan {
            required(workflowId); required(application); required(riskTerms); text(laneReference); required(targetRunId);
            if (generation != 1 || stageAgents == null) throw invalid();
            try { stageAgents = Map.copyOf(stageAgents); }
            catch (IllegalArgumentException | NullPointerException rejected) { throw invalid(); }
            if (!stageAgents.containsKey(AllowedAction.EVALUATE_KYC)) throw invalid();
        }
        public String initialState() { return "KYC_PENDING"; }
        public String initialDecision() { return "ALLOW"; }
        public int usedRisk() { return 0; }
        public int reservedRisk() { return 0; }
        public int kycRuns() { return 0; }
        @Override public String toString() { return "TypedWorkflowPlan[INITIALIZATION_ONLY_REDACTED]"; }
    }

    public record RootCommand(CommandIdentity identity, RootInputs inputs, TypedWorkflowPlan workflowPlan) {
        public RootCommand {
            required(identity); required(inputs); required(workflowPlan);
            var c = inputs.claims(); var p = workflowPlan; var a = p.application();
            if (!identity.grantId().equals(c.grantId()) || !identity.actionId().equals(c.actionId())
                    || !identity.targetRunId().equals(c.targetRunId()) || !identity.workflowId().equals(c.workflowId())
                    || identity.generation() != c.generation() || !identity.customerId().equals(c.customerId())
                    || !p.workflowId().equals(c.workflowId()) || p.generation() != c.generation()
                    || !p.targetRunId().equals(c.targetRunId()) || !a.customerId().equals(c.customerId())
                    || a.amountKrw() != c.amountKrw() || !a.payoutAccountId().equals(c.payoutAccountId())
                    || !p.riskTerms().policyVersion().equals(c.policyVersion())
                    || !p.stageAgents().get(AllowedAction.EVALUATE_KYC).agentId().equals(c.targetAgent())) throw invalid();
        }
        @Override public String toString() { return "RootCommand[REDACTED]"; }
    }

    /** A local facade-lifetime snapshot ticket; its absence flags alone cannot admit freshness. */
    public static final class CurrentBindings {
        private final boolean workflowAbsent, businessReferenceAbsent, laneAbsent, grantAbsent, actionAbsent, targetAbsent;
        CurrentBindings(boolean workflowAbsent, boolean businessReferenceAbsent, boolean laneAbsent,
                        boolean grantAbsent, boolean actionAbsent, boolean targetAbsent) {
            this.workflowAbsent = workflowAbsent; this.businessReferenceAbsent = businessReferenceAbsent;
            this.laneAbsent = laneAbsent; this.grantAbsent = grantAbsent; this.actionAbsent = actionAbsent; this.targetAbsent = targetAbsent;
        }
        public boolean workflowAbsent() { return workflowAbsent; }
        public boolean businessReferenceAbsent() { return businessReferenceAbsent; }
        public boolean laneAbsent() { return laneAbsent; }
        public boolean grantAbsent() { return grantAbsent; }
        public boolean actionAbsent() { return actionAbsent; }
        public boolean targetAbsent() { return targetAbsent; }
        public boolean allAbsent() { return workflowAbsent && businessReferenceAbsent && laneAbsent && grantAbsent && actionAbsent && targetAbsent; }
        @Override public String toString() { return "CurrentBindings[FACADE_LOCAL_NON_AUTHORIZING]"; }
    }

    public record IssuerFacts(SyntheticGrantIssuerBindings.Prepared registry, VirtualGrantFactResolver.Descriptor descriptor) {
        public IssuerFacts { required(registry); required(descriptor); }
        public SyntheticGrantIssuerBindings.Binding binding() { return descriptor.issuerBinding(); }
        @Override public String toString() { return "IssuerFacts[SUPPLIED_REDACTED]"; }
    }
    public record KeyFacts(SyntheticGrantKeyLifecycleAssessment.KeyBinding expected,
                           SyntheticGrantKeyLifecycleAssessment.KeySnapshot snapshot,
                           SyntheticGrantTemporalAssessment.Fact bindingChanged,
                           SyntheticGrantKeyLifecycleAssessment.MaterialFact material,
                           SyntheticGrantTemporalAssessment.TemporalFacts time,
                           SyntheticGrantTemporalAssessment.RevocationFacts revocation,
                           SyntheticGrantKeyLifecycleAssessment.CurrentUseFacts current) {
        public KeyFacts {
            required(expected); required(snapshot); required(bindingChanged); required(material);
            required(time); required(revocation); required(current);
        }
        @Override public String toString() { return "KeyFacts[SUPPLIED_REDACTED]"; }
    }
    public record ResolvedRootProvision(RootCommand command, CurrentBindings currentBindings,
                                        IssuerFacts issuerFacts, KeyFacts keyFacts) {
        public ResolvedRootProvision { required(command); required(currentBindings); required(issuerFacts); required(keyFacts); }
        @Override public String toString() { return "ResolvedRootProvision[SUPPLIED_REDACTED]"; }
    }
    /** Receipt-safe projection: source identity/hash only, never source text. */
    public record RootPlanBinding(UUID workflowId, int generation, String fixtureId, String businessReference,
                                  String customerId, long amountKrw, UUID payoutAccountId,
                                  long monthlyIncomeKrw, long maxLoanAmountKrw, boolean ownsActiveAccount,
                                  UUID documentId, int documentVersion, String contentHash, boolean reviewedSafe,
                                  SimulationSpec.RiskTerms riskTerms, String laneReference, UUID targetRunId,
                                  Map<AllowedAction, AgentReference> stageAgents) {
        public RootPlanBinding {
            required(workflowId); text(fixtureId); text(businessReference); text(customerId); required(payoutAccountId);
            required(documentId); required(riskTerms); text(laneReference); required(targetRunId);
            if (generation != 1 || documentVersion < 1 || !SimulationSpec.hash(contentHash)
                    || amountKrw < 0 || monthlyIncomeKrw < 0 || maxLoanAmountKrw < 0 || stageAgents == null) throw invalid();
            try { stageAgents = Map.copyOf(stageAgents); }
            catch (IllegalArgumentException | NullPointerException rejected) { throw invalid(); }
            if (!stageAgents.containsKey(AllowedAction.EVALUATE_KYC)) throw invalid();
        }
        static RootPlanBinding from(TypedWorkflowPlan p) {
            var a = p.application(); var d = a.source();
            return new RootPlanBinding(p.workflowId(), p.generation(), a.fixtureId(), a.businessReference(),
                    a.customerId(), a.amountKrw(), a.payoutAccountId(), a.monthlyIncomeKrw(), a.maxLoanAmountKrw(),
                    a.ownsActiveAccount(), d.documentId(), d.documentVersion(), d.contentHash(), d.reviewedSafe(),
                    p.riskTerms(), p.laneReference(), p.targetRunId(), p.stageAgents());
        }
        @Override public String toString() { return "RootPlanBinding[REDACTED_NO_SOURCE_TEXT]"; }
    }
    /** Dedicated root purpose; never a child parent, consumption result or source body. */
    public record RootReceipt(int version, CommandIdentity identity, RootInputs inputs, RootPlanBinding planBinding) {
        public RootReceipt {
            if (version != 1) throw invalid(); required(identity); required(inputs); required(planBinding);
        }
        public RootReceipt(int version, RootCommand command) {
            this(version, command.identity(), command.inputs(), RootPlanBinding.from(command.workflowPlan()));
        }
        public boolean matches(RootCommand command) {
            return command != null && identity.equals(command.identity()) && inputs.equals(command.inputs())
                    && planBinding.equals(RootPlanBinding.from(command.workflowPlan()));
        }
        public boolean actualAuthority() { return false; }
        public boolean durable() { return false; }
        @Override public String toString() { return "RootReceipt[VIRTUAL_NON_DURABLE]"; }
    }
    public enum RootEffect { NO_NEW_ROOT_PROVISION_ATTEMPT_THIS_INVOCATION, COMMITTED_IN_PROCESS, UNKNOWN }
    public record RootOutcome(Status status, RootReceipt receipt, RootEffect effectKnowledge) {
        public RootOutcome {
            required(status); required(effectKnowledge);
            boolean committed = status == Status.VIRTUAL_COMMITTED_IN_PROCESS || status == Status.VIRTUAL_REPLAYED_IN_PROCESS;
            boolean unknown = status == Status.COMMIT_UNKNOWN || status == Status.RECONCILIATION_UNCONFIRMED
                    || status == Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH || status == Status.TRANSACTION_INVARIANT_UNCONFIRMED;
            if ((committed && (receipt == null || effectKnowledge != RootEffect.COMMITTED_IN_PROCESS))
                    || (!committed && receipt != null) || (unknown && effectKnowledge != RootEffect.UNKNOWN)
                    || (!committed && !unknown && effectKnowledge != RootEffect.NO_NEW_ROOT_PROVISION_ATTEMPT_THIS_INVOCATION)) throw invalid();
        }
        public boolean actualAuthority() { return false; }
        public boolean durable() { return false; }
        @Override public String toString() { return "RootOutcome[VIRTUAL_NON_AUTHORIZING]"; }
    }

    /** Pure supplied-data consistency only; caller must additionally enforce current context and owned lifetime. */
    public static void checkResolved(RootCommand command, ResolvedRootProvision resolved) {
        try {
            required(command); required(resolved);
            if (!command.equals(resolved.command()) || !resolved.currentBindings().allAbsent()) throw invalid();
            var claims = command.inputs().claims(); var issuer = resolved.issuerFacts(); var binding = issuer.binding();
            var key = resolved.keyFacts(); var expected = key.expected(); var time = key.time();
            if (!issuer.registry().assess(binding).suppliedConsistencyMatched()
                    || !issuer.descriptor().actorAlias().equals(command.identity().actorId())
                    || !issuer.descriptor().keyOwnerReference().equals(binding.keyReference().ownerReference())
                    || !issuer.descriptor().keyVersion().equals(expected.keyVersion())
                    || !binding.principalId().equals(claims.principalId()) || !binding.issuerId().equals(claims.issuer())
                    || binding.stage() != SyntheticGrantIssuerBindings.Stage.KYC_EVALUATOR
                    || binding.action() != claims.allowedAction() || !binding.customerId().equals(claims.customerId())
                    || !binding.rootAuthorizationId().equals(claims.rootAuthorizationId())
                    || !binding.workflowId().equals(claims.workflowId()) || !binding.intent().equals(claims.originIntent())
                    || !binding.keyReference().keyId().equals(claims.kid())
                    || !binding.keyReference().algorithmId().equals(claims.algorithm())
                    || !expected.kid().equals(claims.kid()) || !expected.issuer().equals(claims.issuer())
                    || !expected.algorithm().equals(claims.algorithm())
                    || time.issuedAtEpochSecond() != claims.issuedAt() || time.expiresAtEpochSecond() != claims.expiresAt()
                    || time.chainPosition() != SyntheticGrantTemporalAssessment.ChainPosition.ROOT
                    || time.parentExpiresAtEpochSecond() != null
                    || !SyntheticGrantKeyLifecycleAssessment.assessNewIssuance(expected, key.snapshot(), key.bindingChanged(),
                        key.material(), time, key.revocation(), key.current()).suppliedConditionsSatisfied())
                throw invalid();
        } catch (IllegalArgumentException | NullPointerException rejected) {
            throw invalid();
        }
    }
}
