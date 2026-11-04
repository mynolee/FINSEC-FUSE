package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantIssuerBindings;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantKeyLifecycleAssessment;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane.Scope;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.RootInputs;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.AgentReference;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.IssuerFacts;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.KeyFacts;
import static com.finsec.fuse.reimplementation.grant.VirtualGrantGenerationHistory.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.Status;

/** Explicit continuation data; no provider dispatch, clock allocation or operational authority. */
public final class SyntheticTypedContinuationBinding {
    private SyntheticTypedContinuationBinding() { }
    static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_CONTINUATION", null); }
    private static void required(Object o) { if (o == null) throw invalid(); }
    private static void text(String s) { if (s == null || s.isBlank()) throw invalid(); }
    public sealed interface PriorExpectation permits ExistingHead, OriginalGenerationOne {
        Scope scope(); UUID rootGrantId(); long revision();
    }
    public record ExistingHead(ExpectedHead expected) implements PriorExpectation {
        public ExistingHead { required(expected); }
        public Scope scope() { return expected.scope(); }
        public UUID rootGrantId() { return expected.rootGrantId(); }
        public long revision() { return expected.revision(); }
        @Override public String toString() { return "ExistingHead[REDACTED]"; }
    }
    /** Allocation for a new observation, not an assertion of an absent stored revision. */
    public record OriginalGenerationOne(Scope scope, UUID rootGrantId, UUID rootRequestId,
            UUID rootTargetRunId, long firstObservedRevision) implements PriorExpectation {
        public OriginalGenerationOne {
            required(scope); required(rootGrantId); required(rootRequestId); required(rootTargetRunId);
            if (scope.generation() != 1 || firstObservedRevision < 0) throw invalid();
        }
        public long revision() { return firstObservedRevision; }
        @Override public String toString() { return "OriginalGenerationOne[REDACTED]"; }
    }
    public record ContinuationCommand(CommandIdentity identity, PriorExpectation prior, RootInputs newRoot,
            SimulationSpec.Application application, SimulationSpec.RiskTerms originalTerms,
            String laneReference, Map<AllowedAction,AgentReference> stageAgents, Instant observedAt) {
        public ContinuationCommand {
            required(identity); required(prior); required(newRoot); required(application); required(originalTerms);
            text(laneReference); required(stageAgents); required(observedAt);
            try { stageAgents = Map.copyOf(stageAgents); }
            catch (RuntimeException rejected) { throw invalid(); }
            var c = newRoot.claims(); var old = prior.scope();
            int next; long nextRevision;
            try { next = Math.addExact(old.generation(), 1); nextRevision = Math.addExact(prior.revision(), 1); }
            catch (ArithmeticException rejected) { throw invalid(); }
            if (nextRevision < 0 || observedAt.getNano() != 0 || observedAt.getEpochSecond() < 0
                    || identity.generation() != next || !identity.workflowId().equals(old.workflowId())
                    || !identity.customerId().equals(old.customerId())
                    || !identity.grantId().equals(c.grantId()) || !identity.actionId().equals(c.actionId())
                    || !identity.targetRunId().equals(c.targetRunId()) || !identity.workflowId().equals(c.workflowId())
                    || identity.generation() != c.generation() || !identity.customerId().equals(c.customerId())
                    || c.allowedAction() != AllowedAction.EVALUATE_KYC
                    || !application.customerId().equals(c.customerId()) || application.amountKrw() != c.amountKrw()
                    || !application.payoutAccountId().equals(c.payoutAccountId())
                    || !originalTerms.policyVersion().equals(c.policyVersion())
                    || !stageAgents.containsKey(AllowedAction.EVALUATE_KYC)
                    || !stageAgents.get(AllowedAction.EVALUATE_KYC).agentId().equals(c.targetAgent())) throw invalid();
        }
        public Scope requestedScope() { return new Scope(identity.workflowId(),identity.generation(),identity.customerId()); }
        public long nextRevision() { return Math.addExact(prior.revision(),1); }
        @Override public String toString() { return "ContinuationCommand[REDACTED]"; }
    }
    public enum PendingDisposition { VERIFIED_EMPTY, COHERENT_NONEMPTY, UNCONFIRMED }
    /** Excludes admission denial, stale identity/head conflicts and pending-liability refusal. */
    public enum ResumeReadiness { READY, KNOWN_NOT_READY, UNCONFIRMED }
    /** Facade-local actual-query ticket, never a transport authority or caller truth flag. */
    public static final class CurrentBindings {
        private final GenerationRecord origin;
        private final ExpectedHead head;
        private final SyntheticKycPreparationBinding.SourceCoordinate currentSource;
        private final String businessReference;
        private final long amountKrw;
        private final UUID payoutAccountId, activeJobId;
        private final String oldState;
        private final VirtualGrantEvaluationAccounting.Counters counters;
        private final PendingDisposition pendingDisposition;
        private final ResumeReadiness resumeReadiness;
        CurrentBindings(GenerationRecord origin, ExpectedHead head,
                SyntheticKycPreparationBinding.SourceCoordinate currentSource, String businessReference,
                long amountKrw, UUID payoutAccountId, String oldState, UUID activeJobId,
                VirtualGrantEvaluationAccounting.Counters counters, PendingDisposition pendingDisposition,
                ResumeReadiness resumeReadiness) {
            required(origin); required(currentSource); text(businessReference); required(payoutAccountId); text(oldState);
            required(counters); required(pendingDisposition); required(resumeReadiness);
            if (amountKrw < 0) throw invalid();
            this.origin=origin; this.head=head; this.currentSource=currentSource; this.businessReference=businessReference;
            this.amountKrw=amountKrw; this.payoutAccountId=payoutAccountId; this.oldState=oldState; this.activeJobId=activeJobId;
            this.counters=counters; this.pendingDisposition=pendingDisposition; this.resumeReadiness=resumeReadiness;
        }
        public GenerationRecord origin() { return origin; }
        public ExpectedHead head() { return head; }
        /** Actual old workflow projection; candidate source is validated separately against current catalog/control facts. */
        public SyntheticKycPreparationBinding.SourceCoordinate currentSource() { return currentSource; }
        public String businessReference() { return businessReference; }
        public long amountKrw() { return amountKrw; }
        public UUID payoutAccountId() { return payoutAccountId; }
        public String oldState() { return oldState; }
        public UUID activeJobId() { return activeJobId; }
        public VirtualGrantEvaluationAccounting.Counters counters() { return counters; }
        public PendingDisposition pendingDisposition() { return pendingDisposition; }
        public ResumeReadiness resumeReadiness() { return resumeReadiness; }
        @Override public String toString() { return "CurrentBindings[FACADE_LOCAL_REDACTED]"; }
    }
    public record ResolvedContinuation(ContinuationCommand command, CurrentBindings currentBindings,
            IssuerFacts issuerFacts, KeyFacts keyFacts) {
        public ResolvedContinuation { required(command); required(currentBindings); required(issuerFacts); required(keyFacts); }
        @Override public String toString() { return "ResolvedContinuation[SUPPLIED_REDACTED]"; }
    }
    /** Safe immutable plan comparison; source text is deliberately absent. */
    public record PlanBinding(String fixtureId, String businessReference, String customerId, long amountKrw,
            UUID payoutAccountId, long monthlyIncomeKrw, long maxLoanAmountKrw, boolean ownsActiveAccount,
            UUID documentId, int documentVersion, String contentHash, boolean reviewedSafe,
            SimulationSpec.RiskTerms originalTerms, String laneReference, Map<AllowedAction,AgentReference> stageAgents,
            Instant observedAt) {
        public PlanBinding {
            text(fixtureId); text(businessReference); text(customerId); required(payoutAccountId); required(documentId);
            required(originalTerms); text(laneReference); required(observedAt); required(stageAgents);
            if (amountKrw < 0 || monthlyIncomeKrw < 0 || maxLoanAmountKrw < 0 || documentVersion < 1
                    || !SimulationSpec.hash(contentHash) || observedAt.getNano()!=0 || observedAt.getEpochSecond()<0) throw invalid();
            try { stageAgents=Map.copyOf(stageAgents); } catch (RuntimeException rejected) { throw invalid(); }
            if (!stageAgents.containsKey(AllowedAction.EVALUATE_KYC)) throw invalid();
        }
        public static PlanBinding from(ContinuationCommand c) {
            var a=c.application(); var d=a.source();
            return new PlanBinding(a.fixtureId(),a.businessReference(),a.customerId(),a.amountKrw(),a.payoutAccountId(),
                    a.monthlyIncomeKrw(),a.maxLoanAmountKrw(),a.ownsActiveAccount(),d.documentId(),d.documentVersion(),
                    d.contentHash(),d.reviewedSafe(),c.originalTerms(),c.laneReference(),c.stageAgents(),c.observedAt());
        }
        @Override public String toString() { return "PlanBinding[REDACTED_NO_SOURCE_TEXT]"; }
    }
    public enum ContinuationKind { ADVANCED, DENIED }
    /** Denied records bind the requested material but commit only the old generation projection. */
    public record ContinuationReceipt(int version, ContinuationKind kind, CommandIdentity identity,
            PriorExpectation prior, RootInputs newRoot, PlanBinding planBinding, int committedGeneration,
            Long publishedHeadRevision) {
        public ContinuationReceipt {
            if (version!=1) throw invalid(); required(kind); required(identity); required(prior); required(newRoot); required(planBinding);
            if (kind==ContinuationKind.ADVANCED) {
                if (committedGeneration!=identity.generation() || publishedHeadRevision==null
                        || publishedHeadRevision.longValue()!=Math.addExact(prior.revision(),1)) throw invalid();
            } else if (committedGeneration!=prior.scope().generation() || publishedHeadRevision!=null) throw invalid();
        }
        public ContinuationReceipt(int version, ContinuationKind kind, ContinuationCommand command) {
            this(version,kind,command.identity(),command.prior(),command.newRoot(),PlanBinding.from(command),
                    kind==ContinuationKind.ADVANCED ? command.identity().generation():command.prior().scope().generation(),
                    kind==ContinuationKind.ADVANCED ? Long.valueOf(command.nextRevision()):null);
        }
        public boolean matches(ContinuationCommand c) {
            return c!=null && identity.equals(c.identity()) && prior.equals(c.prior()) && newRoot.equals(c.newRoot())
                    && planBinding.equals(PlanBinding.from(c));
        }
        public boolean actualAuthority() { return false; }
        public boolean durable() { return false; }
        @Override public String toString() { return "ContinuationReceipt[VIRTUAL_REDACTED]"; }
    }
    public enum ContinuationEffect { NO_NEW_CONTINUATION_ATTEMPT_THIS_INVOCATION, COMMITTED_IN_PROCESS, UNKNOWN }
    public record ContinuationOutcome(Status status, ContinuationReceipt receipt, ContinuationEffect effectKnowledge) {
        public ContinuationOutcome {
            required(status); required(effectKnowledge);
            boolean committed=status==Status.VIRTUAL_COMMITTED_IN_PROCESS || status==Status.VIRTUAL_REPLAYED_IN_PROCESS;
            boolean unknown=status==Status.COMMIT_UNKNOWN || status==Status.RECONCILIATION_UNCONFIRMED
                    || status==Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH || status==Status.TRANSACTION_INVARIANT_UNCONFIRMED;
            if ((committed && (receipt==null || effectKnowledge!=ContinuationEffect.COMMITTED_IN_PROCESS))
                    || (!committed && receipt!=null) || (unknown && effectKnowledge!=ContinuationEffect.UNKNOWN)
                    || (!committed && !unknown && effectKnowledge!=ContinuationEffect.NO_NEW_CONTINUATION_ATTEMPT_THIS_INVOCATION)) throw invalid();
        }
        public boolean actualAuthority() { return false; }
        public boolean durable() { return false; }
        @Override public String toString() { return "ContinuationOutcome[VIRTUAL_NON_AUTHORIZING]"; }
    }
    /** Mechanical joins only; the owned transaction must separately verify origin, holds, completeness and ticket identity. */
    public static void checkBindings(ContinuationCommand c, CurrentBindings b) {
        required(c); required(b);
        var p=c.prior(); var o=b.origin(); var a=c.application();
        if (!o.scope().equals(p.scope()) || !o.rootGrantId().equals(p.rootGrantId())
                || !o.terms().equals(c.originalTerms()) || !a.businessReference().equals(b.businessReference())
                || a.amountKrw()!=b.amountKrw() || !a.payoutAccountId().equals(b.payoutAccountId())
                ) throw invalid();
        if (p instanceof ExistingHead e) {
            if (!e.expected().equals(b.head())) throw invalid();
        } else if (p instanceof OriginalGenerationOne g) {
            if (b.head()!=null || !o.rootRequestId().equals(g.rootRequestId())
                    || !o.rootTargetRunId().equals(g.rootTargetRunId())) throw invalid();
        } else throw invalid();
        var n=b.counters();
        if (n.usedRisk()<0 || n.reservedRisk()<0 || n.kycRuns()<0) throw invalid();
    }
    public static void checkResolved(ContinuationCommand command, ResolvedContinuation resolved) {
        try {
            required(command); required(resolved);
            if (!command.equals(resolved.command())) throw invalid();
            checkBindings(command,resolved.currentBindings());
            if (resolved.currentBindings().pendingDisposition()!=PendingDisposition.VERIFIED_EMPTY
                    || resolved.currentBindings().resumeReadiness()!=ResumeReadiness.READY
                    || !(resolved.currentBindings().oldState().equals("BLOCKED") || resolved.currentBindings().oldState().equals("ON_HOLD"))
                    || resolved.currentBindings().activeJobId()!=null) throw invalid();
            var claims = command.newRoot().claims(); var issuer = resolved.issuerFacts(); var binding = issuer.binding();
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
                    || time.nowEpochSecond() != command.observedAt().getEpochSecond()
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
