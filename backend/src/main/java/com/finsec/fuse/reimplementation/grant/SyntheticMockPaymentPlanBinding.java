package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane.Scope;
import java.time.Instant;
import java.util.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;

/** Supplied review evidence plus exact owned snapshots; no actual permission or finality proof. */
public final class SyntheticMockPaymentPlanBinding {
    private SyntheticMockPaymentPlanBinding() { }
    static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_MOCK_PAYMENT_PLAN", null); }
    private static void required(Object value) { if (value == null) throw invalid(); }
    private static void text(String value) { if (value == null || value.isBlank()) throw invalid(); }
    private static void hash(String value) { if (!SimulationSpec.hash(value)) throw invalid(); }
    public enum PlanOperation { REVIEW, RESERVE }
    public enum ReviewDecision { APPROVE, REJECT }
    public enum ApprovalPlanState { AVAILABLE, REJECTED, RESERVED, CONSUMED }

    public record ReviewCommand(CommandIdentity identity, UUID approvalId, ReviewDecision decision,
                                String expectedReviewSnapshotHash, Instant now, Instant expiresAt, String comment) {
        public ReviewCommand {
            required(identity); required(approvalId); required(decision); hash(expectedReviewSnapshotHash);
            required(now); required(expiresAt);
            if (comment == null || comment.length() > 1000 || !now.isBefore(expiresAt)) throw invalid();
        }
        @Override public String toString() { return "ReviewCommand[REDACTED]"; }
    }
    public record ReserveCommand(CommandIdentity identity, PaymentDomain domain,
                                 String expectedReviewSnapshotHash, Instant now) {
        public ReserveCommand {
            required(identity); required(domain); hash(expectedReviewSnapshotHash); required(now);
            if (domain.reservationState() != ReservationState.RESERVED || domain.approvalState() != ApprovalState.RESERVED
                    || !identity.grantId().equals(domain.grantId()) || !identity.actionId().equals(domain.actionId())
                    || !identity.targetRunId().equals(domain.targetRunId()) || !identity.workflowId().equals(domain.workflowId())
                    || identity.generation() != domain.generation() || !identity.customerId().equals(domain.customerId())) throw invalid();
        }
        @Override public String toString() { return "ReserveCommand[REDACTED]"; }
    }
    public record WorkflowSnapshot(Scope scope, String businessReference, UUID documentId, int documentVersion,
                                   long amountKrw, UUID payoutAccountId, int usedRisk, int reservedRisk, int riskLimit,
                                   SimulationSpec.RiskTerms terms) {
        public WorkflowSnapshot {
            required(scope); text(businessReference); required(documentId); required(payoutAccountId); required(terms);
            if (documentVersion < 1 || amountKrw < 1 || amountKrw > 50000000L || usedRisk < 0 || reservedRisk < 0 || riskLimit < 0) throw invalid();
        }
        @Override public String toString() { return "PlanWorkflowSnapshot[REDACTED]"; }
    }
    /** Port must establish actual local/global/result coherence before constructing this snapshot. */
    public record EvaluationSnapshot(GrantSnapshot kycGrant, Receipt kycReceipt,
                                     VirtualGrantTransactionJournal.TypedReference kycReference,
                                     GrantSnapshot loanGrant, Receipt loanReceipt,
                                     VirtualGrantTransactionJournal.TypedReference loanReference) {
        public EvaluationSnapshot {
            required(kycGrant); required(kycReceipt); required(kycReference);
            required(loanGrant); required(loanReceipt); required(loanReference);
        }
        @Override public String toString() { return "PlanEvaluationSnapshot[REDACTED]"; }
    }
    public static final class ReviewBindings {
        private final WorkflowSnapshot workflow; private final EvaluationSnapshot evaluation;
        ReviewBindings(WorkflowSnapshot workflow, EvaluationSnapshot evaluation) {
            required(workflow); required(evaluation); this.workflow=workflow; this.evaluation=evaluation;
        }
        public WorkflowSnapshot workflow() { return workflow; }
        public EvaluationSnapshot evaluation() { return evaluation; }
        @Override public String toString() { return "ReviewBindings[OWNED_LOCAL_REDACTED]"; }
    }
    public static final class ReservationBindings {
        private final ReviewBindings review; private final ApprovalSnapshot approval; private final GrantSnapshot paymentGrant;
        private final VirtualGrantTransactionJournal.TypedReference paymentReference;
        ReservationBindings(ReviewBindings review, ApprovalSnapshot approval, GrantSnapshot paymentGrant,
                            VirtualGrantTransactionJournal.TypedReference paymentReference) {
            required(review); required(approval); required(paymentGrant); required(paymentReference);
            this.review=review; this.approval=approval; this.paymentGrant=paymentGrant; this.paymentReference=paymentReference;
        }
        public ReviewBindings review() { return review; }
        public ApprovalSnapshot approval() { return approval; }
        public GrantSnapshot paymentGrant() { return paymentGrant; }
        public VirtualGrantTransactionJournal.TypedReference paymentReference() { return paymentReference; }
        @Override public String toString() { return "ReservationBindings[OWNED_LOCAL_REDACTED]"; }
    }
    /** Mandatory server-owned supplied links; digest strings are not independently verified body hashes. */
    public record EvidenceSnapshot(UUID applicationId, UUID kycResultId, UUID loanResultId,
                                   String evidenceBundleHash, String loanResultHash, SimulationSpec.Source source,
                                   List<UUID> evidenceIds, List<SimulationSpec.Fact> evidence) {
        public EvidenceSnapshot {
            required(applicationId); required(kycResultId); required(loanResultId); hash(evidenceBundleHash); hash(loanResultHash); required(source);
            try { evidenceIds=List.copyOf(evidenceIds); evidence=List.copyOf(evidence); }
            catch (IllegalArgumentException | NullPointerException rejected) { throw invalid(); }
            if (new HashSet<>(evidenceIds).size()!=evidenceIds.size()) throw invalid();
        }
        @Override public String toString() { return "PlanEvidence[SUPPLIED_REDACTED]"; }
    }
    public record ResolvedEvidence(ReviewBindings bindings, EvidenceSnapshot evidence) {
        public ResolvedEvidence { required(bindings); required(evidence); }
        @Override public String toString() { return "ResolvedPlanEvidence[REDACTED]"; }
    }
    /** Safe local review binding, intentionally excludes source text and comment. */
    public record ReviewMaterial(Scope scope, UUID applicationId, long amountKrw, UUID payoutAccountId,
                                 UUID kycResultId, UUID loanResultId, String evidenceBundleHash, String loanResultHash,
                                 UUID documentId, int documentVersion, String sourceContentHash, String policyVersion,
                                 int usedRisk, int reservedRisk, int riskLimitAfterApproval) {
        public ReviewMaterial {
            required(scope); required(applicationId); required(payoutAccountId); required(kycResultId); required(loanResultId);
            required(documentId); hash(evidenceBundleHash); hash(loanResultHash); hash(sourceContentHash); text(policyVersion);
            if (amountKrw<1 || amountKrw>50000000L || documentVersion<1 || usedRisk<0 || reservedRisk<0 || riskLimitAfterApproval<0) throw invalid();
        }
        @Override public String toString() { return "ReviewMaterial[REDACTED]"; }
    }
    public record ApprovalSnapshot(UUID approvalId, UUID reviewRequestId, String reviewerActorId,
                                   ReviewDecision decision, ReviewMaterial material, String reviewSnapshotHash,
                                   Instant createdAt, Instant expiresAt, int extraRiskLimit, int riskLimit,
                                   ApprovalPlanState state) {
        public ApprovalSnapshot {
            required(approvalId); required(reviewRequestId); text(reviewerActorId); required(decision); required(material);
            hash(reviewSnapshotHash); required(createdAt); required(expiresAt); required(state);
            if (!createdAt.isBefore(expiresAt) || extraRiskLimit<0 || riskLimit<0
                    || (decision==ReviewDecision.REJECT && state!=ApprovalPlanState.REJECTED)
                    || (decision==ReviewDecision.APPROVE && state==ApprovalPlanState.REJECTED)) throw invalid();
        }
        @Override public String toString() { return "ApprovalPlanSnapshot[REDACTED]"; }
    }
    public record PreparedReview(ReviewCommand command, ReviewBindings bindings, ApprovalSnapshot approval) {
        public PreparedReview { required(command); required(bindings); required(approval); }
        @Override public String toString() { return "PreparedReview[NON_AUTHORIZING]"; }
    }
    public record PreparedReservation(ReserveCommand command, ReservationBindings bindings,
                                      ApprovalSnapshot approval, int riskPoints) {
        public PreparedReservation { required(command); required(bindings); required(approval); if(riskPoints<1)throw invalid(); }
        @Override public String toString() { return "PreparedReservation[NON_AUTHORIZING]"; }
    }
    public record PlanReceipt(int version, PlanOperation purpose, CommandIdentity identity,
                              ApprovalSnapshot approval, PaymentDomain domain, int riskPoints) {
        public PlanReceipt {
            if(version!=1)throw invalid(); required(purpose); required(identity); required(approval);
            if(purpose==PlanOperation.REVIEW && (domain!=null || riskPoints!=0)
                    || purpose==PlanOperation.RESERVE && (domain==null || riskPoints<1))throw invalid();
        }
        public boolean actualAuthority(){return false;} public boolean durable(){return false;}
        @Override public String toString(){return "PlanReceipt[VIRTUAL_NON_DURABLE]";}
    }
    public enum PlanEffect { NO_NEW_PLAN_ATTEMPT_THIS_INVOCATION, COMMITTED_IN_PROCESS, UNKNOWN }
    public record PlanOutcome(Status status, PlanReceipt receipt, PlanEffect effectKnowledge) {
        public PlanOutcome {
            required(status);required(effectKnowledge);
            boolean committed=status==Status.VIRTUAL_COMMITTED_IN_PROCESS || status==Status.VIRTUAL_REPLAYED_IN_PROCESS;
            boolean unknown=status==Status.COMMIT_UNKNOWN || status==Status.RECONCILIATION_UNCONFIRMED
                    || status==Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH || status==Status.TRANSACTION_INVARIANT_UNCONFIRMED;
            if(committed && (receipt==null || effectKnowledge!=PlanEffect.COMMITTED_IN_PROCESS)
                    || !committed && receipt!=null || unknown && effectKnowledge!=PlanEffect.UNKNOWN
                    || !committed && !unknown && effectKnowledge!=PlanEffect.NO_NEW_PLAN_ATTEMPT_THIS_INVOCATION)throw invalid();
        }
        public boolean actualAuthority(){return false;} public boolean durable(){return false;}
        @Override public String toString(){return "PlanOutcome[VIRTUAL_NON_AUTHORIZING]";}
    }

    private static void scope(CommandIdentity i, Scope s) {
        if(!i.workflowId().equals(s.workflowId()) || i.generation()!=s.generation() || !i.customerId().equals(s.customerId()))throw invalid();
    }
    private static void consumed(GrantSnapshot g,Receipt r,VirtualGrantTransactionJournal.TypedReference t,
                                 Scope s,AllowedAction action) {
        if(g.state()!=GrantState.CONSUMED || g.action()!=action || r.kind()!=ReceiptKind.CONSUMPTION || r.result()==null
                || r.result().businessConclusion()!=BusinessConclusion.POSITIVE || !"AGENT_RESULT_BINDING_RECORD_1".equals(r.result().bindingProfile())
                || !g.grantId().equals(r.identity().grantId()) || !g.actionId().equals(r.identity().actionId())
                || !g.targetRunId().equals(r.identity().targetRunId()) || !g.workflowId().equals(s.workflowId())
                || g.generation()!=s.generation() || !g.customerId().equals(s.customerId())
                || !t.workflowId().equals(s.workflowId()) || t.generation()!=s.generation() || !t.customerId().equals(s.customerId())
                || !t.grantId().equals(g.grantId()) || !t.actionId().equals(g.actionId()) || !t.targetRunId().equals(g.targetRunId())
                || !r.result().resultId().equals(t.resultId()))throw invalid();
        scope(r.identity(),s);
    }
    private static void evaluations(ReviewBindings b) {
        var s=b.workflow().scope();var e=b.evaluation();
        consumed(e.kycGrant(),e.kycReceipt(),e.kycReference(),s,AllowedAction.EVALUATE_KYC);
        consumed(e.loanGrant(),e.loanReceipt(),e.loanReference(),s,AllowedAction.CREATE_LOAN_RECOMMENDATION);
        if(!e.kycGrant().targetRunId().equals(e.loanReference().sourceRunId())
                || !e.kycReceipt().result().resultId().equals(e.loanReference().sourceResultId()))throw invalid();
        for(var t:List.of(e.kycReference(),e.loanReference()))
            if(!t.documentId().equals(b.workflow().documentId()) || t.documentVersion()!=b.workflow().documentVersion())throw invalid();
    }
    public static ReviewMaterial material(ReviewBindings b,EvidenceSnapshot evidence,Instant now) {
        try {
            required(b);required(evidence);required(now);evaluations(b);
            var w=b.workflow();var e=b.evaluation();var source=evidence.source();
            if(!source.reviewedSafe() || !source.documentId().equals(w.documentId()) || source.documentVersion()!=w.documentVersion()
                    || !evidence.kycResultId().equals(e.kycReceipt().result().resultId())
                    || !evidence.loanResultId().equals(e.loanReceipt().result().resultId()))throw invalid();
            var facts=new HashMap<UUID,SimulationSpec.Fact>();
            for(var fact:evidence.evidence())if(facts.putIfAbsent(fact.evidenceId(),fact)!=null)throw invalid();
            if(!facts.keySet().equals(new HashSet<>(evidence.evidenceIds())))throw invalid();
            for(var id:evidence.evidenceIds()) {
                var fact=facts.get(id);
                if(!fact.customerId().equals(w.scope().customerId()) || !fact.usable(now) || fact.result()!=SimulationSpec.Outcome.PASS)throw invalid();
            }
            return new ReviewMaterial(w.scope(),evidence.applicationId(),w.amountKrw(),w.payoutAccountId(),evidence.kycResultId(),
                    evidence.loanResultId(),evidence.evidenceBundleHash(),evidence.loanResultHash(),w.documentId(),w.documentVersion(),
                    source.contentHash(),w.terms().policyVersion(),w.usedRisk(),w.reservedRisk(),
                    Math.addExact(w.terms().baseLimit(),w.terms().additionalApprovalLimit()));
        }catch(IllegalArgumentException|NullPointerException|ArithmeticException rejected){throw invalid();}
    }
    /** Canonical local review snapshot hash only, not original agent body verification. */
    public static String reviewHash(ReviewMaterial m) {
        required(m);var s=m.scope();
        return CanonicalJson.sha256(Map.ofEntries(Map.entry("workflowId",s.workflowId().toString()),Map.entry("generation",s.generation()),
                Map.entry("customerId",s.customerId()),Map.entry("applicationId",m.applicationId().toString()),Map.entry("amountKrw",m.amountKrw()),
                Map.entry("payoutAccountId",m.payoutAccountId().toString()),Map.entry("kycResultId",m.kycResultId().toString()),
                Map.entry("loanResultId",m.loanResultId().toString()),Map.entry("evidenceBundleHash",m.evidenceBundleHash()),Map.entry("loanResultHash",m.loanResultHash()),
                Map.entry("documentId",m.documentId().toString()),Map.entry("documentVersion",m.documentVersion()),Map.entry("sourceContentHash",m.sourceContentHash()),
                Map.entry("policyVersion",m.policyVersion()),Map.entry("usedRisk",m.usedRisk()),Map.entry("reservedRisk",m.reservedRisk()),
                Map.entry("riskLimitAfterApproval",m.riskLimitAfterApproval())));
    }
    public static PreparedReview prepareReview(ReviewCommand command,ReviewBindings bindings,EvidenceSnapshot evidence) {
        try {
            required(command);var material=material(bindings,evidence,command.now());scope(command.identity(),material.scope());
            var loan=bindings.evaluation().loanGrant();
            if(!command.identity().grantId().equals(loan.grantId()) || !command.identity().actionId().equals(loan.actionId())
                    || !command.identity().targetRunId().equals(loan.targetRunId())
                    || !reviewHash(material).equals(command.expectedReviewSnapshotHash())
                    || !command.now().plus(bindings.workflow().terms().approvalLifetime()).equals(command.expiresAt()))throw invalid();
            boolean approved=command.decision()==ReviewDecision.APPROVE;
            int extra=approved?bindings.workflow().terms().additionalApprovalLimit():0;
            int limit=approved?Math.addExact(bindings.workflow().terms().baseLimit(),extra):bindings.workflow().terms().baseLimit();
            return new PreparedReview(command,bindings,new ApprovalSnapshot(command.approvalId(),command.identity().globalRequestId(),
                    command.identity().actorId(),command.decision(),material,command.expectedReviewSnapshotHash(),command.now(),command.expiresAt(),
                    extra,limit,approved?ApprovalPlanState.AVAILABLE:ApprovalPlanState.REJECTED));
        }catch(IllegalArgumentException|NullPointerException|ArithmeticException|java.time.DateTimeException rejected){throw invalid();}
    }
    public static PreparedReservation prepareReservation(ReserveCommand command,ReservationBindings bindings,EvidenceSnapshot evidence) {
        try {
            required(command);required(bindings);var b=bindings.review();var a=bindings.approval();var g=bindings.paymentGrant();
            var current=material(b,evidence,command.now());var d=command.domain();var i=command.identity();scope(i,current.scope());
            var t=bindings.paymentReference();
            if(!t.workflowId().equals(i.workflowId()) || t.generation()!=i.generation() || !t.customerId().equals(i.customerId())
                    || !t.grantId().equals(i.grantId()) || !t.actionId().equals(i.actionId()) || !t.targetRunId().equals(i.targetRunId())
                    || !b.evaluation().loanGrant().targetRunId().equals(t.sourceRunId())
                    || !b.evaluation().loanReceipt().result().resultId().equals(t.sourceResultId()) || t.resultId()!=null
                    || !t.documentId().equals(current.documentId()) || t.documentVersion()!=current.documentVersion())throw invalid();
            if(a.decision()!=ReviewDecision.APPROVE || a.state()!=ApprovalPlanState.AVAILABLE || !command.now().isBefore(a.expiresAt())
                    || !a.material().equals(current) || !a.reviewSnapshotHash().equals(reviewHash(current))
                    || !a.reviewSnapshotHash().equals(command.expectedReviewSnapshotHash())
                    || a.extraRiskLimit()!=b.workflow().terms().additionalApprovalLimit() || a.riskLimit()!=current.riskLimitAfterApproval()
                    || b.workflow().riskLimit()!=a.riskLimit() || g.state()!=GrantState.ISSUED || g.action()!=AllowedAction.EXECUTE_MOCK_PAYMENT
                    || !g.grantId().equals(i.grantId()) || !g.actionId().equals(i.actionId()) || !g.targetRunId().equals(i.targetRunId())
                    || !g.workflowId().equals(i.workflowId()) || g.generation()!=i.generation() || !g.customerId().equals(i.customerId())
                    || !d.approvalId().equals(a.approvalId()) || !d.applicationId().equals(current.applicationId())
                    || d.amountKrw()!=current.amountKrw() || !d.payoutAccountId().equals(current.payoutAccountId())
                    || !d.securityPolicyVersion().equals(current.policyVersion())
                    || Math.addExact(Math.addExact(b.workflow().usedRisk(),b.workflow().reservedRisk()),b.workflow().terms().payPoints())>a.riskLimit())throw invalid();
            return new PreparedReservation(command,bindings,new ApprovalSnapshot(a.approvalId(),a.reviewRequestId(),a.reviewerActorId(),a.decision(),
                    a.material(),a.reviewSnapshotHash(),a.createdAt(),a.expiresAt(),a.extraRiskLimit(),a.riskLimit(),ApprovalPlanState.RESERVED),b.workflow().terms().payPoints());
        }catch(IllegalArgumentException|NullPointerException|ArithmeticException rejected){throw invalid();}
    }
}
