package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane.Scope;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;

/** Supplied snapshot consistency only; no IO, producer truth, completeness or authorization. */
public final class TypedContinuationPendingAdmission {
    private TypedContinuationPendingAdmission() { }
    public enum Use { FRESH_ADMISSION, HISTORICAL_REPLAY }
    public enum Outcome { REFUSE_NO_MUTATION, RECONCILIATION_UNKNOWN,
        EMPTY_EVIDENCE_NOT_AUTHORIZATION, OUTSIDE_FRESH_RULE }
    public enum Reason { STRUCTURALLY_MATCHED_PENDING, UNRESOLVED_REQUEST, UNCONFIRMED_GLOBAL,
        UNCONFIRMED_PRODUCER, INCONSISTENT_EVIDENCE, INVALID_COUNTER, BOUNDS_EXCEEDED,
        EMPTY_SUPPLIED_SET, HISTORY_NOT_FRESH }
    public enum GlobalState { COMPLETED, PENDING, COMMIT_UNKNOWN, UNCONFIRMED }
    public enum RiskState { RESERVED, CONSUMED, UNCONFIRMED }
    public enum ProducerState { NO_EXECUTION_OBSERVED, IN_FLIGHT, COMMIT_UNKNOWN, EXECUTED, UNCONFIRMED }

    /** Explicit caller allocation limits; no operational default. */
    public record Profile(int maxReservations, int maxEvidenceRows) {
        public Profile { if (maxReservations < 1 || maxEvidenceRows < 1) throw invalid(); }
    }
    public record LocalPlanRecord(PlanReceipt receipt, String commandFingerprint) {
        @Override public String toString() { return "LocalPlanRecord[REDACTED]"; }
    }
    /** A typed projection of an observed global record, not authentication of its origin. */
    public record GlobalPlanRecord(CommandIdentity identity, String commandFingerprint,
                                   PlanReceipt receipt, GlobalState state) {
        @Override public String toString() { return "GlobalPlanRecord[SUPPLIED_REDACTED]"; }
    }
    public record RiskReservation(UUID reservationId, UUID paymentId, UUID approvalId, UUID grantId,
                                  UUID actionId, UUID targetRunId, Scope scope, String policyVersion,
                                  int points, RiskState state) {
        @Override public String toString() { return "RiskReservation[SUPPLIED_REDACTED]"; }
    }
    public record ProducerObservation(UUID reservationId, ProducerState state, CommandIdentity executionIdentity) {
        @Override public String toString() { return "ProducerObservation[SUPPLIED_REDACTED]"; }
    }
    public record UnsettledRequest(CommandIdentity identity, GlobalState state) {
        @Override public String toString() { return "UnsettledRequest[SUPPLIED_REDACTED]"; }
    }
    /** Nullable observed fields express incomplete evidence; they never establish coherence. */
    public record ReservationEvidence(LocalPlanRecord review, GlobalPlanRecord reviewGlobal,
                                      LocalPlanRecord reserve, GlobalPlanRecord reserveGlobal,
                                      ApprovalSnapshot currentApproval, PaymentDomain currentPlan,
                                      GrantSnapshot paymentGrant,
                                      VirtualGrantTransactionJournal.TypedReference paymentReference,
                                      GrantSnapshot loanGrant, Receipt loanReceipt,
                                      VirtualGrantTransactionJournal.TypedReference loanReference) {
        @Override public String toString() { return "ReservationEvidence[SUPPLIED_REDACTED]"; }
    }
    public record Snapshot(Scope scope, SimulationSpec.RiskTerms terms, int reservedRisk,
                           List<ReservationEvidence> reservations, List<RiskReservation> riskInventory,
                           List<ProducerObservation> producerInventory, List<UnsettledRequest> unsettledRequests) {
        public Snapshot {
            if (scope == null || terms == null) throw invalid();
            try {
                reservations = List.copyOf(reservations); riskInventory = List.copyOf(riskInventory);
                producerInventory = List.copyOf(producerInventory); unsettledRequests = List.copyOf(unsettledRequests);
            } catch (RuntimeException rejected) { throw invalid(); }
        }
        @Override public String toString() { return "PendingSnapshot[SUPPLIED_REDACTED]"; }
    }
    public static final class Assessment {
        private final Outcome outcome; private final Reason reason; private final int matchedReservations;
        private Assessment(Outcome outcome, Reason reason, int matchedReservations) {
            this.outcome = outcome; this.reason = reason; this.matchedReservations = matchedReservations;
        }
        public Outcome outcome() { return outcome; }
        public Reason reason() { return reason; }
        public int matchedReservations() { return matchedReservations; }
        public boolean mutationPermitted() { return false; }
        public boolean continuationAuthorized() { return false; }
        public boolean queryCompletenessEstablished() { return false; }
        public boolean producerTruthEstablished() { return false; }
        public boolean actualAuthority() { return false; }
        @Override public String toString() { return "PendingAssessment[NON_AUTHORIZING]"; }
    }
    public static Assessment assess(Profile profile, Use use, Snapshot snapshot) {
        if (profile == null || use == null || snapshot == null) throw invalid();
        if (use == Use.HISTORICAL_REPLAY)
            return result(Outcome.OUTSIDE_FRESH_RULE, Reason.HISTORY_NOT_FRESH, 0);
        long rows = (long) snapshot.reservations().size() + snapshot.riskInventory().size()
                + snapshot.producerInventory().size() + snapshot.unsettledRequests().size();
        if (snapshot.reservations().size() > profile.maxReservations() || rows > profile.maxEvidenceRows())
            return unknown(Reason.BOUNDS_EXCEEDED);
        if (snapshot.reservedRisk() < 0) return unknown(Reason.INVALID_COUNTER);
        try {
            for (var request : snapshot.unsettledRequests()) {
                if (request.identity() == null || !scope(request.identity(), snapshot.scope()) || request.state() == null
                        || request.state() == GlobalState.COMPLETED) return unknown(Reason.INCONSISTENT_EVIDENCE);
            }
            if (!snapshot.unsettledRequests().isEmpty()) return unknown(Reason.UNRESOLVED_REQUEST);
            Map<UUID, RiskReservation> risks = new LinkedHashMap<>();
            for (var risk : snapshot.riskInventory()) {
                if (risk.reservationId() == null || risks.put(risk.reservationId(), risk) != null
                        || !snapshot.scope().equals(risk.scope()) || risk.points() < 1
                        || risk.points() != snapshot.terms().payPoints() || risk.state() != RiskState.RESERVED
                        || !snapshot.terms().policyVersion().equals(risk.policyVersion()))
                    return unknown(Reason.INCONSISTENT_EVIDENCE);
            }
            Map<UUID, ProducerObservation> producers = new LinkedHashMap<>();
            for (var producer : snapshot.producerInventory()) {
                if (producer.reservationId() == null || producers.put(producer.reservationId(), producer) != null
                        || !risks.containsKey(producer.reservationId())) return unknown(Reason.INCONSISTENT_EVIDENCE);
                if (producer.state() != ProducerState.NO_EXECUTION_OBSERVED)
                    return unknown(Reason.UNCONFIRMED_PRODUCER);
                if (producer.executionIdentity() != null) return unknown(Reason.INCONSISTENT_EVIDENCE);
            }
            var reservationIds = new HashSet<UUID>(); var payments = new HashSet<UUID>();
            var approvals = new HashSet<UUID>(); var grants = new HashSet<UUID>();
            var actions = new HashSet<UUID>(); var targets = new HashSet<UUID>(); var requests = new HashSet<UUID>();
            Map<UUID, Receipt> loanRequests = new LinkedHashMap<>();
            Map<UUID, Receipt> loanGrants = new LinkedHashMap<>();
            Map<UUID, Receipt> loanActions = new LinkedHashMap<>();
            Map<UUID, Receipt> loanTargets = new LinkedHashMap<>();
            Map<UUID, Receipt> loanResults = new LinkedHashMap<>();
            long total = 0;
            for (var entry : snapshot.reservations()) {
                if (entry.reviewGlobal() != null && entry.reviewGlobal().state() != GlobalState.COMPLETED
                        || entry.reserveGlobal() != null && entry.reserveGlobal().state() != GlobalState.COMPLETED)
                    return unknown(Reason.UNCONFIRMED_GLOBAL);
                if (!matches(entry, snapshot)) return unknown(Reason.INCONSISTENT_EVIDENCE);
                var plan = entry.currentPlan(); var risk = risks.get(plan.reservationId());
                if (risk == null || !riskMatches(risk, plan) || !producers.containsKey(plan.reservationId())
                        || !reservationIds.add(plan.reservationId()) || !payments.add(plan.paymentId())
                        || !approvals.add(plan.approvalId()) || !grants.add(plan.grantId())
                        || !actions.add(plan.actionId()) || !targets.add(plan.targetRunId())
                        || !requests.add(entry.review().receipt().identity().globalRequestId())
                        || !requests.add(entry.reserve().receipt().identity().globalRequestId()))
                    return unknown(Reason.INCONSISTENT_EVIDENCE);
                var loanReceipt = entry.loanReceipt(); var loanRequest = loanReceipt.identity().globalRequestId();
                var oldLoan = loanRequests.putIfAbsent(loanRequest, loanReceipt);
                if (oldLoan != null && !oldLoan.equals(loanReceipt)) return unknown(Reason.INCONSISTENT_EVIDENCE);
                if (!sameConsumption(loanGrants, entry.loanGrant().grantId(), loanReceipt)
                        || !sameConsumption(loanActions, entry.loanGrant().actionId(), loanReceipt)
                        || !sameConsumption(loanTargets, entry.loanGrant().targetRunId(), loanReceipt)
                        || !sameConsumption(loanResults, loanReceipt.result().resultId(), loanReceipt))
                    return unknown(Reason.INCONSISTENT_EVIDENCE);
                total += risk.points();
                if (total > Integer.MAX_VALUE) return unknown(Reason.INVALID_COUNTER);
            }
            if (reservationIds.size() != risks.size() || producers.size() != risks.size()
                    || total != snapshot.reservedRisk() || !java.util.Collections.disjoint(requests, loanRequests.keySet())
                    || !java.util.Collections.disjoint(grants, loanGrants.keySet()) || !java.util.Collections.disjoint(actions, loanActions.keySet())
                    || !java.util.Collections.disjoint(targets, loanTargets.keySet())) return unknown(Reason.INCONSISTENT_EVIDENCE);
            if (reservationIds.isEmpty())
                return result(Outcome.EMPTY_EVIDENCE_NOT_AUTHORIZATION, Reason.EMPTY_SUPPLIED_SET, 0);
            return result(Outcome.REFUSE_NO_MUTATION, Reason.STRUCTURALLY_MATCHED_PENDING, reservationIds.size());
        } catch (RuntimeException rejected) { return unknown(Reason.INCONSISTENT_EVIDENCE); }
    }
    private static boolean sameConsumption(Map<UUID, Receipt> observed, UUID id, Receipt receipt) {
        var prior = observed.putIfAbsent(id, receipt);
        return prior == null || prior.equals(receipt);
    }
    private static boolean matches(ReservationEvidence e, Snapshot s) {
        if (e.review() == null || e.reserve() == null || e.reviewGlobal() == null || e.reserveGlobal() == null
                || e.currentApproval() == null || e.currentPlan() == null || e.paymentGrant() == null
                || e.paymentReference() == null || e.loanGrant() == null || e.loanReceipt() == null || e.loanReference() == null)
            return false;
        var review = e.review().receipt(); var reserve = e.reserve().receipt(); var a = e.currentApproval();
        var d = e.currentPlan(); var g = e.paymentGrant(); var r = e.paymentReference();
        var loan = e.loanGrant(); var lr = e.loanReceipt(); var ref = e.loanReference(); var m = a.material();
        if (review == null || reserve == null || !global(e.review(), e.reviewGlobal()) || !global(e.reserve(), e.reserveGlobal())
                || review.purpose() != PlanOperation.REVIEW || reserve.purpose() != PlanOperation.RESERVE
                || !scope(review.identity(), s.scope()) || !scope(reserve.identity(), s.scope())
                || review.domain() != null || review.riskPoints() != 0 || reserve.riskPoints() != s.terms().payPoints()
                || !d.equals(reserve.domain()) || !a.equals(reserve.approval())
                || a.decision() != ReviewDecision.APPROVE || a.state() != ApprovalPlanState.RESERVED
                || review.approval().state() != ApprovalPlanState.AVAILABLE || !sameApproval(a, review.approval())
                || !a.reviewRequestId().equals(review.identity().globalRequestId())
                || !a.reviewerActorId().equals(review.identity().actorId()) || !m.scope().equals(s.scope())
                || !a.reviewSnapshotHash().equals(SyntheticMockPaymentPlanBinding.reviewHash(m))
                || !m.policyVersion().equals(s.terms().policyVersion())
                || a.extraRiskLimit() != s.terms().additionalApprovalLimit()
                || a.riskLimit() != Math.addExact(s.terms().baseLimit(), s.terms().additionalApprovalLimit())
                || m.riskLimitAfterApproval() != a.riskLimit()
                || d.reservationState() != ReservationState.RESERVED || d.approvalState() != ApprovalState.RESERVED
                || !d.approvalId().equals(a.approvalId()) || !d.applicationId().equals(m.applicationId())
                || d.amountKrw() != m.amountKrw() || !d.payoutAccountId().equals(m.payoutAccountId())
                || !d.securityPolicyVersion().equals(m.policyVersion())
                || !grant(g, d.grantId(), d.actionId(), d.targetRunId(), s.scope(), AllowedAction.EXECUTE_MOCK_PAYMENT, GrantState.ISSUED)
                || !identity(reserve.identity(), g) || !reference(r, g)
                || r.resultId() != null || !r.documentId().equals(m.documentId()) || r.documentVersion() != m.documentVersion()
                || !grant(loan, loan.grantId(), loan.actionId(), loan.targetRunId(), s.scope(), AllowedAction.CREATE_LOAN_RECOMMENDATION, GrantState.CONSUMED)
                || !identity(review.identity(), loan) || !identity(lr.identity(), loan)
                || lr.kind() != ReceiptKind.CONSUMPTION || lr.result() == null || lr.parentGrantId() != null
                || lr.result().businessConclusion() != BusinessConclusion.POSITIVE
                || !"AGENT_RESULT_BINDING_RECORD_1".equals(lr.result().bindingProfile())
                || !lr.result().resultId().equals(m.loanResultId()) || !reference(ref, loan)
                || !Objects.equals(ref.resultId(), m.loanResultId())
                || !ref.documentId().equals(m.documentId()) || ref.documentVersion() != m.documentVersion()
                || !Objects.equals(ref.sourceResultId(), m.kycResultId()) || m.kycResultId().equals(m.loanResultId())
                || ref.sourceRunId() == null || ref.sourceRunId().equals(loan.targetRunId())
                || !Objects.equals(r.sourceRunId(), loan.targetRunId()) || !Objects.equals(r.sourceResultId(), m.loanResultId()))
            return false;
        return true;
    }
    private static boolean global(LocalPlanRecord local, GlobalPlanRecord global) {
        return local.receipt() != null && global.state() == GlobalState.COMPLETED
                && local.receipt().equals(global.receipt()) && local.receipt().identity().equals(global.identity())
                && local.commandFingerprint() != null && local.commandFingerprint().matches("[0-9a-f]{64}")
                && local.commandFingerprint().equals(global.commandFingerprint());
    }
    private static boolean sameApproval(ApprovalSnapshot a, ApprovalSnapshot b) {
        return a.approvalId().equals(b.approvalId()) && a.reviewRequestId().equals(b.reviewRequestId())
                && a.reviewerActorId().equals(b.reviewerActorId()) && a.decision() == b.decision()
                && a.material().equals(b.material()) && a.reviewSnapshotHash().equals(b.reviewSnapshotHash())
                && a.createdAt().equals(b.createdAt()) && a.expiresAt().equals(b.expiresAt())
                && a.extraRiskLimit() == b.extraRiskLimit() && a.riskLimit() == b.riskLimit();
    }
    private static boolean scope(CommandIdentity i, Scope s) {
        return i != null && s.workflowId().equals(i.workflowId()) && s.generation() == i.generation()
                && s.customerId().equals(i.customerId());
    }
    private static boolean identity(CommandIdentity i, GrantSnapshot g) {
        return i != null && i.grantId().equals(g.grantId()) && i.actionId().equals(g.actionId())
                && i.targetRunId().equals(g.targetRunId()) && i.workflowId().equals(g.workflowId())
                && i.generation() == g.generation() && i.customerId().equals(g.customerId());
    }
    private static boolean grant(GrantSnapshot g, UUID grantId, UUID actionId, UUID target, Scope s,
                                 AllowedAction action, GrantState state) {
        return g.grantId().equals(grantId) && g.actionId().equals(actionId) && g.targetRunId().equals(target)
                && g.workflowId().equals(s.workflowId()) && g.generation() == s.generation()
                && g.customerId().equals(s.customerId()) && g.action() == action && g.state() == state;
    }
    private static boolean reference(VirtualGrantTransactionJournal.TypedReference r, GrantSnapshot g) {
        return r.workflowId().equals(g.workflowId()) && r.generation() == g.generation() && r.customerId().equals(g.customerId())
                && r.grantId().equals(g.grantId()) && r.actionId().equals(g.actionId()) && r.targetRunId().equals(g.targetRunId());
    }
    private static boolean riskMatches(RiskReservation r, PaymentDomain d) {
        return Objects.equals(r.paymentId(), d.paymentId()) && Objects.equals(r.approvalId(), d.approvalId())
                && Objects.equals(r.grantId(), d.grantId()) && Objects.equals(r.actionId(), d.actionId())
                && Objects.equals(r.targetRunId(), d.targetRunId()) && r.scope().workflowId().equals(d.workflowId())
                && r.scope().generation() == d.generation() && r.scope().customerId().equals(d.customerId());
    }
    private static Assessment unknown(Reason reason) { return result(Outcome.RECONCILIATION_UNKNOWN, reason, 0); }
    private static Assessment result(Outcome outcome, Reason reason, int count) { return new Assessment(outcome, reason, count); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_PENDING_ADMISSION", null); }
}
