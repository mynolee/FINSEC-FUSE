package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.RunStatus;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.ResultStatus;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import java.util.List;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.time.Instant;

/** Server-owned reference mechanics; no installed issuer, durable store or authority proof. */
public interface OwnedGrantTransactionPort {
    enum GrantState { ISSUED, CONSUMED }
    enum Gate { CLEAR, REFUSED, UNKNOWN }
    enum ReceiptKind { CONSUMPTION, ISSUANCE }
    enum Status { VIRTUAL_COMMITTED_IN_PROCESS, VIRTUAL_REPLAYED_IN_PROCESS,
        NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, REFUSED_BEFORE_ADMISSION,
        UNCONFIRMED_BEFORE_ADMISSION, IDENTITY_CONFLICT, COMMIT_UNKNOWN, RECONCILIATION_UNCONFIRMED, TRANSACTION_INVARIANT_UNCONFIRMED }
    enum EffectKnowledge { NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION, COMMITTED_IN_PROCESS, UNKNOWN }
    interface ServerContext { String actorId(); }
    record StageCommand(CommandIdentity identity, AllowedAction action) {
        public StageCommand { Objects.requireNonNull(identity); Objects.requireNonNull(action); }
        @Override public String toString() { return "StageCommand[REDACTED]"; }
    }
    record OutsidePreparedResult(UUID resultId, BusinessConclusion businessConclusion,
                                 String bindingProfile, byte[] bindingBytes, byte[] bindingDigest) {
        public OutsidePreparedResult {
            Objects.requireNonNull(resultId); Objects.requireNonNull(businessConclusion);
            if (bindingProfile == null || bindingProfile.isBlank() || bindingBytes == null || bindingBytes.length == 0
                    || bindingDigest == null || bindingDigest.length == 0) throw new IllegalArgumentException("INVALID_GRANT_COMMAND");
            bindingBytes = bindingBytes.clone(); bindingDigest = bindingDigest.clone();
        }
        @Override public byte[] bindingBytes() { return bindingBytes.clone(); }
        @Override public byte[] bindingDigest() { return bindingDigest.clone(); }
        @Override public boolean equals(Object other) {
            return other instanceof OutsidePreparedResult r && resultId.equals(r.resultId)
                    && businessConclusion == r.businessConclusion && bindingProfile.equals(r.bindingProfile)
                    && Arrays.equals(bindingBytes, r.bindingBytes) && Arrays.equals(bindingDigest, r.bindingDigest);
        }
        @Override public int hashCode() {
            return Objects.hash(resultId, businessConclusion, bindingProfile, Arrays.hashCode(bindingBytes), Arrays.hashCode(bindingDigest));
        }
        @Override public String toString() { return "OutsidePreparedResult[SUPPLIED_REDACTED]"; }
    }
    record GrantSnapshot(UUID grantId, UUID actionId, UUID targetRunId, UUID workflowId,
                         int generation, String customerId, AllowedAction action, GrantState state) {
        public GrantSnapshot {
            Objects.requireNonNull(grantId); Objects.requireNonNull(actionId); Objects.requireNonNull(targetRunId);
            Objects.requireNonNull(workflowId); Objects.requireNonNull(action); Objects.requireNonNull(state);
            if (generation < 1 || customerId == null || customerId.isBlank()) throw new IllegalArgumentException("INVALID_GRANT_COMMAND");
        }
        @Override public String toString() { return "GrantSnapshot[SUPPLIED_REDACTED]"; }
    }
    record DomainWrite(UUID id, Map<String, Object> value) {
        public DomainWrite { Objects.requireNonNull(id); value = CanonicalJson.immutableObject(Objects.requireNonNull(value)); }
        @Override public String toString() { return "DomainWrite[REDACTED]"; }
    }
    record ResolvedStage(GrantSnapshot grant, OutsidePreparedResult result, RunStatus runStatus,
                         ResultStatus resultStatus, List<DomainWrite> domainWrites, String inputSnapshotHash) {
        public ResolvedStage(GrantSnapshot grant, OutsidePreparedResult result, RunStatus runStatus,
                             ResultStatus resultStatus, List<DomainWrite> domainWrites) {
            this(grant, result, runStatus, resultStatus, domainWrites, null);
        }
        public ResolvedStage {
            Objects.requireNonNull(grant); Objects.requireNonNull(result);
            Objects.requireNonNull(runStatus); Objects.requireNonNull(resultStatus);
            domainWrites = List.copyOf(domainWrites);
        }
        @Override public String toString() { return "ResolvedStage[REFERENCE_ONLY]"; }
    }
    record Receipt(CommandIdentity identity, ReceiptKind kind, OutsidePreparedResult result, UUID parentGrantId) {
        public Receipt {
            Objects.requireNonNull(identity); Objects.requireNonNull(kind);
            if ((kind == ReceiptKind.CONSUMPTION && (result == null || parentGrantId != null))
                    || (kind == ReceiptKind.ISSUANCE && (result != null || parentGrantId == null)))
                throw new IllegalArgumentException("INVALID_GRANT_COMMAND");
        }
        @Override public String toString() { return "Receipt[VIRTUAL_NON_DURABLE]"; }
    }
    record EvaluationRefusal(int version, CommandIdentity identity, UUID retainedKycResultId) {
        public EvaluationRefusal {
            if (version != 1 || identity == null || retainedKycResultId == null) throw new IllegalArgumentException("INVALID_GRANT_COMMAND");
        }
        public String reason() { return "RISK_LIMIT_EXCEEDED"; }
        public String state() { return "ON_HOLD"; }
        public String decision() { return "DENY"; }
        public boolean actualAuthority() { return false; }
        public boolean durable() { return false; }
        @Override public String toString() { return "EvaluationRefusal[VIRTUAL_REDACTED]"; }
    }
    record StageOutcome(Status status, Receipt receipt, EffectKnowledge effectKnowledge, EvaluationRefusal evaluationRefusal) {
        public StageOutcome(Status status, Receipt receipt, EffectKnowledge effectKnowledge) {
            this(status, receipt, effectKnowledge, null);
        }
        public StageOutcome {
            Objects.requireNonNull(status); Objects.requireNonNull(effectKnowledge);
            if (evaluationRefusal != null && (status != Status.REFUSED_BEFORE_ADMISSION || receipt != null
                    || effectKnowledge != EffectKnowledge.NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION))
                throw new IllegalArgumentException("INVALID_GRANT_COMMAND");
            boolean committed = status == Status.VIRTUAL_COMMITTED_IN_PROCESS || status == Status.VIRTUAL_REPLAYED_IN_PROCESS;
            boolean unknown = status == Status.COMMIT_UNKNOWN || status == Status.RECONCILIATION_UNCONFIRMED
                    || status == Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH || status == Status.TRANSACTION_INVARIANT_UNCONFIRMED;
            if ((committed && (receipt == null || effectKnowledge != EffectKnowledge.COMMITTED_IN_PROCESS))
                    || (!committed && receipt != null)
                    || (unknown && effectKnowledge != EffectKnowledge.UNKNOWN)
                    || (!committed && !unknown && effectKnowledge != EffectKnowledge.NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION))
                throw new IllegalArgumentException("INVALID_GRANT_COMMAND");
        }
        public boolean actualAuthority() { return false; }
        public boolean durable() { return false; }
        public String reason() {
            if (evaluationRefusal != null) return evaluationRefusal.reason();
            return switch (status) {
                case VIRTUAL_COMMITTED_IN_PROCESS, VIRTUAL_REPLAYED_IN_PROCESS -> "NONE";
                case REFUSED_BEFORE_ADMISSION -> "CURRENT_ACCESS_REFUSED";
                case UNCONFIRMED_BEFORE_ADMISSION -> "FINALITY_UNCONFIRMED";
                case IDENTITY_CONFLICT -> "IDENTITY_CONFLICT";
                case COMMIT_UNKNOWN -> "COMMIT_UNKNOWN";
                case TRANSACTION_INVARIANT_UNCONFIRMED -> "TRANSACTION_INVARIANT_UNCONFIRMED";
                default -> "RECONCILIATION_UNCONFIRMED";
            };
        }
        public static StageOutcome of(Status status, Receipt receipt, EffectKnowledge effect) {
            return new StageOutcome(status, receipt, effect);
        }
        @Override public String toString() { return "StageOutcome[VIRTUAL_NON_AUTHORIZING]"; }
    }
    /** Implementations resolve local server facts only; no provider/IO under the owned transaction. */
    interface CurrentFactResolver {
        Gate current(ServerContext context, StageCommand command, OwnedTx tx);
        ResolvedStage resolve(ServerContext context, StageCommand command, OutsidePreparedResult prepared, OwnedTx tx);
        Gate checkIssuance(ServerContext context, StageCommand command, UUID parentGrantId, GrantSnapshot child, OwnedTx tx);
    }
    record PaymentIssuanceProof(SyntheticMockPaymentPlanBinding.ApprovalSnapshot approval,
                                SyntheticMockPaymentTransactionBinding.PaymentDomain intendedPlan, Instant now) {
        public PaymentIssuanceProof {
            if (approval == null || now == null) throw new IllegalArgumentException("INVALID_GRANT_COMMAND", null);
        }
        public boolean actualAuthority() { return false; }
        @Override public String toString() { return "PaymentIssuanceProof[SUPPLIED_REDACTED]"; }
    }
    interface OwnedTx {
        Receipt lookup(StageCommand command);
        StageOutcome lookupRecordedOutcome(StageCommand command);
        void admitFresh(StageCommand command);
        void requireKycPreparation(StageCommand command, String inputSnapshotHash);
        void bindCurrentIssuanceTime(StageCommand command, Instant snapshotTime);
        GrantSnapshot grant(UUID id);
        Receipt commit(StageCommand command, ResolvedStage stage);
        StageOutcome commitEvaluation(StageCommand command, ResolvedStage stage);
        SyntheticMockPaymentTransactionBinding.PaymentDomain paymentDomain(UUID reservationId);
        Receipt commitMockPayment(StageCommand command, SyntheticMockPaymentTransactionBinding.ResolvedPayment payment);
        Receipt issueSuccessor(StageCommand command, UUID parentGrantId, GrantSnapshot child);
        Receipt issueSuccessor(StageCommand command, UUID parentGrantId, GrantSnapshot child, PaymentIssuanceProof proof);
    }
    interface Work { StageOutcome apply(OwnedTx tx); }
    StageOutcome transact(StageCommand command, Work work);
    static RuntimeException stop(Status status) { return new Stop(status); }
    final class Stop extends RuntimeException {
        final Status status;
        private Stop(Status status) {
            super("GRANT_STAGE_REFUSED", null);
            if (status != Status.REFUSED_BEFORE_ADMISSION && status != Status.UNCONFIRMED_BEFORE_ADMISSION
                    && status != Status.IDENTITY_CONFLICT && status != Status.RECONCILIATION_UNCONFIRMED
                    && status != Status.TRANSACTION_INVARIANT_UNCONFIRMED)
                throw new IllegalArgumentException("INVALID_GRANT_COMMAND");
            this.status = status;
        }
    }
}
