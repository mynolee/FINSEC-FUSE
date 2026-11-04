package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.SyntheticMockPaymentReceiptCodec;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;

/** Exact supplied command/domain binding; no real payment, trust or commit proof. */
public final class SyntheticMockPaymentTransactionBinding {
    private SyntheticMockPaymentTransactionBinding() { }
    public static final String RECEIPT_BINDING_PROFILE = "MP-COMMITTED-RECEIPT-1";
    public enum ReservationState { RESERVED, COMMITTED }
    public enum ApprovalState { RESERVED, CONSUMED }
    public record DigestBinding(String identityDigestReference, String algorithm, byte[] bytes) {
        public DigestBinding {
            if (identityDigestReference == null || identityDigestReference.isBlank() || algorithm == null || algorithm.isBlank()
                    || bytes == null || bytes.length < 1 || bytes.length > 128) throw invalid();
            bytes = bytes.clone();
        }
        @Override public byte[] bytes() { return bytes.clone(); }
        @Override public boolean equals(Object other) {
            return other instanceof DigestBinding d && identityDigestReference.equals(d.identityDigestReference)
                    && algorithm.equals(d.algorithm) && Arrays.equals(bytes, d.bytes);
        }
        @Override public int hashCode() { return Objects.hash(identityDigestReference, algorithm, Arrays.hashCode(bytes)); }
        @Override public String toString() { return "DigestBinding[SUPPLIED_REDACTED]"; }
    }
    public record PaymentCommand(StageCommand stage, DigestBinding admittedCommandDigest,
                                 SyntheticMockPaymentReceiptCodec.Input expectedReceipt) {
        public PaymentCommand {
            Objects.requireNonNull(stage); Objects.requireNonNull(admittedCommandDigest); Objects.requireNonNull(expectedReceipt);
        }
        @Override public String toString() { return "PaymentCommand[SUPPLIED_REDACTED]"; }
    }
    public record PaymentDomain(UUID grantId, UUID actionId, UUID paymentId, UUID targetRunId, UUID approvalId,
                                UUID reservationId, UUID workflowId, int generation, String customerId,
                                UUID applicationId, long amountKrw, UUID payoutAccountId, String securityPolicyVersion,
                                ReservationState reservationState, ApprovalState approvalState) {
        public PaymentDomain {
            Objects.requireNonNull(grantId); Objects.requireNonNull(actionId); Objects.requireNonNull(paymentId);
            Objects.requireNonNull(targetRunId); Objects.requireNonNull(approvalId); Objects.requireNonNull(reservationId);
            Objects.requireNonNull(workflowId); Objects.requireNonNull(applicationId); Objects.requireNonNull(payoutAccountId);
            Objects.requireNonNull(reservationState); Objects.requireNonNull(approvalState);
            if (generation < 1 || amountKrw < 1 || amountKrw > 50000000L || customerId == null || customerId.isBlank()
                    || securityPolicyVersion == null || securityPolicyVersion.isBlank()) throw invalid();
        }
        @Override public String toString() { return "PaymentDomain[VIRTUAL_REFERENCE_REDACTED]"; }
    }
    public record ResolvedPayment(PaymentDomain domain, DigestBinding commandDigest,
                                  SyntheticMockPaymentReceiptCodec.Input receiptInput, List<DomainWrite> applicableDomainWrites) {
        public ResolvedPayment {
            Objects.requireNonNull(domain); Objects.requireNonNull(commandDigest); Objects.requireNonNull(receiptInput);
            applicableDomainWrites = List.copyOf(applicableDomainWrites);
        }
        @Override public String toString() { return "ResolvedPayment[REFERENCE_ONLY]"; }
    }
    public interface PaymentFactResolver {
        Gate current(ServerContext context, PaymentCommand command, OwnedTx tx);
        ResolvedPayment resolve(ServerContext context, PaymentCommand command, OwnedTx tx);
    }
    public static SyntheticMockPaymentReceiptCodec.Prepared prepareRequested(PaymentCommand command) {
        if (command == null) throw invalid();
        var c = command.stage(); var i = c.identity(); var p = command.expectedReceipt(); var d = command.admittedCommandDigest();
        if (c.action() != com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction.EXECUTE_MOCK_PAYMENT
                || !i.globalRequestId().equals(p.globalRequestId()) || !i.actorId().equals(p.authenticatedActor())
                || !i.operation().equals(p.operation()) || !i.canonicalizationVersion().equals(p.canonicalizationVersion())
                || !i.canonicalBodyDigest().equals(d.identityDigestReference())
                || !d.algorithm().equals(p.canonicalBodyDigestAlgorithm()) || !Arrays.equals(d.bytes, p.canonicalBodyDigest())
                || !i.grantId().equals(p.grantId()) || !i.actionId().equals(p.actionId()) || !i.targetRunId().equals(p.targetRunId())
                || !i.workflowId().equals(p.workflowId()) || i.generation() != p.generation() || !i.customerId().equals(p.customerId())) throw invalid();
        return SyntheticMockPaymentReceiptCodec.prepare(p);
    }
    public static SyntheticMockPaymentReceiptCodec.Prepared checkResolved(PaymentCommand command, ResolvedPayment resolved) {
        if (resolved == null || !command.admittedCommandDigest().equals(resolved.commandDigest())) throw invalid();
        var expected = prepareRequested(command);
        var actual = SyntheticMockPaymentReceiptCodec.prepare(resolved.receiptInput());
        if (!Arrays.equals(expected.canonicalBytes(), actual.canonicalBytes()) || !Arrays.equals(expected.receiptDigest(), actual.receiptDigest())
                || resolved.domain().reservationState() != ReservationState.RESERVED
                || resolved.domain().approvalState() != ApprovalState.RESERVED) throw invalid();
        checkDomain(resolved.receiptInput(), resolved.domain());
        return actual;
    }
    /** Relational content check only. Final-state trust and current business gates are external. */
    public static void checkDomain(SyntheticMockPaymentReceiptCodec.Input p, PaymentDomain d) {
        if (!p.grantId().equals(d.grantId()) || !p.actionId().equals(d.actionId()) || !p.paymentId().equals(d.paymentId())
                || !p.targetRunId().equals(d.targetRunId()) || !p.approvalId().equals(d.approvalId())
                || !p.reservationId().equals(d.reservationId()) || !p.workflowId().equals(d.workflowId())
                || p.generation() != d.generation() || !p.customerId().equals(d.customerId())
                || !p.applicationId().equals(d.applicationId()) || p.amountKrw() != d.amountKrw()
                || !p.payoutAccountId().equals(d.payoutAccountId()) || !p.securityPolicyVersion().equals(d.securityPolicyVersion())) throw invalid();
    }
    public static PaymentDomain committed(PaymentDomain d) {
        return new PaymentDomain(d.grantId(), d.actionId(), d.paymentId(), d.targetRunId(), d.approvalId(), d.reservationId(),
                d.workflowId(), d.generation(), d.customerId(), d.applicationId(), d.amountKrw(), d.payoutAccountId(),
                d.securityPolicyVersion(), ReservationState.COMMITTED, ApprovalState.CONSUMED);
    }
    static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_MOCK_PAYMENT_TRANSACTION", null); }
}
