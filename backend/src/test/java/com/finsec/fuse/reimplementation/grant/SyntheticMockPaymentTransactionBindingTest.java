package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticMockPaymentReceiptCodec;
import com.finsec.fuse.reimplementation.auth.SyntheticMockPaymentReceiptCodec.Input;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;
import static org.junit.jupiter.api.Assertions.*;

/** Pure supplied-data binding tests, not authenticated payment or committed storage evidence. */
class SyntheticMockPaymentTransactionBindingTest {
    static UUID id(long n) { return new UUID(8, n); }
    static Input input() {
        return new Input(id(1), "synthetic-actor", "synthetic-payment", "supplied-command-profile",
                "supplied-algorithm", new byte[] {4, 5}, id(2), id(3), id(4), id(5), id(6), id(7),
                id(8), 1, "synthetic-customer", id(9), 1000L, id(10), "synthetic-policy",
                "EXECUTE_MOCK_PAYMENT", "COMMITTED", "CONSUMED");
    }
    static PaymentCommand command(Input p) {
        var identity = new CommandIdentity(p.authenticatedActor(), p.globalRequestId(), p.operation(),
                p.canonicalizationVersion(), "supplied-digest-reference", p.grantId(), p.actionId(),
                p.targetRunId(), p.workflowId(), p.generation(), p.customerId());
        return new PaymentCommand(new StageCommand(identity, AllowedAction.EXECUTE_MOCK_PAYMENT),
                new DigestBinding(identity.canonicalBodyDigest(), p.canonicalBodyDigestAlgorithm(), p.canonicalBodyDigest()), p);
    }
    static PaymentDomain domain(Input p) {
        return new PaymentDomain(p.grantId(), p.actionId(), p.paymentId(), p.targetRunId(), p.approvalId(),
                p.reservationId(), p.workflowId(), p.generation(), p.customerId(), p.applicationId(),
                p.amountKrw(), p.payoutAccountId(), p.securityPolicyVersion(), ReservationState.RESERVED, ApprovalState.RESERVED);
    }
    static ResolvedPayment resolved(PaymentCommand c) {
        return new ResolvedPayment(domain(c.expectedReceipt()), c.admittedCommandDigest(), c.expectedReceipt(), List.of());
    }
    /** Change one exact field; the fixed literals intentionally fail codec admission. */
    static Input changed(Input p, int f) {
        return new Input(f == 1 ? id(99) : p.globalRequestId(), f == 2 ? "other-actor" : p.authenticatedActor(),
                f == 3 ? "other-operation" : p.operation(), f == 4 ? "other-profile" : p.canonicalizationVersion(),
                f == 5 ? "other-algorithm" : p.canonicalBodyDigestAlgorithm(), f == 6 ? new byte[] {9} : p.canonicalBodyDigest(),
                f == 7 ? id(99) : p.grantId(), f == 8 ? id(99) : p.actionId(), f == 9 ? id(99) : p.paymentId(),
                f == 10 ? id(99) : p.targetRunId(), f == 11 ? id(99) : p.approvalId(),
                f == 12 ? id(99) : p.reservationId(), f == 13 ? id(99) : p.workflowId(),
                f == 14 ? 2 : p.generation(), f == 15 ? "other-customer" : p.customerId(),
                f == 16 ? id(99) : p.applicationId(), f == 17 ? 1001L : p.amountKrw(),
                f == 18 ? id(99) : p.payoutAccountId(), f == 19 ? "other-policy" : p.securityPolicyVersion(),
                f == 20 ? "OTHER_ACTION" : p.grantAction(), f == 21 ? "RESERVED" : p.reservationStateAtCommit(),
                f == 22 ? "RESERVED" : p.approvalStateAtCommit());
    }

    @Test void exactContentMatchesExistingCodecWithoutClaimingAuthorityOrCommit() {
        PaymentCommand c = command(input()); var expected = SyntheticMockPaymentReceiptCodec.prepare(c.expectedReceipt());
        var requested = prepareRequested(c); var checked = checkResolved(c, resolved(c));
        assertArrayEquals(expected.canonicalBytes(), requested.canonicalBytes());
        assertArrayEquals(expected.canonicalBytes(), checked.canonicalBytes());
        assertArrayEquals(expected.receiptDigest(), checked.receiptDigest());
        assertEquals(SyntheticMockPaymentReceiptCodec.PROFILE_NAME, checked.profileName());
        assertFalse(checked.authorizationEstablished()); assertFalse(checked.commitEstablished());
    }

    @Test void everyReceiptFieldMismatchIsRejectedWithoutAcceptingOtherPreparedMaterial() {
        PaymentCommand c = command(input()); byte[] before = prepareRequested(c).canonicalBytes();
        for (int field = 1; field <= 22; field++) {
            final int f = field;
            assertThrows(IllegalArgumentException.class, () -> {
                // 1..19 construct valid alternative content; 20..22 are fixed-literal constructor refusals.
                Input other = changed(c.expectedReceipt(), f);
                checkResolved(c, new ResolvedPayment(domain(c.expectedReceipt()), c.admittedCommandDigest(), other, List.of()));
            }, "receipt field " + field);
        }
        assertArrayEquals(before, prepareRequested(c).canonicalBytes());
    }

    @Test void allElevenCommandIdentityComponentsMustMatchTheReceiptAndDigestReference() {
        PaymentCommand c = command(input()); CommandIdentity i = c.stage().identity();
        for (int field = 0; field < 11; field++) {
            CommandIdentity other = new CommandIdentity(field == 0 ? "other-actor" : i.actorId(),
                    field == 1 ? id(99) : i.globalRequestId(), field == 2 ? "other-operation" : i.operation(),
                    field == 3 ? "other-profile" : i.canonicalizationVersion(),
                    field == 4 ? "other-reference" : i.canonicalBodyDigest(), field == 5 ? id(99) : i.grantId(),
                    field == 6 ? id(99) : i.actionId(), field == 7 ? id(99) : i.targetRunId(),
                    field == 8 ? id(99) : i.workflowId(), field == 9 ? 2 : i.generation(),
                    field == 10 ? "other-customer" : i.customerId());
            assertThrows(IllegalArgumentException.class, () -> prepareRequested(new PaymentCommand(
                    new StageCommand(other, AllowedAction.EXECUTE_MOCK_PAYMENT), c.admittedCommandDigest(), c.expectedReceipt())));
        }
    }

    @Test void commandAlgorithmBytesAndOpaqueReferenceRemainSeparateFromReceiptSha256() {
        PaymentCommand c = command(input()); DigestBinding d = c.admittedCommandDigest();
        for (DigestBinding bad : List.of(new DigestBinding("other-reference", d.algorithm(), d.bytes()),
                new DigestBinding(d.identityDigestReference(), "SHA-256", d.bytes()),
                new DigestBinding(d.identityDigestReference(), d.algorithm(), new byte[] {8}))) {
            assertThrows(IllegalArgumentException.class, () -> prepareRequested(new PaymentCommand(c.stage(), bad, c.expectedReceipt())));
            assertThrows(IllegalArgumentException.class, () -> checkResolved(c,
                    new ResolvedPayment(domain(c.expectedReceipt()), bad, c.expectedReceipt(), List.of())));
        }
        // The admitted opaque command algorithm need not be the receipt's SHA-256 algorithm.
        assertNotNull(prepareRequested(c));
    }

    @Test void everyNonStateDomainRelationshipMustEqualTheReceipt() {
        PaymentCommand c = command(input());
        for (int field : new int[] {7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}) {
            PaymentDomain wrong = domain(changed(c.expectedReceipt(), field));
            assertThrows(IllegalArgumentException.class, () -> checkDomain(c.expectedReceipt(), wrong));
            assertThrows(IllegalArgumentException.class, () -> checkResolved(c,
                    new ResolvedPayment(wrong, c.admittedCommandDigest(), c.expectedReceipt(), List.of())));
        }
    }

    @Test void committedTargetLiteralsDoNotAdmitAnAlreadyConsumedOrCommittedPlan() {
        PaymentCommand c = command(input()); PaymentDomain d = domain(c.expectedReceipt());
        PaymentDomain finalState = committed(d);
        assertEquals(ReservationState.RESERVED, d.reservationState()); assertEquals(ApprovalState.RESERVED, d.approvalState());
        assertEquals(ReservationState.COMMITTED, finalState.reservationState());
        assertEquals(ApprovalState.CONSUMED, finalState.approvalState());
        assertDoesNotThrow(() -> checkDomain(c.expectedReceipt(), finalState));
        assertThrows(IllegalArgumentException.class, () -> checkResolved(c,
                new ResolvedPayment(finalState, c.admittedCommandDigest(), c.expectedReceipt(), List.of())));
        PaymentDomain onlyApproval = new PaymentDomain(d.grantId(), d.actionId(), d.paymentId(), d.targetRunId(),
                d.approvalId(), d.reservationId(), d.workflowId(), d.generation(), d.customerId(), d.applicationId(),
                d.amountKrw(), d.payoutAccountId(), d.securityPolicyVersion(), ReservationState.RESERVED, ApprovalState.CONSUMED);
        assertThrows(IllegalArgumentException.class, () -> checkResolved(c,
                new ResolvedPayment(onlyApproval, c.admittedCommandDigest(), c.expectedReceipt(), List.of())));
    }

    @Test void nonPaymentStageCannotBorrowAValidMockPaymentReceipt() {
        PaymentCommand c = command(input());
        for (AllowedAction action : List.of(AllowedAction.EVALUATE_KYC, AllowedAction.CREATE_LOAN_RECOMMENDATION))
            assertThrows(IllegalArgumentException.class, () -> prepareRequested(new PaymentCommand(
                    new StageCommand(c.stage().identity(), action), c.admittedCommandDigest(), c.expectedReceipt())));
    }

    @Test void domainAmountAndGenerationKeepExistingBoundsWithoutTruncation() {
        PaymentDomain d = domain(input());
        for (long amount : new long[] {0, -1, 50000001L, Long.MAX_VALUE})
            assertThrows(IllegalArgumentException.class, () -> new PaymentDomain(d.grantId(), d.actionId(), d.paymentId(),
                    d.targetRunId(), d.approvalId(), d.reservationId(), d.workflowId(), d.generation(), d.customerId(),
                    d.applicationId(), amount, d.payoutAccountId(), d.securityPolicyVersion(), d.reservationState(), d.approvalState()));
        for (long amount : new long[] {1, 50000000L})
            assertDoesNotThrow(() -> new PaymentDomain(d.grantId(), d.actionId(), d.paymentId(), d.targetRunId(),
                    d.approvalId(), d.reservationId(), d.workflowId(), 1, d.customerId(), d.applicationId(), amount,
                    d.payoutAccountId(), d.securityPolicyVersion(), d.reservationState(), d.approvalState()));
        assertThrows(IllegalArgumentException.class, () -> new PaymentDomain(d.grantId(), d.actionId(), d.paymentId(),
                d.targetRunId(), d.approvalId(), d.reservationId(), d.workflowId(), 0, d.customerId(), d.applicationId(),
                d.amountKrw(), d.payoutAccountId(), d.securityPolicyVersion(), d.reservationState(), d.approvalState()));
    }

    @Test void digestLengthAndCopiesAreBoundedWithoutBecomingVerificationEvidence() {
        byte[] bytes = {1, 2}; DigestBinding d = new DigestBinding("synthetic-reference", "supplied-algorithm", bytes);
        bytes[0] = 9; d.bytes()[0] = 8; assertArrayEquals(new byte[] {1, 2}, d.bytes());
        assertEquals(d, new DigestBinding("synthetic-reference", "supplied-algorithm", new byte[] {1, 2}));
        assertEquals(d.hashCode(), new DigestBinding("synthetic-reference", "supplied-algorithm", new byte[] {1, 2}).hashCode());
        for (int size : new int[] {0, 129})
            assertThrows(IllegalArgumentException.class, () -> new DigestBinding("reference", "algorithm", new byte[size]));
        for (int size : new int[] {1, 128})
            assertDoesNotThrow(() -> new DigestBinding("reference", "algorithm", new byte[size]));
    }

    @Test void resolvedWritesDetachContainerAndNestedDomainValues() {
        PaymentCommand c = command(input()); var nested = new ArrayList<>(List.of("initial"));
        var source = new java.util.LinkedHashMap<String, Object>(); source.put("values", nested);
        var writes = new ArrayList<>(List.of(new DomainWrite(id(50), source)));
        var r = new ResolvedPayment(domain(c.expectedReceipt()), c.admittedCommandDigest(), c.expectedReceipt(), writes);
        writes.clear(); nested.add("late"); source.put("extra", "late");
        assertEquals(1, r.applicableDomainWrites().size());
        assertEquals(Map.of("values", List.of("initial")), r.applicableDomainWrites().get(0).value());
        assertThrows(UnsupportedOperationException.class, () -> r.applicableDomainWrites().clear());
        assertThrows(UnsupportedOperationException.class, () -> r.applicableDomainWrites().get(0).value().put("x", "y"));
    }

    @Test void diagnosticsNeverIncludeSuppliedIdentityDigestOrDomainValues() {
        PaymentCommand c = command(input()); ResolvedPayment r = resolved(c);
        for (Object value : List.of(c, c.admittedCommandDigest(), r, r.domain())) {
            assertFalse(value.toString().contains("synthetic-actor"));
            assertFalse(value.toString().contains("supplied-digest-reference"));
            assertFalse(value.toString().contains("synthetic-customer"));
            assertFalse(value.toString().contains("synthetic-policy"));
        }
        var failure = assertThrows(IllegalArgumentException.class,
                () -> prepareRequested(new PaymentCommand(c.stage(), new DigestBinding("other", "other", new byte[] {1}), c.expectedReceipt())));
        assertEquals("INVALID_MOCK_PAYMENT_TRANSACTION", failure.getMessage()); assertNull(failure.getCause());
    }
}
