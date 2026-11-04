package com.finsec.fuse.reimplementation.auth;

import java.io.ByteArrayOutputStream;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * Prepares deterministic internal MOCK_PAYMENT receipt content only.
 * No payment, transaction, authentication, signature, storage or command-digest
 * verification is performed. Domain admission and trusted commit evidence are
 * separate requirements; these bytes and their unkeyed digest establish neither.
 */
public final class SyntheticMockPaymentReceiptCodec {
    public static final String PROFILE_NAME = "FUSE-MOCK-PAYMENT-COMMITTED-RECEIPT";
    public static final int PROFILE_VERSION = 1;
    private static final int FIELD_COUNT = 22;
    private static final int MAX_CANONICAL_BYTES = 65536;

    private SyntheticMockPaymentReceiptCodec() { }

    /** Exact structural inputs; stricter domain and command validators remain external. */
    public record Input(UUID globalRequestId, String authenticatedActor, String operation,
                        String canonicalizationVersion, String canonicalBodyDigestAlgorithm,
                        byte[] canonicalBodyDigest, UUID grantId, UUID actionId, UUID paymentId,
                        UUID targetRunId, UUID approvalId, UUID reservationId, UUID workflowId,
                        int generation, String customerId, UUID applicationId, long amountKrw,
                        UUID payoutAccountId, String securityPolicyVersion, String grantAction,
                        String reservationStateAtCommit, String approvalStateAtCommit) {
        public Input {
            requireUuid(globalRequestId); requireUuid(grantId); requireUuid(actionId);
            requireUuid(paymentId); requireUuid(targetRunId); requireUuid(approvalId);
            requireUuid(reservationId); requireUuid(workflowId); requireUuid(applicationId);
            requireUuid(payoutAccountId);
            text(authenticatedActor); text(operation); text(canonicalizationVersion);
            text(canonicalBodyDigestAlgorithm); text(customerId); text(securityPolicyVersion);
            text(grantAction); text(reservationStateAtCommit); text(approvalStateAtCommit);
            if (canonicalBodyDigest == null || canonicalBodyDigest.length < 1
                    || canonicalBodyDigest.length > 128 || generation < 1
                    || amountKrw < 1 || amountKrw > 50000000L
                    || !"EXECUTE_MOCK_PAYMENT".equals(grantAction)
                    || !"COMMITTED".equals(reservationStateAtCommit)
                    || !"CONSUMED".equals(approvalStateAtCommit)) {
                throw invalid();
            }
            canonicalBodyDigest = canonicalBodyDigest.clone();
        }

        @Override public byte[] canonicalBodyDigest() { return canonicalBodyDigest.clone(); }
        @Override public String toString() { return "MockPaymentReceiptInput[REDACTED]"; }
    }

    /** Internal content, not a confirmed receipt or a safe public HTTP projection. */
    public static final class Prepared {
        private final byte[] canonicalBytes;
        private final byte[] receiptDigest;

        private Prepared(byte[] canonicalBytes, byte[] receiptDigest) {
            this.canonicalBytes = canonicalBytes.clone();
            this.receiptDigest = receiptDigest.clone();
        }
        public byte[] canonicalBytes() { return canonicalBytes.clone(); }
        public byte[] receiptDigest() { return receiptDigest.clone(); }
        public String profileName() { return PROFILE_NAME; }
        public int profileVersion() { return PROFILE_VERSION; }
        public boolean authorizationEstablished() { return false; }
        public boolean commitEstablished() { return false; }
        @Override public String toString() { return "MockPaymentReceiptPrepared[REDACTED]"; }
    }

    /** SHA-256 is looked up by name once, without fallback or command-hash inference. */
    public static Prepared prepare(Input input) {
        if (input == null) throw invalid();
        var out = new ByteArrayOutputStream();
        append(out, PROFILE_NAME.getBytes(StandardCharsets.US_ASCII));
        out.write(0);
        unsigned(out, PROFILE_VERSION, 4);
        unsigned(out, FIELD_COUNT, 2);
        field(out, 1, 1, uuid(input.globalRequestId()));
        field(out, 2, 2, text(input.authenticatedActor()));
        field(out, 3, 2, text(input.operation()));
        field(out, 4, 2, text(input.canonicalizationVersion()));
        field(out, 5, 2, text(input.canonicalBodyDigestAlgorithm()));
        field(out, 6, 3, input.canonicalBodyDigest());
        field(out, 7, 1, uuid(input.grantId()));
        field(out, 8, 1, uuid(input.actionId()));
        field(out, 9, 1, uuid(input.paymentId()));
        field(out, 10, 1, uuid(input.targetRunId()));
        field(out, 11, 1, uuid(input.approvalId()));
        field(out, 12, 1, uuid(input.reservationId()));
        field(out, 13, 1, uuid(input.workflowId()));
        field(out, 14, 4, integer(input.generation(), 4));
        field(out, 15, 2, text(input.customerId()));
        field(out, 16, 1, uuid(input.applicationId()));
        field(out, 17, 5, integer(input.amountKrw(), 8));
        field(out, 18, 1, uuid(input.payoutAccountId()));
        field(out, 19, 2, text(input.securityPolicyVersion()));
        field(out, 20, 2, text(input.grantAction()));
        field(out, 21, 2, text(input.reservationStateAtCommit()));
        field(out, 22, 2, text(input.approvalStateAtCommit()));
        byte[] canonical = out.toByteArray();
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical);
            if (digest == null || digest.length != 32) throw unavailable();
            return new Prepared(canonical, digest);
        } catch (NoSuchAlgorithmException | RuntimeException failure) {
            throw unavailable();
        }
    }

    private static byte[] text(String value) {
        if (value == null || value.length() < 1 || value.length() > 4096) throw invalid();
        try {
            var encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value));
            if (encoded.remaining() < 1 || encoded.remaining() > 4096) throw invalid();
            byte[] bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
            boolean nonWhitespace = false;
            for (byte b : bytes) {
                int v = b & 0xff;
                if (v != 0x09 && v != 0x0a && v != 0x0b && v != 0x0c && v != 0x0d && v != 0x20) {
                    nonWhitespace = true;
                }
            }
            if (!nonWhitespace) throw invalid();
            return bytes;
        } catch (CharacterCodingException failure) {
            throw invalid();
        }
    }

    private static void requireUuid(UUID value) {
        if (value == null) throw invalid();
    }

    private static byte[] uuid(UUID value) {
        var out = new ByteArrayOutputStream(16);
        unsigned(out, value.getMostSignificantBits(), 8);
        unsigned(out, value.getLeastSignificantBits(), 8);
        return out.toByteArray();
    }

    private static byte[] integer(long value, int width) {
        var out = new ByteArrayOutputStream(width);
        unsigned(out, value, width);
        return out.toByteArray();
    }

    private static void field(ByteArrayOutputStream out, int ordinal, int tag, byte[] payload) {
        if (payload.length > MAX_CANONICAL_BYTES - out.size() - 7) throw invalid();
        unsigned(out, ordinal, 2);
        out.write(tag);
        unsigned(out, payload.length, 4);
        append(out, payload);
    }

    private static void unsigned(ByteArrayOutputStream out, long value, int width) {
        if (width > MAX_CANONICAL_BYTES - out.size()) throw invalid();
        for (int shift = (width - 1) * 8; shift >= 0; shift -= 8) {
            out.write((int) (value >>> shift) & 0xff);
        }
    }

    private static void append(ByteArrayOutputStream out, byte[] bytes) {
        if (bytes.length > MAX_CANONICAL_BYTES - out.size()) throw invalid();
        out.writeBytes(bytes);
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_MOCK_PAYMENT_RECEIPT", null);
    }
    private static IllegalStateException unavailable() {
        return new IllegalStateException("MOCK_PAYMENT_RECEIPT_UNAVAILABLE", null);
    }
}
