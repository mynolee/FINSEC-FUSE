package com.finsec.fuse.reimplementation.auth;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.RecordComponent;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import static com.finsec.fuse.reimplementation.auth.SyntheticMockPaymentReceiptCodec.*;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic canonical framing checks, without authoritative commit or identity evidence. */
final class SyntheticMockPaymentReceiptCodecTest {
    private static final byte[] PREFIX = "FUSE-MOCK-PAYMENT-COMMITTED-RECEIPT".getBytes(StandardCharsets.US_ASCII);
    private static UUID id(long n) { return new UUID(0x0102030405060708L, n); }
    private static Input input() {
        return new Input(id(1), "synthetic-actor", "synthetic-operation", "synthetic-command-v1",
                "synthetic-explicit-algorithm", new byte[] {0, 1, (byte) 255}, id(2), id(3), id(4), id(5),
                id(6), id(7), id(8), 1, "synthetic-customer", id(9), 1000L, id(10),
                "synthetic-policy", "EXECUTE_MOCK_PAYMENT", "COMMITTED", "CONSUMED");
    }
    @SuppressWarnings("unchecked")
    private static <T extends Record> T changed(T original, String field, Object replacement) throws Exception {
        RecordComponent[] components = original.getClass().getRecordComponents();
        var types = new Class<?>[components.length]; var values = new Object[components.length]; boolean found = false;
        for (int i = 0; i < components.length; i++) {
            types[i] = components[i].getType(); values[i] = components[i].getAccessor().invoke(original);
            if (components[i].getName().equals(field)) { values[i] = replacement; found = true; }
        }
        assertTrue(found);
        try { return (T) original.getClass().getConstructor(types).newInstance(values); }
        catch (InvocationTargetException wrapped) {
            if (wrapped.getCause() instanceof RuntimeException rejected) throw rejected;
            throw wrapped;
        }
    }
    private static void rejected(Executable operation) {
        var failure = assertThrows(IllegalArgumentException.class, operation);
        assertEquals("INVALID_MOCK_PAYMENT_RECEIPT", failure.getMessage()); assertNull(failure.getCause());
    }
    /** Test-only frame navigation; does not decode values or implement a receipt encoder. */
    private static ByteBuffer field(byte[] bytes, int ordinal, int expectedTag, int expectedWidth) {
        var b = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
        b.position(PREFIX.length + 1 + 4 + 2);
        for (int i = 1; i <= ordinal; i++) {
            assertEquals(i, Short.toUnsignedInt(b.getShort()));
            int tag = Byte.toUnsignedInt(b.get()); int length = b.getInt();
            assertTrue(length >= 0 && length <= b.remaining());
            if (i == ordinal) {
                assertEquals(expectedTag, tag);
                if (expectedWidth >= 0) assertEquals(expectedWidth, length);
                return b.slice().order(ByteOrder.BIG_ENDIAN).limit(length);
            }
            b.position(b.position() + length);
        }
        throw new AssertionError("synthetic ordinal");
    }

    @Test void normativePrefixNulVersionAndFieldCountAreExact() {
        byte[] raw = prepare(input()).canonicalBytes();
        assertArrayEquals(PREFIX, Arrays.copyOf(raw, PREFIX.length));
        var header = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN); header.position(PREFIX.length);
        assertEquals(0, header.get()); assertEquals(1, header.getInt()); assertEquals(22, Short.toUnsignedInt(header.getShort()));
        assertEquals("FUSE-MOCK-PAYMENT-COMMITTED-RECEIPT", PROFILE_NAME); assertEquals(1, PROFILE_VERSION);
    }

    @Test void nativeUuidIntegerAndLongWidthsPreserveBigEndianPatterns() throws Exception {
        var value = changed(input(), "amountKrw", 50000000L); value = changed(value, "generation", Integer.MAX_VALUE);
        byte[] raw = prepare(value).canonicalBytes();
        var uuid = field(raw, 1, 1, 16);
        assertEquals(0x0102030405060708L, uuid.getLong()); assertEquals(1L, uuid.getLong());
        var signedBits = prepare(changed(value, "payoutAccountId", new UUID(Long.MIN_VALUE, -1L))).canonicalBytes();
        var signedUuid = field(signedBits, 18, 1, 16);
        assertEquals(Long.MIN_VALUE, signedUuid.getLong()); assertEquals(-1L, signedUuid.getLong());
        assertEquals(Integer.MAX_VALUE, field(raw, 14, 4, 4).getInt());
        assertEquals(50000000L, field(raw, 17, 5, 8).getLong());
        var tail = field(raw, 22, 2, 8); byte[] text = new byte[tail.remaining()]; tail.get(text);
        assertArrayEquals("CONSUMED".getBytes(StandardCharsets.US_ASCII), text);
        assertEquals(raw.length, tail.arrayOffset() + tail.limit());
    }

    @Test void digestBytesRemainBinaryAndNotHexText() {
        var payload = field(prepare(input()).canonicalBytes(), 6, 3, 3); byte[] actual = new byte[3]; payload.get(actual);
        assertArrayEquals(new byte[] {0, 1, (byte) 255}, actual);
    }

    @Test void utf8MultibyteAndEmbeddedDelimitersArePreservedWithoutNormalization() throws Exception {
        String text = "가\0:x\né";
        var raw = prepare(changed(input(), "authenticatedActor", text)).canonicalBytes();
        byte[] expected = text.getBytes(StandardCharsets.UTF_8);
        var payload = field(raw, 2, 2, expected.length); byte[] actual = new byte[payload.remaining()]; payload.get(actual);
        assertArrayEquals(expected, actual);
        assertFalse(Arrays.equals(raw, prepare(changed(input(), "authenticatedActor", "가\0:x\ne\u0301")).canonicalBytes()));
    }

    @Test void onlyFixedAsciiWhitespaceOnlyStringsAreRejectedByFraming() throws Exception {
        for (String text : List.of("", " ", "\t\n\013\f\r ")) {
            rejected(() -> changed(input(), "authenticatedActor", text));
        }
        assertNotNull(prepare(changed(input(), "authenticatedActor", "\u00a0")));
        assertNotNull(prepare(changed(input(), "authenticatedActor", "\u2003")));
        assertNotNull(prepare(changed(input(), "authenticatedActor", " x ")));
    }

    @Test void unpairedSurrogatesRefuseButValidPairUsesFourUtf8Bytes() throws Exception {
        for (String invalid : List.of("\ud800", "\udc00", "x\ud800y")) {
            rejected(() -> changed(input(), "customerId", invalid));
        }
        var raw = prepare(changed(input(), "customerId", "\ud83d\ude00")).canonicalBytes();
        var payload = field(raw, 15, 2, 4); byte[] actual = new byte[4]; payload.get(actual);
        assertArrayEquals(new byte[] {(byte) 0xf0, (byte) 0x9f, (byte) 0x98, (byte) 0x80}, actual);
    }

    @Test void textLimitIs4096Utf8BytesNotUtf16Characters() throws Exception {
        assertNotNull(prepare(changed(input(), "operation", "x".repeat(4096))));
        rejected(() -> changed(input(), "operation", "x".repeat(4097)));
        String exact = "€".repeat(1365) + "x";
        assertEquals(4096, exact.getBytes(StandardCharsets.UTF_8).length);
        assertNotNull(prepare(changed(input(), "operation", exact)));
        rejected(() -> changed(input(), "operation", exact + "x"));
    }

    @Test void binaryDigestOneAnd128AreAcceptedWhileZeroAnd129Refuse() throws Exception {
        for (int length : List.of(1, 128)) {
            var raw = prepare(changed(input(), "canonicalBodyDigest", new byte[length])).canonicalBytes();
            assertEquals(length, field(raw, 6, 3, length).remaining());
        }
        rejected(() -> changed(input(), "canonicalBodyDigest", new byte[0]));
        rejected(() -> changed(input(), "canonicalBodyDigest", new byte[129]));
    }

    @Test void generationAndExistingAmountBoundsAreNotTruncatedOrWidened() throws Exception {
        assertNotNull(prepare(changed(input(), "generation", 1)));
        assertNotNull(prepare(changed(input(), "generation", Integer.MAX_VALUE)));
        rejected(() -> changed(input(), "generation", 0)); rejected(() -> changed(input(), "generation", -1));
        assertNotNull(prepare(changed(input(), "amountKrw", 1L)));
        assertNotNull(prepare(changed(input(), "amountKrw", 50000000L)));
        for (long value : new long[] {0, -1, 50000001, Long.MAX_VALUE}) rejected(() -> changed(input(), "amountKrw", value));
    }

    @Test void threeCommittedDomainLiteralsHaveNoCaseOrLifecycleAliases() {
        rejected(() -> changed(input(), "grantAction", "EVALUATE_KYC"));
        rejected(() -> changed(input(), "grantAction", "execute_mock_payment"));
        rejected(() -> changed(input(), "reservationStateAtCommit", "RESERVED"));
        rejected(() -> changed(input(), "approvalStateAtCommit", "VALIDATED"));
        rejected(() -> changed(input(), "approvalStateAtCommit", "CONSUMED "));
    }

    @Test void allReferenceComponentsAndInputAreRequiredWithoutDefaults() {
        for (String field : List.of("globalRequestId", "authenticatedActor", "operation", "canonicalizationVersion",
                "canonicalBodyDigestAlgorithm", "canonicalBodyDigest", "grantId", "actionId", "paymentId", "targetRunId",
                "approvalId", "reservationId", "workflowId", "customerId", "applicationId", "payoutAccountId",
                "securityPolicyVersion", "grantAction", "reservationStateAtCommit", "approvalStateAtCommit")) {
            rejected(() -> changed(input(), field, null));
        }
        rejected(() -> prepare(null));
    }

    @Test void zeroUuidAndEqualOrDifferentRequestActionValuesAreValidButBindDifferentBytes() throws Exception {
        var zero = changed(input(), "globalRequestId", new UUID(0, 0)); assertNotNull(prepare(zero));
        var different = input(); assertNotEquals(different.globalRequestId(), different.actionId());
        var equal = changed(different, "globalRequestId", different.actionId()); assertNotNull(prepare(equal));
        assertFalse(Arrays.equals(prepare(different).canonicalBytes(), prepare(equal).canonicalBytes()));
        var swapped = changed(different, "globalRequestId", different.actionId());
        swapped = changed(swapped, "actionId", different.globalRequestId());
        assertFalse(Arrays.equals(prepare(different).canonicalBytes(), prepare(swapped).canonicalBytes()));
    }

    @Test void eachVariableFieldBindsItsOwnValueWithoutAnAuthorityAssertion() throws Exception {
        String[] fields = {"globalRequestId", "authenticatedActor", "operation", "canonicalizationVersion",
                "canonicalBodyDigestAlgorithm", "canonicalBodyDigest", "grantId", "actionId", "paymentId", "targetRunId",
                "approvalId", "reservationId", "workflowId", "generation", "customerId", "applicationId", "amountKrw",
                "payoutAccountId", "securityPolicyVersion"};
        Object[] values = {id(99), "other-actor", "other-operation", "other-version", "other-algorithm", new byte[] {7},
                id(99), id(99), id(99), id(99), id(99), id(99), id(99), 2, "other-customer", id(99), 1001L, id(99), "other-policy"};
        byte[] original = prepare(input()).canonicalBytes();
        for (int i = 0; i < fields.length; i++) {
            var prepared = prepare(changed(input(), fields[i], values[i]));
            assertFalse(Arrays.equals(original, prepared.canonicalBytes()), fields[i]);
            assertFalse(prepared.authorizationEstablished()); assertFalse(prepared.commitEstablished());
        }
    }

    @Test void maximumAdmittedFieldSizesStayWithinTotalCapWithoutInventingOvercapInput() throws Exception {
        var value = input();
        for (String field : List.of("authenticatedActor", "operation", "canonicalizationVersion",
                "canonicalBodyDigestAlgorithm", "customerId", "securityPolicyVersion")) value = changed(value, field, "x".repeat(4096));
        value = changed(value, "canonicalBodyDigest", new byte[128]);
        var prepared = prepare(value);
        assertTrue(prepared.canonicalBytes().length <= 65536);
        assertFalse(prepared.authorizationEstablished()); assertFalse(prepared.commitEstablished());
    }

    @Test void callerAndReturnedArraysAreDetachedAndStringsDoNotLeakContents() throws Exception {
        byte[] supplied = {4, 5, 6}; var value = changed(input(), "canonicalBodyDigest", supplied);
        supplied[0] = 99; assertArrayEquals(new byte[] {4, 5, 6}, value.canonicalBodyDigest());
        var exposedInput = value.canonicalBodyDigest(); exposedInput[0] = 99;
        assertArrayEquals(new byte[] {4, 5, 6}, value.canonicalBodyDigest());
        var prepared = prepare(value); byte[] before = prepared.canonicalBytes(), digest = prepared.receiptDigest();
        assertEquals(32, digest.length); var exposed = prepared.canonicalBytes(); exposed[0] ^= 1;
        var exposedDigest = prepared.receiptDigest(); exposedDigest[0] ^= 1;
        assertArrayEquals(before, prepared.canonicalBytes()); assertArrayEquals(digest, prepared.receiptDigest());
        assertEquals(PROFILE_NAME, prepared.profileName()); assertEquals(PROFILE_VERSION, prepared.profileVersion());
        assertFalse(value.toString().contains("synthetic-actor")); assertFalse(prepared.toString().contains("synthetic-customer"));
        assertFalse(prepared.authorizationEstablished()); assertFalse(prepared.commitEstablished());
    }
}
