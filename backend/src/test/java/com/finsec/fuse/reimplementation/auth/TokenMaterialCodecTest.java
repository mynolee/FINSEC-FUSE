package com.finsec.fuse.reimplementation.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic codec contract tests; no randomness, storage, FD or issuance. */
final class TokenMaterialCodecTest {
    // Fixed expected digest for 32 zero bytes; synthetic, not a credential.
    private static final byte[] ZERO_DIGEST = HexFormat.of().parseHex(
            "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925");

    @Test void exactRawBytesHaveCanonical43CharacterUnpaddedUrlEncoding() {
        byte[] raw = new byte[32];
        for (int index = 0; index < raw.length; index++) raw[index] = (byte) (index * 17);
        var material = TokenMaterialCodec.encode(raw);
        assertEquals(43, material.bearer().length());
        assertTrue(material.bearer().matches("[A-Za-z0-9_-]{43}"));
        assertFalse(material.bearer().contains("="));
        assertArrayEquals(raw, Base64.getUrlDecoder().decode(material.bearer()));
        assertEquals(material.bearer(), Base64.getUrlEncoder().withoutPadding().encodeToString(raw));
    }

    @Test void fingerprintHashesRaw32NotEncodedBearerText() throws Exception {
        var material = TokenMaterialCodec.encode(new byte[32]);
        assertEquals("A".repeat(43), material.bearer());
        assertArrayEquals(ZERO_DIGEST, material.fingerprint());
        byte[] textDigest = MessageDigest.getInstance("SHA-256").digest(
                material.bearer().getBytes(StandardCharsets.US_ASCII));
        assertFalse(Arrays.equals(textDigest, material.fingerprint()));
    }

    @Test void inputRemainsUnchangedAndLaterMutationCannotChangeMaterial() {
        byte[] raw = new byte[32];
        byte[] before = raw.clone();
        var material = TokenMaterialCodec.encode(raw);
        assertArrayEquals(before, raw);
        raw[0] = 99;
        assertEquals("A".repeat(43), material.bearer());
        assertArrayEquals(ZERO_DIGEST, material.fingerprint());
    }

    @Test void fingerprintAccessorsNeverExposeRetainedMutableArray() {
        var material = TokenMaterialCodec.encode(new byte[32]);
        byte[] first = material.fingerprint();
        byte[] second = material.fingerprint();
        assertNotSame(first, second);
        first[0] ^= 1;
        assertArrayEquals(ZERO_DIGEST, second);
        assertArrayEquals(ZERO_DIGEST, material.fingerprint());
    }

    @Test void nullAndWrongLengthsHaveFixedNonSensitiveErrors() {
        for (byte[] value : new byte[][] {null, new byte[0], new byte[31], new byte[33], new byte[64]}) {
            var error = assertThrows(IllegalArgumentException.class, () -> TokenMaterialCodec.encode(value));
            assertEquals("INVALID_TOKEN_MATERIAL", error.getMessage());
            assertNull(error.getCause());
            assertEquals(0, error.getSuppressed().length);
        }
    }

    @Test void renderingIsRedactedButExplicitAccessorsStillReturnMaterial() {
        var material = TokenMaterialCodec.encode(new byte[32]);
        assertEquals("TokenMaterial[REDACTED]", material.toString());
        assertFalse(material.toString().contains(material.bearer()));
        assertEquals(32, material.fingerprint().length);
        assertEquals("A".repeat(43), material.bearer());
    }
}
