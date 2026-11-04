package com.finsec.fuse.reimplementation.auth;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TokenStorageShapeTest {
    private static final UUID REGISTRY = UUID.fromString("00000000-0000-4000-8000-000000000401");
    private static final Instant ISSUED = Instant.parse("2020-01-01T00:00:00Z");
    private static final Instant EXPIRES = ISSUED.plusSeconds(7200);

    @Test void validatesStructureWithoutTimeValidityOrFingerprintAlgorithmClaims() {
        TokenStorageShape.validate(new byte[32], REGISTRY, "FUSE-SECURITY-1", 7200,
                ISSUED, EXPIRES, TokenStorageShape.Status.ACTIVE, null, 0);
        // Schema imposes no ordering constraint on revoked_at, and no now() check.
        TokenStorageShape.validate(new byte[32], REGISTRY, "FUSE-SECURITY-1", 7200,
                ISSUED, EXPIRES, TokenStorageShape.Status.REVOKED, ISSUED.minusSeconds(1), Long.MAX_VALUE);
    }

    @Test void requiresExactly32FingerprintBytesButDoesNotInspectTheirMeaning() {
        for (byte[] fingerprint : new byte[][]{null, new byte[0], new byte[31], new byte[33]}) {
            assertInvalid(() -> validate(fingerprint, REGISTRY, "FUSE-SECURITY-1", 7200,
                    ISSUED, EXPIRES, TokenStorageShape.Status.ACTIVE, null, 0));
        }
        var arbitrary = new byte[32];
        java.util.Arrays.fill(arbitrary, (byte) 0xFF);
        validate(arbitrary, REGISTRY, "FUSE-SECURITY-1", 7200, ISSUED, EXPIRES,
                TokenStorageShape.Status.ACTIVE, null, 0);
    }

    @Test void rejectsMissingRegistryWrongPolicyAndWrongDeclaredTtl() {
        assertInvalid(() -> validate(new byte[32], null, "FUSE-SECURITY-1", 7200, ISSUED, EXPIRES, TokenStorageShape.Status.ACTIVE, null, 0));
        for (String policy : new String[]{null, "", "fuse-security-1", "FUSE-SECURITY-2"}) {
            assertInvalid(() -> validate(new byte[32], REGISTRY, policy, 7200, ISSUED, EXPIRES, TokenStorageShape.Status.ACTIVE, null, 0));
        }
        for (int ttl : new int[]{0, 7199, 7201}) {
            assertInvalid(() -> validate(new byte[32], REGISTRY, "FUSE-SECURITY-1", ttl, ISSUED, EXPIRES, TokenStorageShape.Status.ACTIVE, null, 0));
        }
    }

    @Test void requiresNonNullExactStrictlyLaterExpiryAndHandlesArithmeticBounds() {
        for (Instant expiry : new Instant[]{null, ISSUED.minusSeconds(1), ISSUED, EXPIRES.minusNanos(1), EXPIRES.plusSeconds(1)}) {
            assertInvalid(() -> validate(new byte[32], REGISTRY, "FUSE-SECURITY-1", 7200, ISSUED, expiry, TokenStorageShape.Status.ACTIVE, null, 0));
        }
        assertInvalid(() -> validate(new byte[32], REGISTRY, "FUSE-SECURITY-1", 7200, null, EXPIRES, TokenStorageShape.Status.ACTIVE, null, 0));
        assertInvalid(() -> validate(new byte[32], REGISTRY, "FUSE-SECURITY-1", 7200, Instant.MAX, Instant.MAX, TokenStorageShape.Status.ACTIVE, null, 0));
    }

    @Test void requiresStatusRevocationShapeAndNonnegativeRevisionOnly() {
        assertInvalid(() -> validate(new byte[32], REGISTRY, "FUSE-SECURITY-1", 7200, ISSUED, EXPIRES, null, null, 0));
        assertInvalid(() -> validate(new byte[32], REGISTRY, "FUSE-SECURITY-1", 7200, ISSUED, EXPIRES, TokenStorageShape.Status.ACTIVE, ISSUED, 0));
        assertInvalid(() -> validate(new byte[32], REGISTRY, "FUSE-SECURITY-1", 7200, ISSUED, EXPIRES, TokenStorageShape.Status.REVOKED, null, 0));
        assertInvalid(() -> validate(new byte[32], REGISTRY, "FUSE-SECURITY-1", 7200, ISSUED, EXPIRES, TokenStorageShape.Status.ACTIVE, null, -1));
    }

    @Test void javaTimeShapeDoesNotSilentlyClaimPostgresRangeOrMicrosecondRoundTrip() {
        for (Instant issued : new Instant[]{ISSUED.plusNanos(1), ISSUED.plusNanos(1000),
                Instant.parse("+500000-01-01T00:00:00Z")}) {
            assertDoesNotThrow(() -> validate(new byte[32], REGISTRY, "FUSE-SECURITY-1", 7200,
                    issued, issued.plusSeconds(7200), TokenStorageShape.Status.ACTIVE, null, 0));
        }
    }

    private static void validate(byte[] fingerprint, UUID registry, String policy, int ttl,
                                 Instant issued, Instant expires, TokenStorageShape.Status status,
                                 Instant revoked, long revision) {
        TokenStorageShape.validate(fingerprint, registry, policy, ttl, issued, expires, status, revoked, revision);
    }

    private static void assertInvalid(Runnable work) {
        var error = assertThrows(IllegalArgumentException.class, work::run);
        assertEquals("INVALID_TOKEN_STORAGE_SHAPE", error.getMessage());
        assertNull(error.getCause());
    }
}
