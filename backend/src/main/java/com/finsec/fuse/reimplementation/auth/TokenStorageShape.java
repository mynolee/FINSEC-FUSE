package com.finsec.fuse.reimplementation.auth;

import java.time.DateTimeException;
import java.time.Instant;
import java.util.UUID;

/**
 * V6 token-row shape checks only, independent of actor/role/scope validation.
 * Does not authenticate, establish issuance authority, inspect the current time,
 * determine token validity/expiry, select a fingerprint algorithm or touch a DB.
 * A non-null registry ID does not prove the referenced registry exists. These
 * Java values do not establish JDBC/SQL codec compatibility, PostgreSQL timestamp
 * range or stored precision, or the operational validity of any token.
 * No supplied value or fingerprint array is retained or included in diagnostics.
 */
public final class TokenStorageShape {
    public enum Status { ACTIVE, REVOKED }

    private TokenStorageShape() {}

    public static void validate(byte[] fingerprint, UUID registryId, String securityPolicy,
                                int issuanceTtlSeconds, Instant issuedAt, Instant expiresAt,
                                Status status, Instant revokedAt, long revision) {
        if (fingerprint == null || fingerprint.length != 32 || registryId == null
                || !"FUSE-SECURITY-1".equals(securityPolicy) || issuanceTtlSeconds != 7200
                || issuedAt == null || expiresAt == null || status == null || revision < 0) {
            throw invalid();
        }
        Instant expectedExpiry;
        try {
            expectedExpiry = issuedAt.plusSeconds(7200);
        } catch (DateTimeException | ArithmeticException unrepresentable) {
            throw invalid();
        }
        if (!expiresAt.isAfter(issuedAt) || !expiresAt.equals(expectedExpiry)
                || (status == Status.ACTIVE && revokedAt != null)
                || (status == Status.REVOKED && revokedAt == null)) {
            throw invalid();
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_TOKEN_STORAGE_SHAPE");
    }

    @Override public String toString() {
        return "TokenStorageShape[REDACTED]";
    }
}
