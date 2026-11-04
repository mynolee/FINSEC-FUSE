package com.finsec.fuse.reimplementation.auth;

import java.util.UUID;

/**
 * Checks a subset of V1 delegation_grant row structure only. No input is retained.
 * A 32-byte MAC is a storage shape, not an algorithm or proof of authentication.
 * Does not establish referenced-row existence, uniqueness, authority, customer or
 * amount bindings, time validity, isolation, canonical bytes or cryptographic validity.
 */
public final class GrantStorageShape {
    public enum AllowedAction {
        EVALUATE_KYC, CREATE_LOAN_RECOMMENDATION, EXECUTE_MOCK_PAYMENT
    }

    private GrantStorageShape() {}

    public static void validate(int depth, UUID sourceRunId, UUID sourceResultId,
                                UUID parentGrantId, UUID approvalId, UUID targetRunId,
                                UUID actionId, AllowedAction allowedAction, byte[] macBytes) {
        if (depth < 1 || depth > 3 || targetRunId == null || actionId == null
                || allowedAction == null || macBytes == null || macBytes.length != 32) {
            throw invalid();
        }
        boolean sourceAbsent = sourceRunId == null && sourceResultId == null && parentGrantId == null;
        boolean sourcePresent = sourceRunId != null && sourceResultId != null && parentGrantId != null;
        boolean validDepthShape = switch (depth) {
            case 1 -> sourceAbsent && approvalId == null;
            case 2 -> sourcePresent && approvalId == null;
            case 3 -> sourcePresent && approvalId != null;
            default -> false;
        };
        if (!validDepthShape) throw invalid();
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_GRANT_STORAGE_SHAPE");
    }

    @Override public String toString() {
        return "GrantStorageShape[REDACTED]";
    }
}
