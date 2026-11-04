package com.finsec.fuse.reimplementation.auth;

import java.util.UUID;

/** Pure proposed selector/revision shape; no token lookup, validity or authority proof. */
public record TokenRevocationInput(UUID selectionId, long expectedRevision) {
    public TokenRevocationInput {
        if (selectionId == null || expectedRevision < 0) {
            throw new IllegalArgumentException("INVALID_TOKEN_REVOCATION_INPUT");
        }
    }

    @Override public String toString() { return "TokenRevocationInput[REDACTED]"; }
}
