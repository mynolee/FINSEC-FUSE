package com.finsec.fuse.reimplementation.auth;

import java.util.UUID;

/** Pure registry binding; neither UUID possession nor construction establishes authority. */
public record RegistryTokenSelection(UUID registryId, TokenRevocationInput input) {
    public RegistryTokenSelection {
        if (registryId == null || input == null) {
            throw new IllegalArgumentException("INVALID_TOKEN_REVOCATION_INPUT");
        }
    }

    @Override public String toString() { return "RegistryTokenSelection[REDACTED]"; }
}
