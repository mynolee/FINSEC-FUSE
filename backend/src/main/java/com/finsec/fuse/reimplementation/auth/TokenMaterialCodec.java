package com.finsec.fuse.reimplementation.auth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** Encodes caller-supplied material only.
 * No entropy generation, authority, storage, delivery, clock or provider injection.
 * Runtime JCA provider identity/support is not established by this source.
 */
public final class TokenMaterialCodec {
    private TokenMaterialCodec() { }

    /** Secret-bearing result. Redacted rendering does not make accessors safe to log. */
    public static final class Material {
        private final String bearer;
        private final byte[] fingerprint;

        private Material(String bearer, byte[] fingerprint) {
            this.bearer = bearer;
            this.fingerprint = fingerprint.clone();
        }
        public String bearer() { return bearer; }
        public byte[] fingerprint() { return fingerprint.clone(); }
        @Override public String toString() { return "TokenMaterial[REDACTED]"; }
    }

    /** Exact32 raw bytes become canonical unpadded URL-base64 plus SHA-256(raw).
     * Does not validate entropy or establish a valid issued token. No fallback.
     */
    public static Material encode(byte[] raw) {
        if (raw == null || raw.length != 32) {
            throw new IllegalArgumentException("INVALID_TOKEN_MATERIAL", null);
        }
        byte[] snapshot = raw.clone();
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(snapshot);
            if (digest == null || digest.length != 32) throw unavailable();
            return new Material(Base64.getUrlEncoder().withoutPadding().encodeToString(snapshot), digest);
        } catch (NoSuchAlgorithmException | RuntimeException rejected) {
            throw unavailable();
        }
    }

    private static IllegalStateException unavailable() {
        return new IllegalStateException("TOKEN_MATERIAL_UNAVAILABLE", null);
    }
}
