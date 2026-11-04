package com.finsec.fuse.reimplementation.auth;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Optional synthetic equality only. No issuer, key registry, authority or consumption. */
public final class SyntheticGrantV2DetachedMac {
    private SyntheticGrantV2DetachedMac() {}

    public record Profile(int keyMinBytes, int keyMaxBytes, int frameMaxBytes) {
        public Profile {
            if (keyMinBytes < 32 || keyMaxBytes < keyMinBytes || keyMaxBytes > 1024
                    || frameMaxBytes < 1 || frameMaxBytes > 24598) throw invalid();
        }
    }

    /** Caller supplies synthetic bytes; true is not permission or real grant validity. */
    public static boolean matches(Profile profile, SyntheticGrantV2Codec.Prepared prepared,
                                  byte[] callerKey, byte[] detachedTag) {
        if (profile == null || prepared == null || callerKey == null || detachedTag == null
                || callerKey.length < profile.keyMinBytes()
                || callerKey.length > profile.keyMaxBytes() || detachedTag.length != 32) {
            throw invalid();
        }
        byte[] key = null, tag = null, frame = null;
        try {
            key = callerKey.clone();
            tag = detachedTag.clone();
            // Prepared has no length-only accessor. Its codec already caps this clone at24598.
            frame = prepared.unsignedFrame();
            if (frame.length > profile.frameMaxBytes()) throw invalid();
            return compareMac(() -> Mac.getInstance("HmacSHA256"), key, frame, tag);
        } finally {
            // Best effort local arrays only, including exceptional unwinding where finally runs.
            // No guarantee for fatal VM termination, provider internals or SecretKeySpec copies.
            wipe(key); wipe(tag); wipe(frame);
        }
    }

    // Package-private test seam, not a selectable public provider/algorithm API.
    @FunctionalInterface interface MacFactory {
        Mac create() throws GeneralSecurityException;
    }
    static boolean compareMac(MacFactory factory, byte[] key, byte[] frame, byte[] tag) {
        byte[] calculated = null;
        try {
            Mac mac = factory.create();
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            calculated = mac.doFinal(frame);
            if (calculated == null || calculated.length != 32) throw unavailable();
            return MessageDigest.isEqual(calculated, tag);
        } catch (GeneralSecurityException | RuntimeException failure) {
            throw unavailable();
        } finally {
            wipe(calculated);
        }
    }

    private static void wipe(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_SYNTHETIC_DETACHED_MAC_INPUT");
    }

    private static IllegalStateException unavailable() {
        return new IllegalStateException("SYNTHETIC_DETACHED_MAC_UNAVAILABLE");
    }
}
