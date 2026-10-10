package com.finsec.fuse.policy;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/** Only constructed from the independent trusted-evidence registry, never model output. */
public record EvidenceRecord(UUID id, String customerId, String evidenceType, String issuerId,
                             int version, String outcome, String status, Instant issuedAt,
                             Instant expiresAt, Instant revokedAt, Map<String, Object> original,
                             String originalHash) {
    public EvidenceRecord { original = original == null ? Map.of() : java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(original)); }
}
