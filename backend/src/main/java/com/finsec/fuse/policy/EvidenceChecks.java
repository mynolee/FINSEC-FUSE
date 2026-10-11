package com.finsec.fuse.policy;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import java.time.Instant;
import java.util.*;

/** Stateless evidence policy. The caller supplies the time read under the execution gate. */
public final class EvidenceChecks {
    private static final Set<String> KINDS = Set.of("ID_DOC", "FACE_MATCH");
    private static final Set<String> ORIGINAL_FIELDS = Set.of(
            "customerId", "evidenceType", "issuerId", "outcome", "issuedAt", "expiresAt");
    private final Map<String,Set<String>> trustedIssuers;
    private final Json json;

    public EvidenceChecks(Map<String,Set<String>> trustedIssuers, Json json) {
        this.trustedIssuers = FusePolicy.validatedTrustedIssuers(trustedIssuers);
        this.json = Objects.requireNonNull(json);
    }

    public EvidenceDecision evaluate(String status, Collection<UUID> proposed,
                                     Set<UUID> provided, Map<UUID, EvidenceRecord> registry,
                                     String customer, Instant dbNow) {
        Objects.requireNonNull(provided); Objects.requireNonNull(registry);
        Objects.requireNonNull(customer); Objects.requireNonNull(dbNow);
        if (proposed == null || proposed.size() > 10 || proposed.stream().anyMatch(Objects::isNull)) {
            return new EvidenceDecision("ERROR", "ON_HOLD", "MODEL_OUTPUT_INVALID", null, List.of(), false);
        }
        if ("NEEDS_REVIEW".equals(status)) return EvidenceDecision.hold("MANUAL_REVIEW_REQUIRED");
        if ("NOT_VERIFIED".equals(status)) {
            // A business rejection must come from an independently valid FAIL, not from AI text.
            boolean failed = provided.stream().map(registry::get).filter(Objects::nonNull)
                    .anyMatch(e -> authentic(e, customer, dbNow) && "FAIL".equals(e.outcome()));
            return failed ? new EvidenceDecision("ALLOW", "REJECTED", "IDENTITY_CHECK_FAILED", null, List.of(), false)
                    : EvidenceDecision.hold("EVIDENCE_MISSING");
        }
        if (!"VERIFIED".equals(status)) {
            return new EvidenceDecision("ERROR", "ON_HOLD", "MODEL_OUTPUT_INVALID", null, List.of(), false);
        }
        if (proposed.isEmpty()) return EvidenceDecision.blocked("EVIDENCE_MISSING");
        List<UUID> ids = proposed.stream().distinct().sorted(Comparator.comparing(UUID::toString)).toList();
        if (!provided.containsAll(ids)) return EvidenceDecision.blocked("EVIDENCE_INVALID");
        Set<String> found = new HashSet<>();
        List<Map<String, Object>> bundle = new ArrayList<>();
        for (UUID id : ids) {
            EvidenceRecord e = registry.get(id);
            if (e == null || !id.equals(e.id()) || !authentic(e, customer, dbNow) || !"PASS".equals(e.outcome())) {
                return EvidenceDecision.blocked("EVIDENCE_INVALID");
            }
            found.add(e.evidenceType());
            bundle.add(json.ordered("id", id.toString(), "version", e.version(), "originalHash", e.originalHash()));
        }
        if (!found.containsAll(KINDS)) return EvidenceDecision.blocked("EVIDENCE_MISSING");
        return new EvidenceDecision("ALLOW", "KYC_VALIDATED", "EVIDENCE_VALIDATED", json.hash(bundle), ids, false);
    }

    /** ACTIVE and time checks stay live; the immutable bundle hash never substitutes for them. */
    private boolean authentic(EvidenceRecord e, String customer, Instant now) {
        if (!customer.equals(e.customerId()) || !KINDS.contains(e.evidenceType())
                || !trustedIssuers.get(e.evidenceType()).contains(e.issuerId()) || e.version() < 1
                || !"ACTIVE".equals(e.status()) || e.revokedAt() != null
                || e.issuedAt() == null || e.expiresAt() == null
                || now.isBefore(e.issuedAt()) || !now.isBefore(e.expiresAt())
                || !e.issuedAt().isBefore(e.expiresAt())
                || !("PASS".equals(e.outcome()) || "FAIL".equals(e.outcome()))
                || e.originalHash() == null || !e.originalHash().matches("[0-9a-f]{64}")) return false;
        Map<String, Object> original = e.original();
        if (!original.keySet().equals(ORIGINAL_FIELDS)) return false;
        try {
            if (!Objects.equals(original.get("customerId"), e.customerId())
                    || !Objects.equals(original.get("evidenceType"), e.evidenceType())
                    || !Objects.equals(original.get("issuerId"), e.issuerId())
                    || !Objects.equals(original.get("outcome"), e.outcome())
                    || !e.issuedAt().equals(Instant.parse((String) original.get("issuedAt")))
                    || !e.expiresAt().equals(Instant.parse((String) original.get("expiresAt")))) return false;
            return e.originalHash().equals(json.hash(canonicalOriginal(e)));
        } catch (RuntimeException malformed) { return false; }
    }

    public Map<String, Object> canonicalOriginal(EvidenceRecord e) {
        return json.ordered("customerId", e.customerId(), "evidenceType", e.evidenceType(),
                "issuerId", e.issuerId(), "outcome", e.outcome(),
                "issuedAt", e.issuedAt().toString(), "expiresAt", e.expiresAt().toString());
    }
}
