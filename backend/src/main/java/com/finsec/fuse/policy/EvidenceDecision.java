package com.finsec.fuse.policy;

import java.util.List;
import java.util.UUID;

public record EvidenceDecision(String decision, String state, String reasonCode,
                               String evidenceBundleHash, List<UUID> evidenceIds,
                               boolean securityViolation) {
    public EvidenceDecision { evidenceIds = List.copyOf(evidenceIds); }
    public boolean validated() { return "ALLOW".equals(decision) && "KYC_VALIDATED".equals(state); }
    public static EvidenceDecision blocked(String reason) {
        return new EvidenceDecision("DENY", "BLOCKED", reason, null, List.of(), true);
    }
    public static EvidenceDecision hold(String reason) {
        return new EvidenceDecision("ALLOW", "ON_HOLD", reason, null, List.of(), false);
    }
}
