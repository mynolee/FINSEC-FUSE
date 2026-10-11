package com.finsec.fuse.config;

import java.util.Set;
import java.util.Map;
import java.util.List;

/** All policy numbers and reviewed registries originate in one versioned JSON file. */
public record FusePolicy(
    String policyVersion, int automaticRiskLimit, int kycRisk, int loanRisk, int paymentRisk,
    int approvalExtraRisk, int maxRunsPerStage, int grantTtlSeconds, int approvalTtlSeconds,
    int leaseSeconds, int workerPollMs, int reaperPollMs, int kycTimeoutSeconds,
    int maxKycConcurrency, long maxAmountKrw, Map<String,Set<String>> trustedIssuers,
    Set<String> safeSources, Set<String> safeAgentVersions, Map<String,List<String>> allowedEdges) {
    public FusePolicy {
        trustedIssuers=validatedTrustedIssuers(trustedIssuers); safeSources=Set.copyOf(safeSources);
        safeAgentVersions=Set.copyOf(safeAgentVersions);
        allowedEdges=allowedEdges.entrySet().stream().collect(java.util.stream.Collectors.toUnmodifiableMap(Map.Entry::getKey,e->List.copyOf(e.getValue())));
        if (policyVersion==null || policyVersion.isBlank() || automaticRiskLimit<=0 || kycRisk<=0 || loanRisk<=0 ||
            paymentRisk<=0 || approvalExtraRisk<0 || maxRunsPerStage<=0 || grantTtlSeconds<=0 ||
            approvalTtlSeconds<=0 || leaseSeconds<=grantTtlSeconds || workerPollMs<=0 || reaperPollMs<=0 ||
            kycTimeoutSeconds<=0 || leaseSeconds<=kycTimeoutSeconds || maxKycConcurrency<=0 || maxAmountKrw<=0 ||
            trustedIssuers.isEmpty() || safeSources.isEmpty() || safeAgentVersions.isEmpty()) {
            throw new IllegalArgumentException("Invalid FUSE policy configuration");
        }
    }
    /** Issuer authority is specific to an evidence kind; a global issuer allowlist is unsafe. */
    public static Map<String,Set<String>> validatedTrustedIssuers(Map<String,Set<String>> issuers) {
        if (issuers==null || !issuers.keySet().equals(Set.of("ID_DOC","FACE_MATCH"))
                || issuers.values().stream().anyMatch(values -> values==null || values.isEmpty()
                    || values.stream().anyMatch(value -> value==null || value.isBlank()))) {
            throw new IllegalArgumentException("Invalid typed evidence issuer configuration");
        }
        return issuers.entrySet().stream().collect(java.util.stream.Collectors.toUnmodifiableMap(
                Map.Entry::getKey,entry -> Set.copyOf(entry.getValue())));
    }
    public int approvedRiskLimit() { return automaticRiskLimit+approvalExtraRisk; }
}
