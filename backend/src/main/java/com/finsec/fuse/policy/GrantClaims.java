package com.finsec.fuse.policy;

import com.finsec.fuse.common.Json;
import java.util.*;

/** FUSE-GRANT-v1 claims in the exact contract serialization order. */
public record GrantClaims(UUID grantId, UUID workflowId, int generation, UUID rootAuthorizationId,
        String principal, String originIntent, String issuer, String sourceAgent, String targetAgent,
        UUID sourceRunId, UUID targetRunId, String allowedAction, String customerId, long amountKrw,
        UUID payoutAccountId, UUID sourceResultId, String evidenceBundleHash, UUID parentGrantId,
        int depth, UUID actionId, String payloadHash, String policyVersion, UUID riskLedgerId,
        UUID approvalId, long expiresAtEpochMs) {
    public Map<String,Object> canonical(Json json) {
        return json.ordered("grantId", grantId, "workflowId", workflowId, "generation", generation,
                "rootAuthorizationId", rootAuthorizationId, "principal", principal,
                "originIntent", originIntent, "issuer", issuer, "sourceAgent", sourceAgent,
                "targetAgent", targetAgent, "sourceRunId", sourceRunId, "targetRunId", targetRunId,
                "allowedAction", allowedAction, "customerId", customerId, "amountKrw", amountKrw,
                "payoutAccountId", payoutAccountId, "sourceResultId", sourceResultId,
                "evidenceBundleHash", evidenceBundleHash, "parentGrantId", parentGrantId, "depth", depth,
                "actionId", actionId, "payloadHash", payloadHash, "policyVersion", policyVersion,
                "riskLedgerId", riskLedgerId, "approvalId", approvalId, "expiresAtEpochMs", expiresAtEpochMs);
    }
    public void checkShape() {
        if (grantId == null || workflowId == null || rootAuthorizationId == null || targetRunId == null
                || payoutAccountId == null || actionId == null || riskLedgerId == null || generation < 1
                || depth < 1 || depth > 3 || amountKrw < 1 || amountKrw > 50_000_000L || expiresAtEpochMs <= 0
                || !text(principal,64) || !text(customerId,64) || !text(originIntent,100)
                || !text(issuer,64) || !text(sourceAgent,64) || !text(targetAgent,64)
                || !text(allowedAction,64) || !text(policyVersion,64)
                || payloadHash == null || !payloadHash.matches("[0-9a-f]{64}")
                || (evidenceBundleHash != null && !evidenceBundleHash.matches("[0-9a-f]{64}"))) {
            throw new PolicyException("CONTEXT_MISMATCH");
        }
    }
    private static boolean text(String value, int max) {
        return value != null && !value.isBlank() && value.length() <= max;
    }
}
