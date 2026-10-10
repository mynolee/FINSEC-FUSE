package com.finsec.fuse.quarantine;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.UUID;

public record QuarantineRequest(@NotNull Scope scope, UUID runId, UUID resultId,
    UUID workflowId, UUID documentId, @Min(1) Integer documentVersion,
    @Size(max=64) String agentId, @Min(1) Integer agentVersion,
    @NotNull Reason reasonCode, @Size(max=1000) String note) {
    public enum Scope { RUN, RESULT, WORKFLOW, SOURCE_VERSION, AGENT_VERSION }
    public enum Reason {
        EVIDENCE_MISSING, EVIDENCE_INVALID, SCOPE_EXCEEDED, CONTEXT_MISMATCH,
        SIGNATURE_INVALID, QUARANTINED, SECURITY_INVESTIGATION, SOURCE_COMPROMISED,
        AGENT_COMPROMISED, POLICY_VIOLATION
    }
}
