package com.finsec.fuse.quarantine;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.List;
import java.util.UUID;

public record ReleaseRequest(@NotNull @Valid Remediation remediation) {
    public record Remediation(@NotNull UUID safeDocumentId,
        @Min(1) int safeDocumentVersion,
        @NotNull @Size(max=100) List<@NotNull UUID> checkEvidenceIds,
        @Size(max=64) String safeAgentId, @Min(1) Integer safeAgentVersion,
        @NotBlank @Size(max=1000) String note) {}
}
