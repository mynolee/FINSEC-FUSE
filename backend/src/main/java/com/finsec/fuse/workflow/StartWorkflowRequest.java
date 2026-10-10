package com.finsec.fuse.workflow;

import jakarta.validation.constraints.*;
import java.util.UUID;

public record StartWorkflowRequest(
        @NotBlank @Size(max=80) String businessReference,
        @NotBlank @Size(max=64) String customerId,
        @NotNull @Min(1) @Max(50_000_000) Long amountKrw,
        @NotNull UUID payoutAccountId) {}
