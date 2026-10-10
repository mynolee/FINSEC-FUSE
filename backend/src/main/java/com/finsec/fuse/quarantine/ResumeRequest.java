package com.finsec.fuse.quarantine;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResumeRequest(@Min(1) int expectedGeneration,
    @NotBlank @Size(max=1000) String reason) {}
