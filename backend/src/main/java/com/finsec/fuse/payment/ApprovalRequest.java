package com.finsec.fuse.payment;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ApprovalRequest(@NotNull Decision decision,
    @NotNull @Pattern(regexp = "[0-9a-f]{64}") String reviewSnapshotHash,
    @Size(max = 1000) String comment) {
    public enum Decision { APPROVE, REJECT }
}
