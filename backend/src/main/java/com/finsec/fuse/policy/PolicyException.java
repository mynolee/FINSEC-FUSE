package com.finsec.fuse.policy;

/** A policy refusal, never an instruction to mutate an unrelated workflow. */
public final class PolicyException extends RuntimeException {
    private final String reasonCode;
    public PolicyException(String reasonCode) { super(reasonCode); this.reasonCode = reasonCode; }
    public PolicyException(String reasonCode, Throwable cause) { super(reasonCode, cause); this.reasonCode = reasonCode; }
    public String reasonCode() { return reasonCode; }
}
