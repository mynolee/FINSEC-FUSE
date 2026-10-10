package com.finsec.fuse.common;

/** Request validation failures only. Do not throw after persisting a policy denial. */
public class ApiException extends RuntimeException {
    private final int status;
    private final String reasonCode;
    public ApiException(int status, String reasonCode, String message) {
        super(message); this.status = status; this.reasonCode = reasonCode;
    }
    public int status() { return status; }
    public String reasonCode() { return reasonCode; }
    public int getStatus() { return status; }
    public String getReasonCode() { return reasonCode; }
}
