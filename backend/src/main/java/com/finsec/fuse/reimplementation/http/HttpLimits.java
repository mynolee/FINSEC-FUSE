package com.finsec.fuse.reimplementation.http;

/** Explicit application-layer bounds. No configuration source or defaults are selected. */
public record HttpLimits(long maxHeaderBytes, int maxBodyBytes, int maxJsonDepth) {
    public HttpLimits {
        if (maxHeaderBytes <= 0 || maxBodyBytes <= 0 || maxJsonDepth <= 0) {
            throw new IllegalArgumentException("Explicit positive HTTP limits are required");
        }
    }
}
