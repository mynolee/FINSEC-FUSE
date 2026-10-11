package com.finsec.fuse.policy;

public record GrantTransport(Grant grant, String actionPayloadBase64Url) {
    public record Grant(String format, String kid, String payloadBase64Url, String macBase64Url) {}
}
