package com.finsec.fuse.config;

/** Versioned admission limits. Changes require a new reviewed policy version. */
public record SecurityPolicy(
    String policyVersion,
    int publicRequestMaxBytes,
    int internalRequestMaxBytes,
    int internalResponseMaxBytes,
    int httpHeaderMaxBytes,
    int jsonMaxDepth,
    int evidenceFactsMaxItems,
    int documentsMaxItems,
    int documentTextMaxUtf8Bytes,
    int grantTransportMaxBytes,
    int grantClaimsMaxDecodedBytes,
    int actionPayloadMaxDecodedBytes,
    int devTokenTtlSeconds,
    int authenticatedReadsPerMinute,
    int authenticatedChangesPerMinute,
    int anonymousAttemptsPerIpPerMinute,
    int modelConcurrency,
    int queuedJobsMax,
    int dbLockTimeoutMilliseconds,
    int dbStatementTimeoutMilliseconds) {
    public SecurityPolicy {
        if (!"FUSE-SECURITY-1".equals(policyVersion) || publicRequestMaxBytes != 65536 ||
            internalRequestMaxBytes != 262144 ||
            internalResponseMaxBytes != 65536 ||
            httpHeaderMaxBytes != 16384 ||
            jsonMaxDepth != 16 ||
            evidenceFactsMaxItems != 10 ||
            documentsMaxItems != 8 ||
            documentTextMaxUtf8Bytes != 16384 ||
            grantTransportMaxBytes != 65536 ||
            grantClaimsMaxDecodedBytes != 16384 ||
            actionPayloadMaxDecodedBytes != 16384 ||
            devTokenTtlSeconds != 7200 ||
            authenticatedReadsPerMinute != 120 ||
            authenticatedChangesPerMinute != 20 ||
            anonymousAttemptsPerIpPerMinute != 30 ||
            modelConcurrency != 4 ||
            queuedJobsMax != 1000 ||
            dbLockTimeoutMilliseconds != 2000 ||
            dbStatementTimeoutMilliseconds != 5000)
            throw new IllegalArgumentException("Invalid security policy");
    }
}
