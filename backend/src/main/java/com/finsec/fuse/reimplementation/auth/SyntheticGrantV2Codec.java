package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Optional synthetic byte preparation only; not a grant issuer, verifier or authority. */
public final class SyntheticGrantV2Codec {
    private SyntheticGrantV2Codec() {}

    /** Explicit caller limits may narrow the proposed maxima; there is no default profile. */
    public record Profile(int claimsMaxUtf8Bytes, int actionMaxUtf8Bytes, int jsonDepthMax,
                          int fieldsPerObjectMax, int stringMaxUtf16CodeUnits, long ttlSecondsMax) {
        public Profile {
            if (claimsMaxUtf8Bytes < 1 || claimsMaxUtf8Bytes > 16384
                    || actionMaxUtf8Bytes < 1 || actionMaxUtf8Bytes > 8192
                    || jsonDepthMax < 1 || jsonDepthMax > 8
                    || fieldsPerObjectMax < 1 || fieldsPerObjectMax > 64
                    || stringMaxUtf16CodeUnits < 1 || stringMaxUtf16CodeUnits > 1000
                    || ttlSecondsMax < 1 || ttlSecondsMax > 300) throw invalid();
        }
    }

    public record Claims(String format, String algorithm, String kid, UUID grantId,
                         UUID workflowId, int generation, UUID rootAuthorizationId,
                         String principalId, String originIntent, String issuer,
                         String sourceAgent, String targetAgent, UUID sourceRunId,
                         UUID targetRunId, GrantStorageShape.AllowedAction allowedAction,
                         String customerId, long amountKrw, UUID payoutAccountId,
                         UUID sourceResultId, String evidenceBundleHash, UUID parentGrantId,
                         int depth, UUID actionId, String payloadHash, String policyVersion,
                         UUID riskLedgerId, UUID approvalId, long issuedAt, long expiresAt) {
        @Override public String toString() { return "SyntheticGrantV2Codec.Claims[REDACTED]"; }
    }

    public record Action(UUID actionId, UUID workflowId, int generation,
                         GrantStorageShape.AllowedAction allowedAction, String customerId,
                         long amountKrw, UUID payoutAccountId, UUID targetRunId,
                         UUID sourceResultId, String evidenceBundleHash, UUID approvalId,
                         String policyVersion) {
        @Override public String toString() { return "SyntheticGrantV2Codec.Action[REDACTED]"; }
    }

    public static final class Prepared {
        private final byte[] claimsBytes, actionBytes, unsignedFrame;
        private final String payloadSha256;
        private Prepared(byte[] claims, byte[] action, byte[] frame, String digest) {
            claimsBytes = claims.clone(); actionBytes = action.clone(); unsignedFrame = frame.clone();
            payloadSha256 = digest;
        }
        public byte[] claimsBytes() { return claimsBytes.clone(); }
        public byte[] actionBytes() { return actionBytes.clone(); }
        public byte[] unsignedFrame() { return unsignedFrame.clone(); }
        public String payloadSha256() { return payloadSha256; }
        @Override public String toString() { return "SyntheticGrantV2Codec.Prepared[UNSIGNED]"; }
    }

    /** No clock, raw JSON, key, MAC, registry, Authority or persistence input is accepted. */
    public static Prepared prepare(Profile profile, Claims claims, Action action) {
        try {
            if (profile == null || claims == null || action == null) throw invalid();
            checkClaims(claims, profile); checkAction(action, profile);
            Map<String, Object> actionMap = actionMap(action);
            Map<String, Object> claimsMap = claimsMap(claims);
            for (var entry : actionMap.entrySet()) {
                if (!Objects.equals(entry.getValue(), claimsMap.get(entry.getKey()))) throw invalid();
            }
            byte[] actionBytes = bytes(actionMap, profile.actionMaxUtf8Bytes(), profile);
            String digest = sha256(actionBytes);
            if (!digest.equals(claims.payloadHash())) throw invalid();
            byte[] claimsBytes = bytes(claimsMap, profile.claimsMaxUtf8Bytes(), profile);
            byte[] prefix = "FUSE-GRANT-v2".getBytes(StandardCharsets.US_ASCII);
            int total = Math.addExact(Math.addExact(prefix.length, 9),
                    Math.addExact(claimsBytes.length, actionBytes.length));
            byte[] frame = ByteBuffer.allocate(total).put(prefix).put((byte) 0)
                    .putInt(claimsBytes.length).put(claimsBytes)
                    .putInt(actionBytes.length).put(actionBytes).array();
            return new Prepared(claimsBytes, actionBytes, frame, digest);
        } catch (IllegalArgumentException | NullPointerException | ArithmeticException rejected) {
            throw invalid();
        }
    }

    /**
     * Explicit root-to-leaf unsigned chain preparation. The existing single-row
     * format and prepare API are unchanged. Structural success establishes no
     * current issuer, lifecycle, committed result, temporal or operational authority.
     */
    public static SyntheticGrantChainStructure.PreparedChain prepareChain(
            Profile profile, List<SyntheticGrantChainStructure.Node> nodes) {
        try {
            var snapshot = SyntheticGrantChainStructure.freezeNodes(nodes);
            var frames = new ArrayList<Prepared>(snapshot.size());
            for (var node : snapshot) frames.add(prepare(profile, node.claims(), node.action()));
            return SyntheticGrantChainStructure.finish(frames);
        } catch (IllegalArgumentException | NullPointerException rejected) {
            throw SyntheticGrantChainStructure.invalid();
        }
    }

    /**
     * Explicit unsigned KYC/LOAN supplied-result binding; never acquisition of
     * authoritative finality or verification of a result canonicalization profile.
     */
    public static SyntheticGrantStageBinding.PreparedStage prepareAgentResultStage(
            Profile profile, List<SyntheticGrantChainStructure.Node> nodes,
            SyntheticGrantStageBinding.BindingProfile bindingProfile,
            SyntheticGrantStageBinding.StageCommand command,
            SyntheticGrantStageBinding.RunSnapshot run,
            SyntheticGrantStageBinding.ResultSnapshot result,
            SyntheticGrantStageBinding.WorkflowSnapshot workflow,
            SyntheticGrantStageBinding.ExpectedResultBinding expected) {
        try {
            var snapshot = SyntheticGrantChainStructure.freezeNodes(nodes);
            var chain = prepareChain(profile, snapshot);
            return SyntheticGrantStageBinding.bind(chain, snapshot, bindingProfile, command, run, result, workflow, expected);
        } catch (IllegalArgumentException | NullPointerException rejected) {
            throw SyntheticGrantStageBinding.invalid();
        }
    }

    private static void checkClaims(Claims c, Profile p) {
        if (!"FUSE-GRANT-v2".equals(c.format()) || !"HMAC-SHA256".equals(c.algorithm())
                || c.grantId() == null || c.workflowId() == null || c.rootAuthorizationId() == null
                || c.targetRunId() == null || c.payoutAccountId() == null || c.actionId() == null
                || c.riskLedgerId() == null || c.allowedAction() == null || c.generation() < 1
                || c.amountKrw() < 1 || c.depth() < 1 || c.depth() > 3
                || c.issuedAt() < 0 || c.expiresAt() <= c.issuedAt()
                || Math.subtractExact(c.expiresAt(), c.issuedAt()) > p.ttlSecondsMax()) throw invalid();
        boolean sourceAbsent = c.sourceRunId() == null && c.sourceResultId() == null && c.parentGrantId() == null;
        boolean sourcePresent = c.sourceRunId() != null && c.sourceResultId() != null && c.parentGrantId() != null;
        if (!(switch (c.depth()) {
            case 1 -> sourceAbsent && c.approvalId() == null;
            case 2 -> sourcePresent && c.approvalId() == null;
            case 3 -> sourcePresent && c.approvalId() != null;
            default -> false;
        })) throw invalid();
        synthetic(c.kid(), p); synthetic(c.principalId(), p); synthetic(c.customerId(), p);
        synthetic(c.issuer(), p); synthetic(c.sourceAgent(), p); synthetic(c.targetAgent(), p);
        text(c.originIntent(), 64, p); text(c.policyVersion(), 64, p);
        hash(c.payloadHash(), false); hash(c.evidenceBundleHash(), true);
    }

    private static void checkAction(Action a, Profile p) {
        if (a.actionId() == null || a.workflowId() == null || a.targetRunId() == null
                || a.payoutAccountId() == null || a.allowedAction() == null
                || a.generation() < 1 || a.amountKrw() < 1) throw invalid();
        synthetic(a.customerId(), p); text(a.policyVersion(), 64, p); hash(a.evidenceBundleHash(), true);
    }

    private static void synthetic(String value, Profile p) {
        text(value, 64, p);
        if (!value.startsWith("synthetic-") || value.length() == "synthetic-".length()) throw invalid();
    }

    private static void text(String value, int bound, Profile p) {
        if (value == null || value.isEmpty() || value.length() > bound
                || value.length() > p.stringMaxUtf16CodeUnits()) throw invalid();
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            if (Character.isHighSurrogate(current)) {
                if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) throw invalid();
            } else if (Character.isLowSurrogate(current)) throw invalid();
        }
    }

    private static void hash(String value, boolean nullable) {
        if (value == null && nullable) return;
        if (value == null || !value.matches("[0-9a-f]{64}")) throw invalid();
    }

    private static byte[] bytes(Map<String, Object> values, int cap, Profile p) {
        if (values.size() > p.fieldsPerObjectMax()) throw invalid();
        // Both maps are closed flat objects with scalar/null values (depth1), no arrays.
        for (var entry : values.entrySet()) {
            text(entry.getKey(), p.stringMaxUtf16CodeUnits(), p);
            if (entry.getValue() instanceof String value) text(value, p.stringMaxUtf16CodeUnits(), p);
        }
        byte[] result = CanonicalJson.write(values).getBytes(StandardCharsets.UTF_8);
        if (result.length > cap) throw invalid();
        return result;
    }

    private static Map<String, Object> actionMap(Action a) {
        var m = new LinkedHashMap<String, Object>();
        m.put("actionId", uuid(a.actionId())); m.put("workflowId", uuid(a.workflowId()));
        m.put("generation", a.generation()); m.put("allowedAction", a.allowedAction().name());
        m.put("customerId", a.customerId()); m.put("amountKrw", a.amountKrw());
        m.put("payoutAccountId", uuid(a.payoutAccountId())); m.put("targetRunId", uuid(a.targetRunId()));
        m.put("sourceResultId", uuid(a.sourceResultId())); m.put("evidenceBundleHash", a.evidenceBundleHash());
        m.put("approvalId", uuid(a.approvalId())); m.put("policyVersion", a.policyVersion());
        return m;
    }

    private static Map<String, Object> claimsMap(Claims c) {
        var m = new LinkedHashMap<String, Object>();
        m.put("format", c.format()); m.put("algorithm", c.algorithm()); m.put("kid", c.kid());
        m.put("grantId", uuid(c.grantId())); m.put("workflowId", uuid(c.workflowId()));
        m.put("generation", c.generation()); m.put("rootAuthorizationId", uuid(c.rootAuthorizationId()));
        m.put("principalId", c.principalId()); m.put("originIntent", c.originIntent());
        m.put("issuer", c.issuer()); m.put("sourceAgent", c.sourceAgent()); m.put("targetAgent", c.targetAgent());
        m.put("sourceRunId", uuid(c.sourceRunId())); m.put("targetRunId", uuid(c.targetRunId()));
        m.put("allowedAction", c.allowedAction().name()); m.put("customerId", c.customerId());
        m.put("amountKrw", c.amountKrw()); m.put("payoutAccountId", uuid(c.payoutAccountId()));
        m.put("sourceResultId", uuid(c.sourceResultId())); m.put("evidenceBundleHash", c.evidenceBundleHash());
        m.put("parentGrantId", uuid(c.parentGrantId())); m.put("depth", c.depth()); m.put("actionId", uuid(c.actionId()));
        m.put("payloadHash", c.payloadHash()); m.put("policyVersion", c.policyVersion());
        m.put("riskLedgerId", uuid(c.riskLedgerId())); m.put("approvalId", uuid(c.approvalId()));
        m.put("issuedAt", c.issuedAt()); m.put("expiresAt", c.expiresAt());
        return m;
    }

    private static String uuid(UUID value) { return value == null ? null : value.toString(); }
    private static String sha256(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (NoSuchAlgorithmException unavailable) { throw new IllegalStateException("SHA256_UNAVAILABLE"); }
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_SYNTHETIC_GRANT_V2"); }
}
