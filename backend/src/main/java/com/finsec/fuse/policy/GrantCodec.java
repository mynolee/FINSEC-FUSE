package com.finsec.fuse.policy;

import com.finsec.fuse.common.Json;
import java.nio.*;
import java.nio.charset.*;
import java.security.*;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

/** Proprietary HMAC format, not JWS or public-key non-repudiation. Authenticates original bytes. */
@Component
public final class GrantCodec {
    public static final String FORMAT = "FUSE-GRANT-v1";
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Set<String> CLAIM_FIELDS = Set.of("grantId","workflowId","generation","rootAuthorizationId",
            "principal","originIntent","issuer","sourceAgent","targetAgent","sourceRunId","targetRunId",
            "allowedAction","customerId","amountKrw","payoutAccountId","sourceResultId","evidenceBundleHash",
            "parentGrantId","depth","actionId","payloadHash","policyVersion","riskLedgerId","approvalId","expiresAtEpochMs");
    private final Json json;
    private final SigningKeyProvider keys;
    public GrantCodec(Json json, SigningKeyProvider keys) { this.json = json; this.keys = keys; }

    public GrantTransport sign(GrantClaims claims, byte[] actionBytes) {
        claims.checkShape();
        if (actionBytes == null || actionBytes.length > 16_384 || !json.sha256(actionBytes).equals(claims.payloadHash()))
            throw new PolicyException("CONTEXT_MISMATCH");
        byte[] claimsBytes = json.bytes(claims.canonical(json));
        if (claimsBytes.length > 16_384) throw invalid();
        String payload = B64.encodeToString(claimsBytes);
        String kid = keys.activeKid();
        return new GrantTransport(new GrantTransport.Grant(FORMAT, kid, payload,
                B64.encodeToString(mac(kid, payload))), B64.encodeToString(actionBytes));
    }

    public VerifiedGrant verify(GrantTransport transport) {
        var verified=verifyBasic(transport);
        requireActionBindings(verified);
        return verified;
    }

    /** Common authentication floor; deliberately package-private, never a caller-selected bypass. */
    VerifiedGrant verifyBasic(GrantTransport transport) {
        try {
            if (transport == null || transport.grant() == null) throw invalid();
            // Bound encoded fields before serialization as well as decoded bytes.
            var envelope = transport.grant();
            if (tooLarge(envelope.payloadBase64Url()) || tooLarge(envelope.macBase64Url())
                    || tooLarge(transport.actionPayloadBase64Url()) || tooLarge(envelope.kid())
                    || tooLarge(envelope.format()) || json.bytes(transport).length > 65_536) throw invalid();
            var grant = transport.grant();
            if (!FORMAT.equals(grant.format()) || grant.kid() == null
                    || !grant.kid().matches("[A-Za-z0-9._-]{1,64}")) throw invalid();
            byte[] claimsBytes = decode(grant.payloadBase64Url(), 16_384);
            byte[] macBytes = decode(grant.macBase64Url(), 32);
            if (macBytes.length != 32 || !MessageDigest.isEqual(mac(grant.kid(), grant.payloadBase64Url()), macBytes))
                throw invalid();
            // No JSON is read until the authentication tag over the original transport bytes passed.
            String claimsJson = utf8(claimsBytes);
            Map<String,Object> fields = json.map(claimsJson);
            if (!fields.keySet().equals(CLAIM_FIELDS)) throw invalid();
            strictScalars(fields);
            GrantClaims claims = json.read(claimsJson, GrantClaims.class);
            claims.checkShape();
            byte[] actionBytes = decode(transport.actionPayloadBase64Url(), 16_384);
            // The action is also strict JSON; duplicate keys must not select different instructions downstream.
            if(json.map(utf8(actionBytes))==null) throw invalid();
            if (!MessageDigest.isEqual(HexFormat.of().parseHex(claims.payloadHash()),
                    HexFormat.of().parseHex(json.sha256(actionBytes)))) throw invalid();
            return new VerifiedGrant(claims, claimsBytes, actionBytes, macBytes, grant.kid());
        } catch (PolicyException denied) { throw denied; }
        catch (RuntimeException malformed) { throw invalid(); }
    }

    void requireActionBindings(VerifiedGrant verified) {
        requireActionBindings(verified.claims(),json.map(utf8(verified.actionBytes())));
    }
    private void requireActionBindings(GrantClaims claims, Map<String,Object> action) {
        Map<String,Object> bound = claims.canonical(json);
        bound.put("requestId", claims.actionId());
        bound.put("runId", claims.targetRunId());
        for (String key : List.of("workflowId","generation","rootAuthorizationId","principal","originIntent",
                "customerId","amountKrw","payoutAccountId","sourceRunId","targetRunId","sourceResultId",
                "allowedAction","actionId","policyVersion","riskLedgerId","approvalId","evidenceBundleHash",
                "requestId","runId")) {
            if (!action.containsKey(key)) continue;
            Object actual = action.get(key), expected = bound.get(key);
            if (expected instanceof UUID) expected = expected.toString();
            boolean same;
            if (expected instanceof Number n) {
                same = (actual instanceof Byte || actual instanceof Short || actual instanceof Integer || actual instanceof Long)
                        && ((Number) actual).longValue() == n.longValue();
            } else same = Objects.equals(actual, expected);
            if (!same) throw new PolicyException("CONTEXT_MISMATCH");
        }
    }
    private static void strictScalars(Map<String,Object> fields) {
        for (String name : List.of("principal","originIntent","issuer","sourceAgent","targetAgent","allowedAction",
                "customerId","payloadHash","policyVersion")) {
            if (!(fields.get(name) instanceof String)) throw invalid();
        }
        if (fields.get("evidenceBundleHash") != null && !(fields.get("evidenceBundleHash") instanceof String)) throw invalid();
        for (String name : List.of("generation","amountKrw","depth","expiresAtEpochMs")) {
            Object value = fields.get(name);
            if (!(value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long)) throw invalid();
        }
        for (String name : List.of("grantId","workflowId","rootAuthorizationId","sourceRunId","targetRunId",
                "payoutAccountId","sourceResultId","parentGrantId","actionId","riskLedgerId","approvalId")) {
            Object value = fields.get(name);
            if (value != null && (!(value instanceof String str)
                    || !str.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))) throw invalid();
        }
    }
    private byte[] mac(String kid, String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keys.key(kid), "HmacSHA256"));
            return mac.doFinal((FORMAT + "\n" + kid + "\n" + payload).getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException impossible) { throw new IllegalStateException("HMAC-SHA256 unavailable", impossible); }
    }
    private static boolean tooLarge(String value) { return value != null && value.length() > 65_536; }
    private static byte[] decode(String value, int maximum) {
        if (value == null || value.length() > ((maximum + 2) / 3) * 4
                || !value.matches("[A-Za-z0-9_-]*")) throw invalid();
        byte[] bytes = Base64.getUrlDecoder().decode(value);
        if (bytes.length > maximum || !B64.encodeToString(bytes).equals(value)) throw invalid();
        return bytes;
    }
    private static String utf8(byte[] value) {
        try { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(value)).toString(); }
        catch (CharacterCodingException malformed) { throw invalid(); }
    }
    private static PolicyException invalid() { return new PolicyException("SIGNATURE_INVALID"); }
    public record VerifiedGrant(GrantClaims claims, byte[] claimsBytes, byte[] actionBytes, byte[] macBytes, String kid) {
        public VerifiedGrant { claimsBytes=claimsBytes.clone(); actionBytes=actionBytes.clone(); macBytes=macBytes.clone(); }
        @Override public byte[] claimsBytes() { return claimsBytes.clone(); }
        @Override public byte[] actionBytes() { return actionBytes.clone(); }
        @Override public byte[] macBytes() { return macBytes.clone(); }
    }
}
