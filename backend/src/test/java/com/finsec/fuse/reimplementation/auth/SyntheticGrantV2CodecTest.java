package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.lang.reflect.RecordComponent;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantV2Codec.*;
import static org.junit.jupiter.api.Assertions.*;

/** Independent synthetic byte contracts, not executed security or real grant evidence. */
class SyntheticGrantV2CodecTest {
    private static final String EXPECTED_ACTION = "{\"actionId\":\"00000000-0000-0000-0000-000000000001\",\"allowedAction\":\"EVALUATE_KYC\",\"amountKrw\":9007199254740993,\"approvalId\":null,\"customerId\":\"synthetic-customer\",\"evidenceBundleHash\":null,\"generation\":1,\"payoutAccountId\":\"00000000-0000-0000-0000-000000000003\",\"policyVersion\":\"synthetic-policy\",\"sourceResultId\":null,\"targetRunId\":\"00000000-0000-0000-0000-000000000004\",\"workflowId\":\"00000000-0000-0000-0000-000000000002\"}";
    private static final String EXPECTED_CLAIMS = "{\"actionId\":\"00000000-0000-0000-0000-000000000001\",\"algorithm\":\"HMAC-SHA256\",\"allowedAction\":\"EVALUATE_KYC\",\"amountKrw\":9007199254740993,\"approvalId\":null,\"customerId\":\"synthetic-customer\",\"depth\":1,\"evidenceBundleHash\":null,\"expiresAt\":400,\"format\":\"FUSE-GRANT-v2\",\"generation\":1,\"grantId\":\"00000000-0000-0000-0000-000000000005\",\"issuedAt\":100,\"issuer\":\"synthetic-issuer\",\"kid\":\"synthetic-key\",\"originIntent\":\"synthetic-intent\",\"parentGrantId\":null,\"payloadHash\":\"90c64612a43f403c5cb7d6ef90f2d6a8619913889ed328cb4cc808f02640b365\",\"payoutAccountId\":\"00000000-0000-0000-0000-000000000003\",\"policyVersion\":\"synthetic-policy\",\"principalId\":\"synthetic-principal\",\"riskLedgerId\":\"00000000-0000-0000-0000-000000000007\",\"rootAuthorizationId\":\"00000000-0000-0000-0000-000000000006\",\"sourceAgent\":\"synthetic-source\",\"sourceResultId\":null,\"sourceRunId\":null,\"targetAgent\":\"synthetic-target\",\"targetRunId\":\"00000000-0000-0000-0000-000000000004\",\"workflowId\":\"00000000-0000-0000-0000-000000000002\"}";
    private static final String EXPECTED_HASH = "90c64612a43f403c5cb7d6ef90f2d6a8619913889ed328cb4cc808f02640b365";
    private static UUID id(long value) { return new UUID(0, value); }
    private static Profile profile() { return new Profile(16384, 8192, 8, 64, 1000, 300); }
    private static Action action(int depth) {
        return new Action(id(1), id(2), 1, GrantStorageShape.AllowedAction.EVALUATE_KYC,
                "synthetic-customer", 9007199254740993L, id(3), id(4),
                depth == 1 ? null : id(8), null, depth == 3 ? id(10) : null, "synthetic-policy");
    }
    private static String payload(Action a) {
        var m = new LinkedHashMap<String, Object>();
        m.put("actionId", a.actionId() == null ? null : a.actionId().toString());
        m.put("workflowId", a.workflowId() == null ? null : a.workflowId().toString());
        m.put("generation", a.generation()); m.put("allowedAction", a.allowedAction().name());
        m.put("customerId", a.customerId()); m.put("amountKrw", a.amountKrw());
        m.put("payoutAccountId", a.payoutAccountId().toString()); m.put("targetRunId", a.targetRunId().toString());
        m.put("sourceResultId", a.sourceResultId() == null ? null : a.sourceResultId().toString());
        m.put("evidenceBundleHash", a.evidenceBundleHash());
        m.put("approvalId", a.approvalId() == null ? null : a.approvalId().toString());
        m.put("policyVersion", a.policyVersion()); return CanonicalJson.sha256(m);
    }
    private static Claims claims(Action a, int depth) {
        return new Claims("FUSE-GRANT-v2", "HMAC-SHA256", "synthetic-key", id(5), a.workflowId(),
                a.generation(), id(6), "synthetic-principal", "synthetic-intent", "synthetic-issuer",
                "synthetic-source", "synthetic-target", depth == 1 ? null : id(9), a.targetRunId(),
                a.allowedAction(), a.customerId(), a.amountKrw(), a.payoutAccountId(), a.sourceResultId(),
                a.evidenceBundleHash(), depth == 1 ? null : id(11), depth, a.actionId(), payload(a),
                a.policyVersion(), id(7), a.approvalId(), 100, 400);
    }
    @SuppressWarnings("unchecked")
    private static <T extends Record> T changed(T value, String field, Object replacement) throws Exception {
        RecordComponent[] fields = value.getClass().getRecordComponents();
        Class<?>[] types = new Class<?>[fields.length]; Object[] values = new Object[fields.length];
        boolean found = false;
        for (int i = 0; i < fields.length; i++) {
            types[i] = fields[i].getType(); values[i] = fields[i].getAccessor().invoke(value);
            if (fields[i].getName().equals(field)) { values[i] = replacement; found = true; }
        }
        assertTrue(found); return (T) value.getClass().getDeclaredConstructor(types).newInstance(values);
    }
    private static void rejected(Executable action) {
        var error = assertThrows(IllegalArgumentException.class, action);
        assertEquals("INVALID_SYNTHETIC_GRANT_V2", error.getMessage()); assertNull(error.getCause());
    }

    @Test void fixedLiteralBytesPreserveIntegerAboveBinary64AndUnsignedFraming() throws Exception {
        var a = action(1); var prepared = prepare(profile(), claims(a, 1), a);
        assertEquals(EXPECTED_ACTION, new String(prepared.actionBytes(), StandardCharsets.UTF_8));
        assertEquals(EXPECTED_CLAIMS, new String(prepared.claimsBytes(), StandardCharsets.UTF_8));
        assertEquals(EXPECTED_HASH, prepared.payloadSha256());
        var output = new ByteArrayOutputStream();
        try (var frame = new DataOutputStream(output)) {
            frame.write("FUSE-GRANT-v2".getBytes(StandardCharsets.US_ASCII)); frame.writeByte(0);
            frame.writeInt(EXPECTED_CLAIMS.getBytes(StandardCharsets.UTF_8).length);
            frame.write(EXPECTED_CLAIMS.getBytes(StandardCharsets.UTF_8));
            frame.writeInt(EXPECTED_ACTION.getBytes(StandardCharsets.UTF_8).length);
            frame.write(EXPECTED_ACTION.getBytes(StandardCharsets.UTF_8));
        }
        assertArrayEquals(output.toByteArray(), prepared.unsignedFrame());
        assertEquals(EXPECTED_HASH, HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(EXPECTED_ACTION.getBytes(StandardCharsets.UTF_8))));
    }

    @Test void everyDuplicatedActionFieldMustBindEvenWhenPayloadHashIsRecomputed() throws Exception {
        var original = action(1); var bound = claims(original, 1);
        String[] fields = {"actionId", "workflowId", "generation", "allowedAction", "customerId", "amountKrw",
                "payoutAccountId", "targetRunId", "sourceResultId", "evidenceBundleHash", "approvalId", "policyVersion"};
        Object[] replacements = {id(99), id(99), 2, GrantStorageShape.AllowedAction.CREATE_LOAN_RECOMMENDATION,
                "synthetic-other", 9007199254740994L, id(99), id(99), id(99), "a".repeat(64), id(99), "synthetic-other"};
        assertEquals(12, fields.length);
        for (int i = 0; i < fields.length; i++) {
            var different = changed(original, fields[i], replacements[i]);
            var rehashed = changed(bound, "payloadHash", payload(different));
            rejected(() -> prepare(profile(), rehashed, different));
        }
    }

    @Test void nullShapeFollowsThreeExistingDepthsWithoutActionRoleInference() throws Exception {
        for (int depth = 1; depth <= 3; depth++) {
            var a = action(depth); assertNotNull(prepare(profile(), claims(a, depth), a));
        }
        var a = action(1); var c = claims(a, 1);
        rejected(() -> prepare(profile(), changed(c, "parentGrantId", id(99)), a));
        rejected(() -> prepare(profile(), changed(c, "depth", 0), a));
        rejected(() -> prepare(profile(), changed(c, "depth", 4), a));
        var second = action(2); var c2 = claims(second, 2);
        rejected(() -> prepare(profile(), changed(c2, "sourceRunId", null), second));
        var third = changed(action(3), "approvalId", null);
        rejected(() -> prepare(profile(), claims(third, 3), third));
    }

    @Test void utf8ByteCapsAreExactAndCannotUseCharacterCount() throws Exception {
        var a = changed(action(1), "customerId", "synthetic-한😀"); var c = claims(a, 1);
        var baseline = prepare(profile(), c, a);
        int cb = baseline.claimsBytes().length, ab = baseline.actionBytes().length;
        var exact = new Profile(cb, ab, 1, 29, 64, 300);
        assertArrayEquals(baseline.unsignedFrame(), prepare(exact, c, a).unsignedFrame());
        rejected(() -> prepare(new Profile(cb - 1, ab, 1, 29, 64, 300), c, a));
        rejected(() -> prepare(new Profile(cb, ab - 1, 1, 29, 64, 300), c, a));
        assertTrue(ab > new String(baseline.actionBytes(), StandardCharsets.UTF_8).length());
        rejected(() -> prepare(new Profile(cb, ab, 1, 28, 64, 300), c, a));
    }

    @Test void staticTtlAndLongBoundsNeverBecomeCurrentTimeValidity() throws Exception {
        var a = action(1); var c = claims(a, 1);
        assertNotNull(prepare(profile(), c, a)); // historical epoch100..400 is bytes, not a clock verdict.
        rejected(() -> prepare(profile(), changed(c, "expiresAt", 401L), a));
        rejected(() -> prepare(profile(), changed(c, "expiresAt", 100L), a));
        rejected(() -> prepare(profile(), changed(c, "issuedAt", Long.MIN_VALUE), a));
        rejected(() -> prepare(profile(), changed(c, "expiresAt", Long.MIN_VALUE), a));
        var atMax = changed(changed(c, "issuedAt", Long.MAX_VALUE - 300), "expiresAt", Long.MAX_VALUE);
        assertNotNull(prepare(profile(), atMax, a));
        rejected(() -> prepare(new Profile(16384, 8192, 8, 64, 1000, 299), c, a));
        var huge = changed(a, "amountKrw", Long.MAX_VALUE);
        assertNotNull(prepare(profile(), claims(huge, 1), huge));
        var zero = changed(a, "amountKrw", 0L);
        rejected(() -> prepare(profile(), claims(zero, 1), zero));
    }

    @Test void outputArraysAreDetachedAndNoAuthenticatedTokenIsReturned() {
        var a = action(1); var p = prepare(profile(), claims(a, 1), a);
        byte[] cb = p.claimsBytes(), ab = p.actionBytes(), frame = p.unsignedFrame();
        byte[] expectedClaims = cb.clone(), expectedAction = ab.clone(), expectedFrame = frame.clone();
        Arrays.fill(cb, (byte) 0); Arrays.fill(ab, (byte) 0); Arrays.fill(frame, (byte) 0);
        assertArrayEquals(expectedClaims, p.claimsBytes()); assertArrayEquals(expectedAction, p.actionBytes());
        assertArrayEquals(expectedFrame, p.unsignedFrame());
        assertEquals("SyntheticGrantV2Codec.Prepared[UNSIGNED]", p.toString());
        assertFalse(p.toString().contains("synthetic-key"));
    }

    @Test void explicitProfilesRejectUnboundedValuesAndDoNotDefault() {
        rejected(() -> new Profile(Integer.MAX_VALUE, 8192, 8, 64, 1000, 300));
        rejected(() -> new Profile(16384, 8193, 8, 64, 1000, 300));
        rejected(() -> new Profile(16384, 8192, 0, 64, 1000, 300));
        rejected(() -> new Profile(16384, 8192, 8, 65, 1000, 300));
        rejected(() -> new Profile(16384, 8192, 8, 64, 1001, 300));
        rejected(() -> new Profile(16384, 8192, 8, 64, 1000, Long.MAX_VALUE));
        rejected(() -> new Profile(0, 8192, 8, 64, 1000, 300));
        var a = action(1); rejected(() -> prepare(null, claims(a, 1), a));
    }

    @Test void syntheticLabelsNullsAlgorithmsHashesAndSurrogatesFailClosed() throws Exception {
        var a = action(1); var c = claims(a, 1);
        for (String field : List.of("kid", "principalId", "issuer", "sourceAgent", "targetAgent")) {
            rejected(() -> prepare(profile(), changed(c, field, "real-service"), a));
        }
        rejected(() -> prepare(profile(), changed(c, "grantId", null), a));
        rejected(() -> prepare(profile(), changed(c, "format", "FUSE-GRANT-v1"), a));
        rejected(() -> prepare(profile(), changed(c, "algorithm", "none"), a));
        rejected(() -> prepare(profile(), changed(c, "payloadHash", "0".repeat(64)), a));
        rejected(() -> prepare(profile(), changed(c, "payloadHash", "A".repeat(64)), a));
        rejected(() -> prepare(profile(), changed(c, "originIntent", "\uD800"), a));
        rejected(() -> prepare(profile(), changed(c, "policyVersion", ""), a));
        var blankLabel = changed(a, "customerId", "synthetic-");
        rejected(() -> prepare(profile(), claims(blankLabel, 1), blankLabel));
    }
}
