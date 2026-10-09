package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.observation.SecurityCheckObservation;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.policy.*;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.*;

/** Both isolated arms retain the same cryptographic floor before any database or execution use. */
class BaselineDelegationServiceTest {
    private static final Instant NOW=Instant.parse("2026-10-09T04:00:00Z");
    private static final byte[] KEY=new byte[32];
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private final GrantCodec codec=new GrantCodec(json,new SigningKeyProvider("test-key",Map.of("test-key",KEY)));
    private final ForbiddenDb db=new ForbiddenDb();
    private final byte[] action=json.bytes(Map.of("customerId","customer-102","amountKrw",1_000_000));
    private final GrantClaims claims=new GrantClaims(UUID.randomUUID(),UUID.randomUUID(),1,UUID.randomUUID(),
            "customer-102","LOAN_APPLICATION","FUSE","FUSE","KYC",null,UUID.randomUUID(),"EVALUATE_KYC",
            "customer-102",1_000_000,UUID.randomUUID(),null,null,null,1,UUID.randomUUID(),Json.sha256(action),
            "FUSE-MVP-2",UUID.randomUUID(),null,NOW.plusSeconds(60).toEpochMilli());

    private DelegationService service(boolean baseline) {
        return baseline?new BaselineDelegationService(db,json,null,codec,null,null,null):
            new DelegationService(db,json,null,codec,null,null,null);
    }
    static Stream<Arguments> integrityMutations() {
        return Stream.of(true,false).flatMap(baseline->Stream.of("MAC","BODY","CLAIMS_DUPLICATE","CLAIMS_UNKNOWN",
                "CLAIMS_TRAILING","CLAIMS_INTEGER","ACTION_DUPLICATE","ACTION_TRAILING","ACTION_NONOBJECT",
                "ACTION_UTF8","ACTION_NULL","NONCANONICAL_BASE64","UNKNOWN_KID").map(mutation->Arguments.of(baseline,mutation)));
    }
    @ParameterizedTest @MethodSource("integrityMutations")
    void commonIntegrityFailurePreventsExecutionInBothArms(boolean baseline,String mutation) throws Exception {
        var original=codec.sign(claims,action);var grant=original.grant();
        String raw=json.write(claims.canonical(json));
        GrantTransport tested=switch(mutation) {
            case "MAC" -> {
                byte[] mac=Base64.getUrlDecoder().decode(grant.macBase64Url());mac[0]^=1;
                yield new GrantTransport(new GrantTransport.Grant(grant.format(),grant.kid(),grant.payloadBase64Url(),b64(mac)),original.actionPayloadBase64Url());
            }
            case "BODY" -> new GrantTransport(grant,b64("{}".getBytes(StandardCharsets.UTF_8)));
            case "CLAIMS_DUPLICATE" -> authenticated(raw.replace("\"generation\":1","\"generation\":1,\"generation\":2").getBytes(StandardCharsets.UTF_8),action);
            case "CLAIMS_UNKNOWN" -> authenticated(raw.replace("\"generation\":1","\"generation\":1,\"role\":\"ADMIN\"").getBytes(StandardCharsets.UTF_8),action);
            case "CLAIMS_TRAILING" -> authenticated((raw+"{}").getBytes(StandardCharsets.UTF_8),action);
            case "CLAIMS_INTEGER" -> authenticated(raw.replace("\"generation\":1","\"generation\":\"1\"").getBytes(StandardCharsets.UTF_8),action);
            case "ACTION_DUPLICATE" -> signedAction("{\"amountKrw\":1,\"amountKrw\":2}".getBytes(StandardCharsets.UTF_8));
            case "ACTION_TRAILING" -> signedAction("{}{}".getBytes(StandardCharsets.UTF_8));
            case "ACTION_NONOBJECT" -> signedAction("[]".getBytes(StandardCharsets.UTF_8));
            case "ACTION_UTF8" -> signedAction(new byte[]{(byte)0xc3,0x28});
            case "ACTION_NULL" -> signedAction("null".getBytes(StandardCharsets.UTF_8));
            case "NONCANONICAL_BASE64" -> new GrantTransport(new GrantTransport.Grant(grant.format(),grant.kid(),grant.payloadBase64Url()+"=",grant.macBase64Url()),original.actionPayloadBase64Url());
            case "UNKNOWN_KID" -> new GrantTransport(new GrantTransport.Grant(grant.format(),"unregistered",grant.payloadBase64Url(),grant.macBase64Url()),original.actionPayloadBase64Url());
            default -> throw new AssertionError(mutation);
        };
        var executions=new AtomicInteger();
        var observation=SecurityCheckObservation.begin();
        try(observation) {
            var error=assertThrows(PolicyException.class,()->{
                service(baseline).validate(tested,"FUSE",claims.workflowId(),claims.targetRunId(),"EVALUATE_KYC",NOW);
                executions.incrementAndGet();
            });
            assertEquals("SIGNATURE_INVALID",error.reasonCode());
        }
        assertEquals(0,executions.get());assertFalse(db.accessed);
        assertEquals(0,observation.result().completedCheckCount(),"Common checks are not additional FUSE policy work");
    }
    @Test void validBodyHashStillAllowsOnlyTheIsolatedBaselineToAblateActionScope() throws Exception {
        // Correctly authenticated, but intentionally contradictory amount: a scope ablation, not byte tampering.
        var tested=signedAction(json.bytes(Map.of("amountKrw",2_000_000)));
        assertEquals(claims.grantId(),service(true).validate(tested,"FUSE",claims.workflowId(),claims.targetRunId(),"EVALUATE_KYC",NOW).grantId());
        assertEquals("CONTEXT_MISMATCH",assertThrows(PolicyException.class,()->service(false).validate(tested,"FUSE",claims.workflowId(),claims.targetRunId(),"EVALUATE_KYC",NOW)).reasonCode());
        assertEquals("CONTEXT_MISMATCH",assertThrows(PolicyException.class,()->codec.verify(tested)).reasonCode());
        assertFalse(db.accessed);
    }
    @Test void commonOnlyVerificationCannotBeSelectedThroughPublicMethodsOrABaselineBean() throws Exception {
        assertFalse(Modifier.isPublic(GrantCodec.class.getDeclaredMethod("verifyBasic",GrantTransport.class).getModifiers()));
        assertTrue(Modifier.isProtected(DelegationService.class.getDeclaredMethod("verifyBasicTransport",GrantTransport.class).getModifiers()));
        assertTrue(Modifier.isFinal(DelegationService.class.getDeclaredMethod("verifyBasicTransport",GrantTransport.class).getModifiers()));
        assertFalse(Modifier.isPublic(BaselineDelegationService.class.getModifiers()));
        assertFalse(BaselineDelegationService.class.isAnnotationPresent(org.springframework.stereotype.Service.class));
    }
    private GrantTransport signedAction(byte[] bytes) throws Exception {
        var fields=claims.canonical(json);fields.put("payloadHash",Json.sha256(bytes));
        return authenticated(json.bytes(fields),bytes);
    }
    private static GrantTransport authenticated(byte[] claimsBytes,byte[] actionBytes) throws Exception {
        String payload=b64(claimsBytes);Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(KEY,"HmacSHA256"));
        return new GrantTransport(new GrantTransport.Grant(GrantCodec.FORMAT,"test-key",payload,
            b64(mac.doFinal((GrantCodec.FORMAT+"\ntest-key\n"+payload).getBytes(StandardCharsets.UTF_8)))),b64(actionBytes));
    }
    private static String b64(byte[] bytes) { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    private static final class ForbiddenDb extends Db {
        private boolean accessed;
        private ForbiddenDb() { super(null); }
        @Override public List<Map<String,Object>> query(String sql,Object... args) {
            accessed=true;throw new AssertionError("Untrusted envelope must not reach database reads");
        }
        @Override public int update(String sql,Object... args) {
            accessed=true;throw new AssertionError("Untrusted envelope must not reach database writes");
        }
    }
}
