package com.finsec.fuse.policy;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class GrantCodecTest {
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private final byte[] key=new byte[32];
    private final GrantCodec codec=new GrantCodec(json,new SigningKeyProvider("test-key",Map.of("test-key",key)));
    private final byte[] action="{\"customerId\":\"customer-102\",\"amountKrw\":1000000}".getBytes(StandardCharsets.UTF_8);
    private GrantClaims claims() {
        return new GrantClaims(UUID.fromString("00000000-0000-4000-8000-000000000001"),UUID.fromString("00000000-0000-4000-8000-000000000002"),1,
                UUID.fromString("00000000-0000-4000-8000-000000000003"),"customer-102","LOAN_APPLICATION","FUSE","FUSE","KYC",null,
                UUID.fromString("00000000-0000-4000-8000-000000000004"),"EVALUATE_KYC","customer-102",1_000_000,
                UUID.fromString("00000000-0000-4000-8000-000000000102"),null,null,null,1,
                UUID.fromString("00000000-0000-4000-8000-000000000005"),Json.sha256(action),"FUSE-MVP-2",
                UUID.fromString("00000000-0000-4000-8000-000000000006"),null,Instant.parse("2026-10-09T04:01:00Z").toEpochMilli());
    }
    @Test void authenticatesExactRawBytesAndFixedNoTrailingNewlineDomain() throws Exception {
        var t=codec.sign(claims(),action);var result=codec.verify(t);
        assertEquals(claims(),result.claims());assertArrayEquals(action,result.actionBytes());
        var mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(key,"HmacSHA256"));
        byte[] expected=mac.doFinal(("FUSE-GRANT-v1\ntest-key\n"+t.grant().payloadBase64Url()).getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(expected,result.macBytes());assertFalse(t.grant().macBase64Url().contains("="));
    }
    @ParameterizedTest @ValueSource(strings={"amountKrw","customerId","allowedAction"})
    void tamperedClaimByteCannotReachExecution(String field) {
        var t=codec.sign(claims(),action);String original=new String(Base64.getUrlDecoder().decode(t.grant().payloadBase64Url()),StandardCharsets.UTF_8);
        String altered=switch(field){case "amountKrw"->original.replace("1000000","2000000");case "customerId"->original.replace("customer-102","customer-101");default->original.replace("EVALUATE_KYC","FINAL_APPROVE");};
        var forged=new GrantTransport(new GrantTransport.Grant(t.grant().format(),t.grant().kid(),b64(altered.getBytes(StandardCharsets.UTF_8)),t.grant().macBase64Url()),t.actionPayloadBase64Url());
        assertDenied("SIGNATURE_INVALID",()->codec.verify(forged));
    }
    @Test void actionTamperingFailsPayloadHashEvenWhenClaimsMacIsValid() {
        var t=codec.sign(claims(),action);assertDenied("SIGNATURE_INVALID",()->codec.verify(new GrantTransport(t.grant(),b64("{}".getBytes(StandardCharsets.UTF_8)))));
    }
    @Test void wrongFormatUnknownKeyAndPaddingAreRejected() {
        var t=codec.sign(claims(),action);var g=t.grant();
        assertDenied("SIGNATURE_INVALID",()->codec.verify(new GrantTransport(new GrantTransport.Grant("JWS",g.kid(),g.payloadBase64Url(),g.macBase64Url()),t.actionPayloadBase64Url())));
        assertDenied("SIGNATURE_INVALID",()->codec.verify(new GrantTransport(new GrantTransport.Grant(g.format(),"other-key",g.payloadBase64Url(),g.macBase64Url()),t.actionPayloadBase64Url())));
        assertDenied("SIGNATURE_INVALID",()->codec.verify(new GrantTransport(new GrantTransport.Grant(g.format(),g.kid(),g.payloadBase64Url()+"=",g.macBase64Url()),t.actionPayloadBase64Url())));
    }
    @ParameterizedTest @ValueSource(strings={"duplicate","unknown","fractional","stringInteger","trailing","shortUuid","invalidUtf8"})
    void evenAuthenticatedMalformedClaimsAreRejected(String mutation) throws Exception {
        String raw=json.write(claims().canonical(json));
        byte[] bytes=switch(mutation) {
            case "duplicate" -> raw.replace("\"generation\":1", "\"generation\":1,\"generation\":2").getBytes(StandardCharsets.UTF_8);
            case "unknown" -> raw.replace("\"generation\":1", "\"generation\":1,\"isAdmin\":true").getBytes(StandardCharsets.UTF_8);
            case "fractional" -> raw.replace("\"generation\":1", "\"generation\":1.0").getBytes(StandardCharsets.UTF_8);
            case "stringInteger" -> raw.replace("\"generation\":1", "\"generation\":\"1\"").getBytes(StandardCharsets.UTF_8);
            case "trailing" -> (raw+"{}").getBytes(StandardCharsets.UTF_8);
            case "shortUuid" -> raw.replace("00000000-0000-4000-8000-000000000001","0-0-4000-8000-1").getBytes(StandardCharsets.UTF_8);
            default -> new byte[]{(byte)0xc3,0x28};
        };
        var forged=authenticated(bytes,action);assertDenied("SIGNATURE_INVALID",()->codec.verify(forged));
    }
    @Test void whitespaceChangeWithCorrectNewMacIsReadWithoutReserialization() throws Exception {
        String raw=json.write(claims().canonical(json)).replace(",",", ");
        var t=authenticated(raw.getBytes(StandardCharsets.UTF_8),action);
        assertArrayEquals(raw.getBytes(StandardCharsets.UTF_8),codec.verify(t).claimsBytes());
    }
    @ParameterizedTest @ValueSource(strings={"{\"amountKrw\":1,\"amountKrw\":2}","[]","null","{bad}","{}{}"})
    void authenticatedActionMustStillBeOneStrictJsonObject(String rawAction) throws Exception {
        byte[] bytes=rawAction.getBytes(StandardCharsets.UTF_8);
        var values=claims().canonical(json);values.put("payloadHash",Json.sha256(bytes));
        var transport=authenticated(json.bytes(values),bytes);
        assertDenied("SIGNATURE_INVALID",()->codec.verify(transport));
    }
    @Test void authenticatedActionCannotContradictItsOwnScopedAmount() throws Exception {
        byte[] wrong="{\"amountKrw\":2000000}".getBytes(StandardCharsets.UTF_8);
        var fields=claims().canonical(json);fields.put("payloadHash",Json.sha256(wrong));
        var transport=authenticated(json.bytes(fields),wrong);
        assertDenied("CONTEXT_MISMATCH",()->codec.verify(transport));
    }
    @Test void returnedBytesDoNotExposeMutableStoredArrays() {
        var result=codec.verify(codec.sign(claims(),action));byte[] returned=result.actionBytes();returned[0]=0;
        assertArrayEquals(action,result.actionBytes());
    }
    @Test void signingKeyMinimumIsEnforced() { assertThrows(IllegalArgumentException.class,()->new SigningKeyProvider("bad",Map.of("bad",new byte[31]))); }
    @Test void decodedClaimsAndActionsRespectSixteenKiBBoundaries() throws Exception {
        byte[] exact=("{\"padding\":\""+"a".repeat(16384-14)+"\"}").getBytes(StandardCharsets.UTF_8);
        assertEquals(16384,exact.length);
        var fields=claims().canonical(json);fields.put("payloadHash",Json.sha256(exact));
        assertArrayEquals(exact,codec.verify(authenticated(json.bytes(fields),exact)).actionBytes());
        byte[] oversized=Arrays.copyOf(exact,16385);
        fields.put("payloadHash",Json.sha256(oversized));
        var transport=authenticated(json.bytes(fields),oversized);
        assertDenied("SIGNATURE_INVALID",()->codec.verify(transport));
        byte[] claimsOver=new byte[16385];
        var hugeClaims=authenticated(claimsOver,action);
        assertDenied("SIGNATURE_INVALID",()->codec.verify(hugeClaims));
        var hugeTransport=new GrantTransport(transport.grant(),"a".repeat(65537));
        assertDenied("SIGNATURE_INVALID",()->codec.verify(hugeTransport));
    }
    @Test void authenticOldGrantSurvivesRotationButNotRevocation() {
        var old=codec.sign(claims(),action);
        var entries=new HashMap<String,SigningKeyProvider.Entry>();
        entries.put("next",new SigningKeyProvider.Entry(new byte[32],SigningKeyProvider.State.ISSUING));
        entries.put("test-key",new SigningKeyProvider.Entry(key,SigningKeyProvider.State.VERIFY_ONLY));
        var rotated=new GrantCodec(json,new SigningKeyProvider("next",entries,true));
        assertEquals(claims(),rotated.verify(old).claims());
        assertEquals("next",rotated.sign(claims(),action).grant().kid());
        entries.put("test-key",new SigningKeyProvider.Entry(key,SigningKeyProvider.State.REVOKED));
        var revoked=new GrantCodec(json,new SigningKeyProvider("next",entries,true));
        assertDenied("SIGNATURE_INVALID",()->revoked.verify(old));
    }
    private GrantTransport authenticated(byte[] claimsBytes,byte[] actionBytes) throws Exception {
        String payload=b64(claimsBytes);Mac m=Mac.getInstance("HmacSHA256");m.init(new SecretKeySpec(key,"HmacSHA256"));
        return new GrantTransport(new GrantTransport.Grant(GrantCodec.FORMAT,"test-key",payload,b64(m.doFinal((GrantCodec.FORMAT+"\ntest-key\n"+payload).getBytes(StandardCharsets.UTF_8)))),b64(actionBytes));
    }
    private static String b64(byte[] bytes){return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    private static void assertDenied(String expected,org.junit.jupiter.api.function.Executable action) { assertEquals(expected,assertThrows(PolicyException.class,action).reasonCode()); }
}
