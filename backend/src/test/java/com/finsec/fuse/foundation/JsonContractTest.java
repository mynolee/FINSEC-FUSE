package com.finsec.fuse.foundation;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.config.JsonConfiguration;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class JsonContractTest {
    record Amount(long amountKrw) {}
    record Text(String note) {}
    record Identifier(java.util.UUID id) {}
    @Test void uuidJsonRequiresCanonicalLowercaseStringAndKeepsOptionalNull() {
        String canonical="fbaedcba-0123-4567-89ab-0123456789ab";
        assertEquals(java.util.UUID.fromString(canonical),json.read("{\"id\":\""+canonical+"\"}",Identifier.class).id());
        assertNull(json.read("{\"id\":null}",Identifier.class).id());
        for(String invalid:java.util.List.of("\"FBAEDCBA-0123-4567-89AB-0123456789AB\"","\"AAAAAAAAAAAAAAAAAAAAAA==\"","\"1-1-1-1-1\"","\" fbaedcba-0123-4567-89ab-0123456789ab\"","1","true","{}","[]"))
            assertThrows(RuntimeException.class,()->json.read("{\"id\":"+invalid+"}",Identifier.class));
    }
    @Test void textualFieldsCannotBeCoercedFromNumbersOrBooleans() {
        for(String value:java.util.List.of("1","1.5","true"))assertThrows(RuntimeException.class,()->json.read("{\"note\":"+value+"}",Text.class));
    }
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    @Test void duplicateKeysAreRejectedBeforeTheyCanAlterAuthority() {
        assertThrows(RuntimeException.class,()->json.map("{\"customerId\":\"customer-101\",\"customerId\":\"customer-102\"}"));
    }
    @Test void unknownFieldsTrailingValuesAndNullPrimitivesAreRejected() {
        assertThrows(RuntimeException.class,()->json.read("{\"amountKrw\":1,\"role\":\"LOAN_REVIEWER\"}",Amount.class));
        assertThrows(RuntimeException.class,()->json.read("{\"amountKrw\":1} {}",Amount.class));
        assertThrows(RuntimeException.class,()->json.read("{\"amountKrw\":null}",Amount.class));
    }
    @Test void moneyCannotBeRoundedOrCoercedFromAString() {
        assertThrows(RuntimeException.class,()->json.read("{\"amountKrw\":1000000.5}",Amount.class));
        assertThrows(RuntimeException.class,()->json.read("{\"amountKrw\":\"1000000\"}",Amount.class));
        assertEquals(1000000L,json.read("{\"amountKrw\":1000000}",Amount.class).amountKrw());
    }
    @Test void canonicalEncodingRetainsExplicitOrderUtf8AndNoWhitespace() {
        var value=Json.ordered("customerId","customer-102","evidenceType","ID_DOC","issuerId","mock-id-issuer","outcome","PASS","issuedAt","2026-10-09T03:55:00Z","expiresAt","2026-10-09T04:30:00Z");
        assertEquals("{\"customerId\":\"customer-102\",\"evidenceType\":\"ID_DOC\",\"issuerId\":\"mock-id-issuer\",\"outcome\":\"PASS\",\"issuedAt\":\"2026-10-09T03:55:00Z\",\"expiresAt\":\"2026-10-09T04:30:00Z\"}",json.write(value));
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",Json.sha256(new byte[0]));
        assertArrayEquals("{\"note\":\"확인\"}".getBytes(StandardCharsets.UTF_8),json.bytes(Json.ordered("note","확인")));
    }
    @Test void onlyTheVersionedPolicySuppliesRiskNumbers() throws Exception {
        FusePolicy policy=new JsonConfiguration().fusePolicy(new JsonConfiguration().jsonMapper());
        assertEquals(35,policy.kycRisk()+policy.loanRisk());
        assertEquals(40,policy.automaticRiskLimit());
        assertEquals(85,policy.approvedRiskLimit());
        assertEquals(policy.approvedRiskLimit(),policy.kycRisk()+policy.loanRisk()+policy.paymentRisk());
        assertEquals(java.util.List.of("PAYMENT"),policy.allowedEdges().get("LOAN"));
    }
}
