package com.finsec.fuse.policy;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import static org.junit.jupiter.api.Assertions.*;

class EvidenceChecksTest {
    private static final Instant NOW=Instant.parse("2026-10-09T04:00:00Z");
    private static final String CUSTOMER="customer-102";
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private final EvidenceChecks checks=new EvidenceChecks(Map.of("ID_DOC",Set.of("mock-id-issuer"),"FACE_MATCH",Set.of("mock-face-issuer")),json);
    private final UUID ID=UUID.fromString("00000000-0000-4000-8000-000000001021");
    private final UUID FACE=UUID.fromString("00000000-0000-4000-8000-000000001022");
    private Map<UUID,EvidenceRecord> registry;
    @BeforeEach void seed() { registry=new HashMap<>();registry.put(ID,evidence(ID,"ID_DOC","PASS"));registry.put(FACE,evidence(FACE,"FACE_MATCH","PASS")); }
    private EvidenceRecord evidence(UUID id,String kind,String outcome) {
        String issuer=kind.equals("ID_DOC")?"mock-id-issuer":"mock-face-issuer";
        var original=Json.ordered("customerId",CUSTOMER,"evidenceType",kind,"issuerId",issuer,"outcome",outcome,
                "issuedAt",NOW.minusSeconds(300).toString(),"expiresAt",NOW.plusSeconds(1800).toString());
        return new EvidenceRecord(id,CUSTOMER,kind,issuer,1,outcome,"ACTIVE",NOW.minusSeconds(300),NOW.plusSeconds(1800),null,original,json.hash(original));
    }
    private EvidenceDecision verify(List<UUID> proposed) { return checks.evaluate("VERIFIED",proposed,Set.of(ID,FACE),registry,CUSTOMER,NOW); }
    @ParameterizedTest @ValueSource(strings={"ID_DOC","FACE_MATCH"})
    void aDifferentKindsTrustedIssuerCannotAuthorizeEvenWithMatchingOriginalAndHash(String kind) {
        UUID id=kind.equals("ID_DOC")?ID:FACE;
        registry.put(id,crossIssued(id,kind,"PASS"));
        var result=verify(List.of(ID,FACE));
        assertEquals("EVIDENCE_INVALID",result.reasonCode());assertTrue(result.securityViolation());
    }
    @ParameterizedTest @ValueSource(strings={"ID_DOC","FACE_MATCH"})
    void crossIssuedFailCannotBecomeNormalBusinessRejection(String kind) {
        UUID id=kind.equals("ID_DOC")?ID:FACE;
        registry.put(id,crossIssued(id,kind,"FAIL"));
        var result=checks.evaluate("NOT_VERIFIED",List.of(ID,FACE),Set.of(ID,FACE),registry,CUSTOMER,NOW);
        assertEquals("ON_HOLD",result.state());assertEquals("EVIDENCE_MISSING",result.reasonCode());
        assertFalse(result.securityViolation());
    }
    private EvidenceRecord crossIssued(UUID id,String kind,String outcome) {
        var e=evidence(id,kind,outcome);String issuer=kind.equals("ID_DOC")?"mock-face-issuer":"mock-id-issuer";
        var original=new LinkedHashMap<>(e.original());original.put("issuerId",issuer);
        return new EvidenceRecord(id,e.customerId(),kind,issuer,e.version(),outcome,e.status(),e.issuedAt(),
                e.expiresAt(),e.revokedAt(),original,json.hash(original));
    }
    @Test void normalIndependentPairIsValidatedWithSortedStableBundle() {
        var result=verify(List.of(FACE,ID,FACE)); assertTrue(result.validated());assertFalse(result.securityViolation());
        assertEquals(List.of(ID,FACE),result.evidenceIds());
        assertEquals(verify(List.of(ID,FACE)).evidenceBundleHash(),result.evidenceBundleHash());
        assertEquals(json.hash(List.of(Json.ordered("id",ID.toString(),"version",1,"originalHash",registry.get(ID).originalHash()),
                Json.ordered("id",FACE.toString(),"version",1,"originalHash",registry.get(FACE).originalHash()))),result.evidenceBundleHash());
    }
    @Test void missingEvidenceBlocksFalseVerified() { assertEquals("EVIDENCE_MISSING",verify(List.of()).reasonCode());assertTrue(verify(List.of()).securityViolation()); }
    @Test void oneKindCannotSubstituteForFace() { assertEquals("EVIDENCE_MISSING",verify(List.of(ID)).reasonCode()); }
    @Test void proposalCannotChooseEvidenceNotSuppliedToRun() {
        var result=checks.evaluate("VERIFIED",List.of(ID,FACE),Set.of(ID),registry,CUSTOMER,NOW);
        assertEquals("EVIDENCE_INVALID",result.reasonCode());
    }
    @Test void anotherCustomersValidDocumentsCannotBeReused() {
        assertEquals("EVIDENCE_INVALID",checks.evaluate("VERIFIED",List.of(ID,FACE),Set.of(ID,FACE),registry,"customer-101",NOW).reasonCode());
    }
    @Test void missingRegistryRowDenies() { registry.remove(FACE);assertEquals("EVIDENCE_INVALID",verify(List.of(ID,FACE)).reasonCode()); }
    @ParameterizedTest @ValueSource(strings={"customer","type","issuer","outcome","status","version","future","expired","revoked","original","hash","extraField"})
    void rejectsEachIndependentInvalidField(String field) {
        var e=registry.get(FACE);var original=new LinkedHashMap<>(e.original());
        if(field.equals("original"))original.put("outcome","FAIL");
        if(field.equals("extraField"))original.put("approved",true);
        var bad=new EvidenceRecord(FACE,field.equals("customer")?"customer-101":e.customerId(),
                field.equals("type")?"RAG_DOCUMENT":e.evidenceType(),field.equals("issuer")?"model-self-issued":e.issuerId(),
                field.equals("version")?0:e.version(),field.equals("outcome")?"FAIL":e.outcome(),
                field.equals("status")?"REVOKED":e.status(),field.equals("future")?NOW.plusSeconds(1):e.issuedAt(),
                field.equals("expired")?NOW:e.expiresAt(),field.equals("revoked")?NOW:null,original,
                field.equals("hash")?"0".repeat(64):e.originalHash());
        registry.put(FACE,bad);assertEquals("EVIDENCE_INVALID",verify(List.of(ID,FACE)).reasonCode());
    }
    @Test void issueTimeIsInclusiveAndExpiryIsExclusive() {
        var e=registry.get(FACE);
        assertTrue(checks.evaluate("VERIFIED",List.of(ID,FACE),Set.of(ID,FACE),registry,CUSTOMER,e.issuedAt()).validated());
        assertFalse(checks.evaluate("VERIFIED",List.of(ID,FACE),Set.of(ID,FACE),registry,CUSTOMER,e.expiresAt()).validated());
    }
    @Test void normalFailRejectsWithoutSecurityQuarantine() {
        registry.put(FACE,evidence(FACE,"FACE_MATCH","FAIL"));
        var result=checks.evaluate("NOT_VERIFIED",List.of(ID,FACE),Set.of(ID,FACE),registry,CUSTOMER,NOW);
        assertEquals("REJECTED",result.state());assertFalse(result.securityViolation());
        assertEquals("EVIDENCE_INVALID",verify(List.of(ID,FACE)).reasonCode());
    }
    @Test void modelCannotInventBusinessFail() {
        var result=checks.evaluate("NOT_VERIFIED",List.of(),Set.of(ID,FACE),registry,CUSTOMER,NOW);
        assertEquals("ON_HOLD",result.state());assertFalse(result.securityViolation());
    }
    @Test void revokedFailDoesNotBecomeBusinessRejection() {
        registry.put(FACE,evidence(FACE,"FACE_MATCH","FAIL"));
        var result=checks.evaluate("NOT_VERIFIED",List.of(),Set.of(ID),registry,CUSTOMER,NOW);
        assertEquals("ON_HOLD",result.state());
    }
    @Test void needsReviewIsNotCountedAsPolicyBlock() {
        var result=checks.evaluate("NEEDS_REVIEW",List.of(),Set.of(),Map.of(),CUSTOMER,NOW);
        assertEquals("ON_HOLD",result.state());assertFalse(result.securityViolation());
    }
    @Test void malformedModelOutputIsErrorNotSecuritySuccess() {
        assertEquals("ERROR",checks.evaluate("FINAL_APPROVE",List.of(),Set.of(),Map.of(),CUSTOMER,NOW).decision());
        assertEquals("ERROR",checks.evaluate("VERIFIED",Collections.nCopies(11,ID),Set.of(ID),registry,CUSTOMER,NOW).decision());
        assertEquals("ERROR",checks.evaluate("VERIFIED",Arrays.asList(ID,null),Set.of(ID),registry,CUSTOMER,NOW).decision());
    }
}
