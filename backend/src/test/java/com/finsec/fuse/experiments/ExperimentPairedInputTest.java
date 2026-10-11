package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.workflow.KycContract;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ExperimentPairedInputTest {
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private final String fixtureHash="a".repeat(64);
    private Map<String,Object> fixture(){return Json.ordered("caseId","synthetic-provenance-test","customerId","customer-102",
        "amountKrw",1000000,"injection",Map.of("operation","none","parameters",Map.of()),"modelOutput",Map.of("status","VERIFIED"));}
    private KycContract.Input input(String text,String outcome) {
        var initial=new KycContract.Input(UUID.randomUUID(),UUID.randomUUID(),1,UUID.randomUUID(),"customer-102","FUSE-MVP-2",null,
            List.of(new KycContract.EvidenceFact(UUID.fromString("00000000-0000-4000-8000-000000001021"),"ID_DOC",outcome)),
            List.of(new KycContract.Document(UUID.fromString("00000000-0000-4000-8000-000000000201"),1,Json.sha256(text.getBytes(StandardCharsets.UTF_8)),text)));
        return initial.withHash(json.hash(initial.unhashed()));
    }
    private String hash(KycContract.Input input,Map<String,Object> business,String model,String prompt,String promptHash){
        return ExperimentPairedInput.hash(json,fixture(),fixtureHash,new ExperimentPairedInput.Prepared(input,business),"LIVE",model,prompt,promptHash);
    }
    @Test void differentTransportIdsShareOnlyComparisonHashAndKeepTheirOwnByteBindings() {
        var first=input("opaque-test-content","PASS");var second=input("opaque-test-content","PASS");
        assertNotEquals(first.inputSnapshotHash(),second.inputSnapshotHash());
        assertEquals(hash(first,Map.of("amount",1),"model","KYC-PROMPT-1","b".repeat(64)),hash(second,Map.of("amount",1),"model","KYC-PROMPT-1","b".repeat(64)));
        var proposal=new KycContract.Proposal(KycContract.ProposalStatus.VERIFIED,List.of(),"Synthetic test");
        var a=binding(first,proposal);var b=binding(second,proposal);
        assertNotEquals(a.responseByteHash(),b.responseByteHash());
        assertNotEquals(a.requestByteHash(),b.requestByteHash());
        assertEquals(a.inputSnapshotHash(),Json.sha256(a.inputBytes()));
        assertEquals(a.responseByteHash(),Json.sha256(a.responseBytes()));
        assertTrue(json.read(a.responseBytes(),KycContract.Response.class).boundTo(first));
        assertFalse(json.read(a.responseBytes(),KycContract.Response.class).boundTo(second));
        assertFalse(json.write(a.trace()).contains("opaque-test-content"));
    }
    private ExperimentArmBinding binding(KycContract.Input input,KycContract.Proposal proposal) {
        return ExperimentArmBinding.capture(json,input,new KycContract.Response(input.requestId(),input.workflowId(),input.generation(),input.runId(),input.inputSnapshotHash(),proposal,new KycContract.ModelMetadata("model","KYC-PROMPT-1")));
    }
    @Test void businessEvidenceDocumentAndModelPromptChangesChangeComparisonDigest() {
        var source=input("opaque-test-content","PASS");String expected=hash(source,Map.of("amount",1),"model","KYC-PROMPT-1","b".repeat(64));
        assertNotEquals(expected,hash(source,Map.of("amount",2),"model","KYC-PROMPT-1","b".repeat(64)));
        assertNotEquals(expected,hash(input("other-opaque-content","PASS"),Map.of("amount",1),"model","KYC-PROMPT-1","b".repeat(64)));
        assertNotEquals(expected,hash(input("opaque-test-content","FAIL"),Map.of("amount",1),"model","KYC-PROMPT-1","b".repeat(64)));
        assertNotEquals(expected,hash(source,Map.of("amount",1),"other-model","KYC-PROMPT-1","b".repeat(64)));
        assertNotEquals(expected,hash(source,Map.of("amount",1),"model","other-prompt","b".repeat(64)));
        assertNotEquals(expected,hash(source,Map.of("amount",1),"model","KYC-PROMPT-1","c".repeat(64)));
    }
    @Test void ignoresSuppliedDigestAndRuntimeIdsButBindsRegisteredFixtureConditions() {
        var input=input("opaque-test-content","PASS");var prepared=new ExperimentPairedInput.Prepared(input,Map.of());
        var original=fixture();String hash=ExperimentPairedInput.hash(json,original,fixtureHash,prepared,"REPLAY","replay","KYC-PROMPT-1",null);
        var changed=new LinkedHashMap<>(original);changed.put("pairedInputHash","0".repeat(64));changed.put("workflowId",UUID.randomUUID());changed.put("modelOutput",Map.of("status","NEEDS_REVIEW"));
        assertEquals(hash,ExperimentPairedInput.hash(json,changed,fixtureHash,prepared,"REPLAY","replay","KYC-PROMPT-1",null));
        changed.put("amountKrw",2);
        assertNotEquals(hash,ExperimentPairedInput.hash(json,changed,fixtureHash,prepared,"REPLAY","replay","KYC-PROMPT-1",null));
    }
    @Test void canonicalMapOrderIsStableAndPrivateDocumentBodiesAreNotExported() {
        var input=input("opaque-test-content","PASS");
        assertEquals(hash(input,Json.ordered("z",2,"a",1),"model","KYC-PROMPT-1",null),hash(input,Json.ordered("a",1,"z",2),"model","KYC-PROMPT-1",null));
        var projected=ExperimentPairedInput.canonical(json,fixture(),fixtureHash,new ExperimentPairedInput.Prepared(input,Map.of()),"REPLAY","replay","KYC-PROMPT-1",null);
        assertFalse(json.write(projected).contains("opaque-test-content"));
        assertFalse(json.write(projected).contains(input.workflowId().toString()));
    }
    @Test void rejectsTamperedSnapshotAndDocumentHashesRatherThanTrustingThem() {
        var input=input("opaque-test-content","PASS");
        assertThrows(IllegalArgumentException.class,()->hash(input.withHash("0".repeat(64)),Map.of(),"model","KYC-PROMPT-1",null));
        var forged=new KycContract.Input(input.requestId(),input.workflowId(),1,input.runId(),input.customerId(),input.policyVersion(),null,input.evidenceFacts(),
            List.of(new KycContract.Document(input.documents().getFirst().documentId(),1,"0".repeat(64),"opaque-test-content")));
        assertThrows(IllegalArgumentException.class,()->hash(forged.withHash(json.hash(forged.unhashed())),Map.of(),"model","KYC-PROMPT-1",null));
    }
    @Test void canonicalProjectionMatchesIndependentPythonGoldenVector() throws Exception {
        var path=java.util.stream.Stream.of(java.nio.file.Path.of("../evaluation/tests/fixtures/paired-input-canonical.json"),
            java.nio.file.Path.of("evaluation/tests/fixtures/paired-input-canonical.json")).filter(java.nio.file.Files::isRegularFile).findFirst().orElseThrow();
        var vector=json.map(java.nio.file.Files.readAllBytes(path));
        assertEquals(vector.get("sha256"),hash(input("opaque-test-content","PASS"),Map.of("amount",1),"model","KYC-PROMPT-1","b".repeat(64)));
        assertEquals(vector.get("sha256"),json.hash(ExperimentRegistry.sorted(vector.get("canonical"))));
    }
}
