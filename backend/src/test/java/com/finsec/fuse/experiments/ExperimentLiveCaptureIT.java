package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.config.PrivateDocuments;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.testing.PostgresSupport;
import com.finsec.fuse.workflow.KycContract;
import java.util.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import static org.junit.jupiter.api.Assertions.*;

/** Real disposable PostgreSQL arms, fake capture gateway: no provider network or real credentials. */
class ExperimentLiveCaptureIT {
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private final ExperimentSandbox.Database database=new ExperimentSandbox.Database(PostgresSupport.url(),"postgres","");
    @TempDir Path directory;
    private PrivateDocuments privateDocuments() throws Exception {
        Path path=directory.resolve("documents.json");
        Files.writeString(path,json.write(Map.of("seed-v1","opaque-seed-01","seed-v2","opaque-seed-02","rag-01","opaque-rag-01")));
        return new PrivateDocuments(json,new MockEnvironment().withProperty("FUSE_PRIVATE_DOCUMENTS_PATH",path.toString()));
    }
    @Test void oneCapturedCandidateIsAppliedToTwoRealIsolatedArmsWithActualMetadata() throws Exception {
        var documents=privateDocuments();
        var selection=new ExperimentRegistry(json).select("mvp-security-v1",List.of("T02_MISSING_EVIDENCE"));
        var fixture=selection.cases().getFirst();var calls=new AtomicInteger();var schemas=new HashSet<String>();
        var runner=new ExperimentPairRunner(json,input->{
            assertFalse(TransactionSynchronizationManager.isActualTransactionActive(),"Model calls must never hold database transactions");
            assertEquals("customer-101",input.customerId());assertTrue(input.evidenceFacts().isEmpty());assertEquals(1,input.documents().size());
            assertEquals("opaque-seed-02",input.documents().getFirst().text());
            assertEquals(json.hash(input.unhashed()),input.inputSnapshotHash());
            calls.incrementAndGet();
            var candidate=json.read(json.write(fixture.get("modelOutput")),KycContract.Proposal.class);
            var response=new KycContract.Response(input.requestId(),input.workflowId(),1,input.runId(),input.inputSnapshotHash(),candidate,new KycContract.ModelMetadata("fake-resolved-model","KYC-PROMPT-1"));
            return new ExperimentModelCapture(response,"LIVE","c".repeat(64),json.hash(ExperimentRegistry.sorted(json.map(json.write(candidate)))));
        },(f,live)->{try(var sandbox=ExperimentSandbox.open(database,false)){schemas.add(sandbox.schema());return new ExperimentScenario(sandbox,false,documents).preparePairedInput(f,live);}},
        (f,h,r,b)->{try(var sandbox=ExperimentSandbox.open(database,b)){
            schemas.add(sandbox.schema());var output=new ExperimentScenario(sandbox,b).run(f,h,r);
            var result=sandbox.bean(Db.class).required("SELECT body_json FROM agent_result WHERE body_json->>'status'='VERIFIED'");
            assertTrue(result.get("body_json").toString().contains("fake-resolved-model"));return output;
        }});
        var rows=runner.run(fixture,selection.hash(),1,ExperimentRequest.ModelMode.LIVE);
        assertEquals(1,calls.get());assertEquals(3,schemas.size());
        assertEquals("PAID",rows.getFirst().get("state"));assertEquals("BLOCKED",rows.getLast().get("state"));
        assertEquals(rows.getFirst().get("modelOutputHash"),rows.getLast().get("modelOutputHash"));
        assertEquals(rows.getFirst().get("pairedInputHash"),rows.getLast().get("pairedInputHash"));
        assertNotEquals(rows.getFirst().get("inputSnapshotHash"),rows.getLast().get("inputSnapshotHash"));
        assertNotEquals(rows.getFirst().get("responseByteHash"),rows.getLast().get("responseByteHash"));
        assertTrue(rows.stream().allMatch(row->row.get("exclusionReason")==null));
        assertEquals("fake-resolved-model",rows.getFirst().get("model"));assertEquals("fake-resolved-model",rows.getLast().get("model"));
        var metrics=ExperimentMetrics.calculate(selection,rows,1,"LIVE");assertEquals(1,metrics.get("commonEligibleAttackPairs"));
    }
    @Test void inputUsesAuthoritativeCustomerFactsAndPrivateDocumentBytes() throws Exception {
        var documents=privateDocuments();
        var selection=new ExperimentRegistry(json).select("mvp-security-v1",List.of("T01_NORMAL_PAYMENT","T03_WRONG_CUSTOMER_EVIDENCE"));
        for(var fixture:selection.cases())try(var sandbox=ExperimentSandbox.open(database,false)){
            var input=new ExperimentScenario(sandbox,false,documents).prepareCaptureInput(fixture);
            assertEquals(fixture.get("customerId"),input.customerId());
            assertEquals("T01_NORMAL_PAYMENT".equals(fixture.get("caseId"))?2:0,input.evidenceFacts().size());
            var document=input.documents().getFirst();assertEquals(document.contentHash(),Json.sha256(document.text().getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            assertEquals("opaque-seed-"+("1".equals(fixture.get("documentVersion").toString())?"01":"02"),document.text());
            for(var fact:input.evidenceFacts())assertTrue(fact.evidenceId().toString().contains("00102"));
        }
    }
    @Test void ragCaptureResolvesPrivateTextAndMissingAssetsFailBeforeModelOrWorkflow() throws Exception {
        var fixture=new ExperimentRegistry(json).select("security-evaluation-v1",List.of("A_RAG_POISONING_01")).cases().getFirst();
        try(var sandbox=ExperimentSandbox.open(database,false)) {
            var documents=privateDocuments();var input=new ExperimentScenario(sandbox,false,documents).prepareCaptureInput(fixture);
            assertEquals("opaque-rag-01",input.documents().getFirst().text());
            assertEquals(json.hash(input.unhashed()),input.inputSnapshotHash());
        }
        try(var sandbox=ExperimentSandbox.open(database,false)) {
            var missing=new PrivateDocuments(json,new MockEnvironment());
            assertThrows(PrivateDocuments.Unavailable.class,()->new ExperimentScenario(sandbox,false,missing).prepareCaptureInput(fixture));
            assertEquals(0,Db.integer(sandbox.bean(Db.class).required("SELECT count(*) AS n FROM workflow"),"n"));
            assertEquals("FUSE_DOCUMENT_ID:seed-v1",Db.string(sandbox.bean(Db.class).required("SELECT content FROM source_document_version WHERE version=1"),"content"));
        }
    }
}
