package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.persistence.*;
import java.util.*;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.Status;
import static org.junit.jupiter.api.Assertions.*;

/** Real virtual services, synthetic facts, public trace only. SOURCE_ONLY / NOT_RUN. */
final class VirtualTypedWorkflowTraceProjectionTest {
    static final Set<String> ARRAYS=Set.of("runs","results","grants","dependencies","approvals","riskEvents","payments","auditEvents");
    static final Set<String> RESULT_KEYS=Set.of("resultId","runId","workflowId","generation","bindingProfile","bindingDigest");
    static final Set<String> GRANT_KEYS=Set.of("grantId","actionId","targetRunId","workflowId","generation","action","state","status");
    static final Set<String> EDGE_KEYS=Set.of("parentRunId","childRunId","parentResultId","generation");
    @SuppressWarnings("unchecked") static List<Map<String,Object>> rows(Map<String,Object> trace,String key) {
        assertInstanceOf(List.class,trace.get(key));var result=(List<?>)trace.get(key);
        for(var row:result)assertInstanceOf(Map.class,row);
        return (List<Map<String,Object>>)trace.get(key);
    }
    static VirtualWorkflowService reader(VirtualGrantContinuationFixture f,SimulationAccess access) {
        return new VirtualWorkflowService(f.store,f.continuationCatalog,f.terms,access,f.seed.f.clock,f.seed.f::id);
    }
    static VirtualWorkflowService reader(VirtualGrantContinuationFixture f) {
        return reader(f,new SimulationAccess((actor,operation,workflow,customer)->f.seed.f.permitted.get()));
    }
    static Map<String,Object> trace(VirtualGrantContinuationFixture f) {
        return reader(f).trace(SimulationFixture.ACTOR,f.scope(1).workflowId());
    }
    static void envelope(Map<String,Object> trace,VirtualGrantContinuationFixture f,int generation) {
        assertEquals(f.scope(1).workflowId().toString(),trace.get("workflowId"));
        assertEquals(Integer.class,trace.get("generation").getClass());assertEquals(generation,trace.get("generation"));
        for(String key:ARRAYS)rows(trace,key);
        var keys=new HashSet<>(ARRAYS);keys.addAll(Set.of("workflowId","generation","sourceUses","executionMode","cryptographicAuthorityImplemented"));
        assertEquals(keys,trace.keySet());
        assertEquals(VirtualTransactionalStore.MODE,trace.get("executionMode"));
        assertEquals(false,trace.get("cryptographicAuthorityImplemented"));
    }
    static void noLegacyResults(VirtualGrantContinuationFixture f) {
        assertTrue(f.store.snapshot().getOrDefault("virtual_results",Map.of()).isEmpty());
        assertTrue(f.store.snapshot().getOrDefault("virtual_runs",Map.of()).isEmpty());
    }
    static void consume(VirtualGrantContinuationFixture f,int generation,long request) {
        var prepared=f.prepareCurrent();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,prepared.status());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,f.consume(generation,prepared.receipt().inputSnapshotHash(),request).status());
    }
    static Map<String,Object> byId(List<Map<String,Object>> rows,String key,UUID id) {
        var found=rows.stream().filter(r->id.toString().equals(r.get(key))).toList();
        assertEquals(1,found.size());return found.get(0);
    }
    @Test void inertRootIsGrantMetadataAndNeverAStartedProviderRunOrInventedResultEdge() {
        var f=new VirtualGrantContinuationFixture();var before=f.store.snapshot();var out=trace(f);envelope(out,f,1);
        var grant=byId(rows(out,"grants"),"grantId",f.oldRootCommand.identity().grantId());
        assertEquals(GRANT_KEYS,grant.keySet());assertEquals("ISSUED",grant.get("state"));assertEquals(grant.get("state"),grant.get("status"));
        assertTrue(rows(out,"runs").isEmpty());assertTrue(rows(out,"results").isEmpty());assertTrue(rows(out,"dependencies").isEmpty());
        assertTrue(rows(out,"payments").isEmpty());assertEquals(before,f.store.snapshot());
    }
    @Test void actualKycCompletionAppearsWithoutLegacyResultRowsAndOnlyClosedMetadata() {
        var f=new VirtualGrantContinuationFixture();consume(f,1,7201);noLegacyResults(f);
        var workflow=f.workflow();var before=f.store.snapshot();var out=trace(f);envelope(out,f,1);
        UUID result=UUID.fromString((String)workflow.get("currentKycResultId"));
        var projected=byId(rows(out,"results"),"resultId",result);
        assertEquals(RESULT_KEYS,projected.keySet());assertEquals(f.oldRootCommand.identity().targetRunId().toString(),projected.get("runId"));
        assertEquals(1,projected.get("generation"));assertEquals("AGENT_RESULT_BINDING_RECORD_1",projected.get("bindingProfile"));
        assertInstanceOf(String.class,projected.get("bindingDigest"));assertFalse(((String)projected.get("bindingDigest")).isBlank());
        assertTrue(rows(out,"runs").isEmpty());assertEquals(before,f.store.snapshot());
    }
    @Test void actualGenerationTwoKycRetainsBothOwnGenerationResultsWithoutCrossRootDependency() {
        var f=new VirtualGrantContinuationFixture();consume(f,1,7201);
        UUID oldResult=UUID.fromString((String)f.workflow().get("currentKycResultId"));
        f.blockAndRelease();var command=f.firstCommand();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,f.advance(command).status());
        consume(f,2,7202);noLegacyResults(f);
        UUID currentResult=UUID.fromString((String)f.workflow().get("currentKycResultId"));
        var before=f.store.snapshot();var out=trace(f);envelope(out,f,2);
        assertEquals(1,byId(rows(out,"results"),"resultId",oldResult).get("generation"));
        assertEquals(2,byId(rows(out,"results"),"resultId",currentResult).get("generation"));
        assertEquals(1,byId(rows(out,"grants"),"grantId",f.oldRootCommand.identity().grantId()).get("generation"));
        assertEquals(2,byId(rows(out,"grants"),"grantId",command.identity().grantId()).get("generation"));
        assertTrue(rows(out,"dependencies").isEmpty());assertTrue(rows(out,"runs").isEmpty());
        assertEquals(List.of(1,2),rows(out,"results").stream().map(r->r.get("generation")).toList());
        assertEquals(before,f.store.snapshot());
    }
    @Test void actualConsumedParentRelationProducesOnlyItsRecordedDependency() {
        var f=new VirtualGrantEvaluationRefusalBoundaryTest.Fixture(3);
        // Fixture has an actually consumed parent and a positively recorded child ISSUANCE;
        // no child execution/result is needed to record that existing dependency.
        var issued=f.seed.f.workflows.trace(SimulationFixture.ACTOR,f.root.identity().workflowId());
        assertTrue(rows(issued,"results").stream().noneMatch(r->f.loan.identity().targetRunId().toString().equals(r.get("runId"))));
        var issuedEdges=rows(issued,"dependencies");assertEquals(1,issuedEdges.size());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,f.evaluateLoan().status());
        assertTrue(f.seed.f.store.snapshot().getOrDefault("virtual_results",Map.of()).isEmpty());
        var out=f.seed.f.workflows.trace(SimulationFixture.ACTOR,f.root.identity().workflowId());
        assertEquals(issuedEdges,rows(out,"dependencies"));
        var edge=rows(out,"dependencies").stream().filter(r->f.loan.identity().targetRunId().toString().equals(r.get("childRunId"))).toList();
        assertEquals(1,edge.size());assertEquals(EDGE_KEYS,edge.get(0).keySet());
        assertEquals(f.root.identity().targetRunId().toString(),edge.get(0).get("parentRunId"));
        assertEquals(VirtualGrantEvaluationRefusalBoundaryTest.id(1600).toString(),edge.get(0).get("parentResultId"));
        assertEquals(1,edge.get(0).get("generation"));assertTrue(rows(out,"runs").isEmpty());
    }
    static final class WatchedStore implements TransactionalStore {
        final VirtualTransactionalStore delegate=new VirtualTransactionalStore();boolean watch;int typedReads,writes;
        public String mode(){return delegate.mode();}
        public Map<String,Map<String,Map<String,Object>>> snapshot(){return delegate.snapshot();}
        public <T>T transaction(Function<Tx,T> work){return delegate.transaction(tx->work.apply(new Tx(){
            void read(String table){if(watch&&table.startsWith("virtual_grant_profile_"))typedReads++;}
            public Map<String,Object> get(String table,String key){read(table);return tx.get(table,key);}
            public Map<String,Map<String,Object>> rows(String table){read(table);return tx.rows(table);}
            public void put(String table,String key,Map<String,Object> row){if(watch)writes++;tx.put(table,key,row);}
        }));}
    }
    @Test void deniedPublicReadOccursBeforeAnyTypedMetadataAccessOrWrite() {
        var watched=new WatchedStore();var f=new VirtualGrantContinuationFixture(watched);var before=watched.snapshot();
        watched.watch=true;var denied=reader(f,new SimulationAccess((actor,operation,workflow,customer)->false));
        var error=assertThrows(SimulationFailure.class,()->denied.trace(SimulationFixture.ACTOR,f.scope(1).workflowId()));
        assertEquals(403,error.status());assertEquals(0,watched.typedReads);assertEquals(0,watched.writes);assertEquals(before,watched.snapshot());
    }
    @Test void legacyOnlyTraceRetainsExistingResultRowsAndEmptyGrantContract() {
        var f=new SimulationFixture();UUID workflow=f.ready();var before=f.store.snapshot();
        var out=f.workflows.trace(SimulationFixture.ACTOR,workflow);
        assertEquals(workflow.toString(),out.get("workflowId"));assertEquals(1,out.get("generation"));
        assertFalse(rows(out,"results").isEmpty());assertFalse(rows(out,"runs").isEmpty());
        assertTrue(rows(out,"grants").isEmpty());for(String key:ARRAYS)rows(out,key);
        var stored=before.get("virtual_results").values().stream().filter(r->workflow.toString().equals(r.get("workflowId"))).toList();
        assertEquals(stored,rows(out,"results"));assertEquals(before,f.store.snapshot());
    }
    @Test void typedMetadataCannotExposeOpaqueBodyFramesTokensOrInferSelectedEvidence() {
        var f=new VirtualGrantContinuationFixture();consume(f,1,7201);var out=trace(f);
        for(var row:rows(out,"results")){assertEquals(RESULT_KEYS,row.keySet());assertEquals(Integer.class,row.get("generation").getClass());}
        for(var row:rows(out,"grants")){assertEquals(GRANT_KEYS,row.keySet());assertEquals(Integer.class,row.get("generation").getClass());}
        for(var row:rows(out,"dependencies"))assertEquals(EDGE_KEYS,row.keySet());
        assertFalse(rows(out,"sourceUses").isEmpty());
        for(var row:rows(out,"sourceUses"))assertEquals(Set.of("runId","documentId","documentVersion","contentHash"),row.keySet());
        assertFalse(rows(out,"riskEvents").isEmpty());
        for(var row:rows(out,"riskEvents"))assertEquals(Set.of("riskEventId","workflowId","generation","eventType","stage","points","runId","policyVersion"),row.keySet());
        assertTrue(rows(out,"payments").isEmpty());assertTrue(rows(out,"approvals").isEmpty());
        assertTrue(rows(out,"auditEvents").isEmpty()); // no stored generic root/stage event timestamp is invented
        assertFalse(out.containsKey("evidenceUses"));assertFalse(out.containsKey("evidenceCheckedAt"));
        assertThrows(UnsupportedOperationException.class,()->rows(out,"results").clear());
        assertThrows(UnsupportedOperationException.class,()->rows(out,"grants").get(0).put("body","synthetic-forbidden"));
        for(String key:List.of("results","grants","dependencies"))for(var row:rows(out,key))
            for(String forbidden:List.of("body","bindingBytes","frame","token","leaseToken","canonicalBytes","businessConclusion","evidenceIds"))assertFalse(row.containsKey(forbidden));
    }
    @Test void successfulTypedTraceActuallyReadsOwnedMetadataWithoutReadTimeWrites() {
        var watched=new WatchedStore();var f=new VirtualGrantContinuationFixture(watched);consume(f,1,7201);
        var before=watched.snapshot();watched.watch=true;var out=trace(f);
        assertFalse(rows(out,"results").isEmpty());assertTrue(watched.typedReads>0);
        assertEquals(0,watched.writes);assertEquals(before,watched.snapshot());
    }

}
