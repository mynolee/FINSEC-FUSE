package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.simulation.VirtualGrantContinuationFixture.id;
import static org.junit.jupiter.api.Assertions.*;

/** Public containment metadata is distinct from business admission and historical artifact reuse. */
final class VirtualTypedWorkflowReadQuarantineTest {
    private static final Set<String> RESPONSE_FIELDS=Set.of("workflowId","generation","state","businessReference","customerId",
            "amountKrw","payoutAccountId","usedRisk","reservedRisk","riskLimit","kycRuns","currentKycResultId","currentLoanResultId",
            "reasonCodes","lastDecision","policyVersion","activeJob","activeQuarantines","canApprove","canResume","executionMode");
    static final class ObservedStore implements TransactionalStore {
        final VirtualTransactionalStore delegate=new VirtualTransactionalStore();
        int puts;
        public String mode(){return delegate.mode();}
        public Map<String,Map<String,Map<String,Object>>> snapshot(){return delegate.snapshot();}
        public <R> R transaction(Function<Tx,R> work){
            return delegate.transaction(tx->work.apply(new Tx(){
                public Map<String,Object> get(String table,String key){return tx.get(table,key);}
                public Map<String,Map<String,Object>> rows(String table){return tx.rows(table);}
                public void put(String table,String key,Map<String,Object> row){puts++;tx.put(table,key,row);}
            }));
        }
    }
    private static VirtualWorkflowService reader(VirtualGrantContinuationFixture f,SimulationSpec.Catalog catalog){
        var access=new SimulationAccess((actor,operation,workflow,customer)->f.seed.f.permitted.get());
        return new VirtualWorkflowService(f.store,catalog,f.terms,access,f.seed.f.clock,f.seed.f::id);
    }
    @SuppressWarnings("unchecked")
    private static Map<String,Object> observe(VirtualGrantContinuationFixture f,ObservedStore store,SimulationSpec.Catalog catalog){
        var before=store.snapshot();int writes=store.puts;var service=reader(f,catalog);
        var detail=service.get(SimulationFixture.ACTOR,id(1));
        var page=service.list(SimulationFixture.ACTOR,0,10);
        assertEquals(1,page.get("total"));assertInstanceOf(List.class,page.get("items"));
        var items=(List<?>)page.get("items");assertEquals(1,items.size());assertInstanceOf(Map.class,items.get(0));
        assertEquals(detail,(Map<String,Object>)items.get(0));
        assertEquals(RESPONSE_FIELDS,detail.keySet());
        assertEquals(id(1).toString(),detail.get("workflowId"));assertNull(detail.get("activeJob"));
        assertEquals(Boolean.FALSE,detail.get("canApprove"));assertInstanceOf(Boolean.class,detail.get("canResume"));
        assertInstanceOf(List.class,detail.get("activeQuarantines"));
        for(String key:List.of("body","result","currentKycResult","currentLoanResult","canonicalBytes","receiptDigest",
                "typedStageAgents","claimsBytes","actionBytes","unsignedRootMaterial","inputSnapshotHash"))
            assertFalse(detail.containsKey(key));
        var encoded=CanonicalJson.write(detail);
        assertFalse(encoded.contains(f.seed.f.source.text()));assertFalse(encoded.contains(f.newApplication.source().text()));
        assertFalse(encoded.contains("AGENT_RESULT_BINDING_RECORD_1"));
        assertEquals(writes,store.puts);assertEquals(before,store.snapshot());
        return detail;
    }
    private static void summary(Map<String,Object> view,UUID quarantine,boolean present){
        assertEquals(present,((List<?>)view.get("activeQuarantines")).contains(quarantine.toString()));
    }
    private static VirtualGrantContinuationFixture fixture(ObservedStore store){
        var f=new VirtualGrantContinuationFixture(store);
        assertEquals("KYC_PENDING",f.workflow().get("state"));assertEquals(1,f.workflow().get("generation"));
        var initial=observe(f,store,f.seed.f.catalog);
        assertTrue(((List<?>)initial.get("activeQuarantines")).isEmpty());assertEquals(Boolean.FALSE,initial.get("canResume"));
        return f;
    }
    @Test void activeWorkflowContainmentIsReadableAndReleaseClearsSummaryWithoutEnablingLegacyActions(){
        var store=new ObservedStore();var f=fixture(store);
        var quarantine=f.hold(new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.WORKFLOW,
                Map.of("workflowId",id(1).toString())));
        var held=observe(f,store,f.seed.f.catalog);summary(held,quarantine,true);assertEquals("BLOCKED",held.get("state"));
        assertEquals(Boolean.FALSE,held.get("canResume"));
        f.release(quarantine);
        assertEquals("RELEASED",store.snapshot().get("virtual_quarantines").get(quarantine.toString()).get("status"));
        var released=observe(f,store,f.seed.f.catalog);summary(released,quarantine,false);
        assertEquals("BLOCKED",released.get("state"));assertEquals(1,released.get("generation"));
        // Readiness metadata is not permission to execute a legacy resume or approve business work.
        assertEquals(Boolean.TRUE,released.get("canResume"));
    }
    @Test void currentSourceContainmentIsReportedAndSupportedRemediationDoesNotRewriteOriginalRoot(){
        var store=new ObservedStore();var f=fixture(store);
        var source=f.seed.f.source;
        var quarantine=f.hold(new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.SOURCE_VERSION,
                Map.of("documentId",source.documentId().toString(),"documentVersion",source.documentVersion())));
        var held=observe(f,store,f.seed.f.catalog);summary(held,quarantine,true);
        assertEquals(Boolean.FALSE,held.get("canResume"));
        var material=store.snapshot().get("virtual_grant_profile_root_material");assertNotNull(material);
        f.release(quarantine);
        assertEquals(material,store.snapshot().get("virtual_grant_profile_root_material"));
        assertEquals(2,f.workflow().get("documentVersion"));
        var released=observe(f,store,f.seed.f.catalog);summary(released,quarantine,false);
        assertEquals(1,released.get("generation"));assertEquals("BLOCKED",released.get("state"));
        assertEquals(Boolean.TRUE,released.get("canResume"));
    }
    @Test void currentAgentContainmentRemainsReadableWhenItsReleaseMechanismIsUnavailable(){
        var store=new ObservedStore();var f=fixture(store);
        var kyc=f.oldRootCommand.workflowPlan().stageAgents().get(com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction.EVALUATE_KYC);
        var quarantine=f.hold(new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.AGENT_VERSION,
                Map.of("agentId",kyc.agentId(),"agentVersion",kyc.version())));
        var held=observe(f,store,f.seed.f.catalog);summary(held,quarantine,true);
        assertEquals(Boolean.FALSE,held.get("canResume"));
        var before=store.snapshot();var failure=assertThrows(SimulationFailure.class,()->f.release(quarantine));
        assertEquals(503,failure.status());assertEquals(before,store.snapshot());
        assertEquals("ACTIVE",store.snapshot().get("virtual_quarantines").get(quarantine.toString()).get("status"));
        var stillHeld=observe(f,store,f.seed.f.catalog);summary(stillHeld,quarantine,true);
        assertEquals(Boolean.FALSE,stillHeld.get("canResume"));
    }
    private static void unusedOldArtifactDoesNotBecomeCurrentSummary(VirtualQuarantineService.Scope kind){
        var store=new ObservedStore();var f=fixture(store);
        var prepared=f.prepareCurrent();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,prepared.status());assertNotNull(prepared.receipt());
        var consumed=f.consume(1,prepared.receipt().inputSnapshotHash(),8201);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,consumed.status());assertNotNull(consumed.receipt());assertNotNull(consumed.receipt().result());
        observe(f,store,f.seed.f.catalog);
        var target=kind==VirtualQuarantineService.Scope.RUN
                ?Map.<String,Object>of("runId",f.oldRootCommand.identity().targetRunId().toString())
                :Map.<String,Object>of("resultId",consumed.receipt().result().resultId().toString());
        var quarantine=f.hold(new VirtualQuarantineService.Target(kind,target));
        var held=observe(f,store,f.continuationCatalog);summary(held,quarantine,true);
        assertEquals("BLOCKED",held.get("state"));
        assertEquals(1,held.get("kycRuns"));assertEquals(0,held.get("reservedRisk"));assertNull(held.get("activeJob"));
        assertEquals(Boolean.TRUE,held.get("canResume"));
        var advanced=f.advance(f.firstCommand());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,advanced.status());assertNotNull(advanced.receipt());
        assertEquals(2,advanced.receipt().committedGeneration());
        var current=observe(f,store,f.continuationCatalog);summary(current,quarantine,false);
        assertEquals("KYC_PENDING",current.get("state"));assertEquals(2,current.get("generation"));
        assertEquals(Boolean.FALSE,current.get("canResume"));
        assertNull(current.get("currentKycResultId"));assertNull(current.get("currentLoanResultId"));
        var old=store.snapshot().get("virtual_quarantines").get(quarantine.toString());
        assertEquals("ACTIVE",old.get("status"));assertEquals(kind.name(),old.get("scope"));assertEquals(target,old.get("target"));
    }
    @Test void unusedOldRunHoldIsNotInheritedByIndependentNewGenerationReadSummary(){
        unusedOldArtifactDoesNotBecomeCurrentSummary(VirtualQuarantineService.Scope.RUN);
    }
    @Test void unusedOldResultHoldIsNotInheritedByIndependentNewGenerationReadSummary(){
        unusedOldArtifactDoesNotBecomeCurrentSummary(VirtualQuarantineService.Scope.RESULT);
    }
}
