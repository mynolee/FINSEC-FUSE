package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static org.junit.jupiter.api.Assertions.*;

/** Public read contracts over actual synthetic root/preparation/result services, not caller-supplied result rows. */
class VirtualTypedWorkflowReadProjectionTest {
    static final class ObservedReadStore implements com.finsec.fuse.reimplementation.persistence.TransactionalStore {
        final com.finsec.fuse.reimplementation.persistence.TransactionalStore delegate;int puts;
        ObservedReadStore(com.finsec.fuse.reimplementation.persistence.TransactionalStore delegate){this.delegate=delegate;}
        public String mode(){return delegate.mode();}
        public Map<String,Map<String,Map<String,Object>>> snapshot(){return delegate.snapshot();}
        public <R> R transaction(java.util.function.Function<Tx,R> work){return delegate.transaction(tx->work.apply(new Tx(){
            public Map<String,Object> get(String table,String id){return tx.get(table,id);}
            public Map<String,Map<String,Object>> rows(String table){return tx.rows(table);}
            public void put(String table,String id,Map<String,Object> value){puts++;tx.put(table,id,value);}
        }));}
    }
    static final class Reads {
        final ObservedReadStore observed;final VirtualWorkflowService service;
        Reads(VirtualGrantContinuationFixture f,SimulationSpec.Catalog catalog,SimulationAccess.Authority authority){
            observed=new ObservedReadStore(f.store);service=new VirtualWorkflowService(observed,catalog,f.terms,new SimulationAccess(authority),f.seed.f.clock,f.seed.f::id);
        }
        Map<String,Object> get(WorkflowStartBoundary.ActorRef actor,UUID id){return service.get(actor,id);}
        Map<String,Object> list(WorkflowStartBoundary.ActorRef actor,int page,int size){return service.list(actor,page,size);}
        Map<String,Object> list(WorkflowStartBoundary.ActorRef actor,String state,int page,int size){return service.list(actor,state,page,size);}
        com.finsec.fuse.reimplementation.WorkflowHttpController.Receipt start(WorkflowStartBoundary.Command command){return service.start(command);}
    }
    static Reads reader(VirtualGrantContinuationFixture f,SimulationSpec.Catalog catalog,SimulationAccess.Authority authority){return new Reads(f,catalog,authority);}
    static VirtualGrantContinuationFixture completedKyc(){
        var f=new VirtualGrantContinuationFixture();var prep=f.prepareCurrent();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,prep.status());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,f.consume(1,prep.receipt().inputSnapshotHash(),8101).status());
        assertTrue(f.store.snapshot().getOrDefault("virtual_results",Map.of()).isEmpty(),"No legacy result fixture may hide the typed pointer boundary");
        return f;
    }
    static void typedSummary(Map<String,Object> dto,VirtualGrantContinuationFixture f){
        assertEquals(Set.of("workflowId","generation","state","businessReference","customerId","amountKrw","payoutAccountId","usedRisk","reservedRisk","riskLimit","kycRuns","currentKycResultId","currentLoanResultId","reasonCodes","lastDecision","policyVersion","activeJob","activeQuarantines","canApprove","canResume","executionMode"),dto.keySet());
        assertEquals(f.terms.baseLimit(),dto.get("riskLimit"));
        assertEquals(f.oldRootCommand.identity().workflowId().toString(),dto.get("workflowId"));assertEquals(1,dto.get("generation"));
        assertEquals(f.newApplication.customerId(),dto.get("customerId"));assertEquals(VirtualGrantContinuationFixture.id(90001).toString(),dto.get("currentKycResultId"));
        assertEquals(Boolean.FALSE,dto.get("canApprove"),"Opaque typed result is not selected evidence for approval");
        assertInstanceOf(Boolean.class,dto.get("canResume"));assertEquals(f.terms.kycPoints(),dto.get("usedRisk"));
        assertEquals(1,dto.get("kycRuns"));assertNull(dto.get("activeJob"));
        assertEquals(com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore.MODE,dto.get("executionMode"));
        for(String key:List.of("documentId","documentVersion","typedStageAgents","canonicalInput","modelInput","bindingBytes","bindingDigest","inputSnapshotHash","grantReceipt","token"))assertFalse(dto.containsKey(key));
        String rendered=dto.toString();assertFalse(rendered.contains(f.seed.f.source.text()));assertFalse(rendered.contains(f.seed.f.replacement.text()));
        assertFalse(rendered.contains("AGENT_RESULT_BINDING_RECORD_1"));
    }
    @Test void actualTypedKycPointerIsReadableThroughGetAndListWithoutAnyLegacyResultRow(){
        var f=completedKyc();var reads=reader(f,f.seed.f.catalog,(actor,op,workflow,customer)->true);var before=f.store.snapshot();
        var dto=reads.get(SimulationFixture.ACTOR,VirtualGrantContinuationFixture.id(1));typedSummary(dto,f);
        var page=reads.list(SimulationFixture.ACTOR,0,10);assertEquals(1,page.get("total"));var items=(List<?>)page.get("items");assertEquals(1,items.size());assertEquals(dto,items.get(0));
        assertEquals(0,page.get("page"));assertEquals(10,page.get("size"));assertEquals(before,f.store.snapshot());assertEquals(0,reads.observed.puts);
        assertThrows(UnsupportedOperationException.class,dto::clear);
    }
    @Test void currentReadAuthorityDenialPrecedesTypedResultProjectionForGetAndList(){
        var f=completedKyc();var itemChecks=new AtomicInteger();var broadChecks=new AtomicInteger();
        var reads=reader(f,f.seed.f.catalog,(actor,op,workflow,customer)->{
            assertEquals(SimulationAccess.Operation.READ,op);
            if(customer==null){broadChecks.incrementAndGet();return true;}itemChecks.incrementAndGet();return false;
        });
        var before=f.store.snapshot();var denied=assertThrows(SimulationFailure.class,()->reads.get(SimulationFixture.ACTOR,VirtualGrantContinuationFixture.id(1)));
        assertEquals(403,denied.status());assertEquals("FORBIDDEN",denied.code());assertFalse(denied.getMessage().contains(f.seed.f.source.text()));
        var page=reads.list(SimulationFixture.ACTOR,0,10);assertEquals(0,page.get("total"));assertEquals(List.of(),page.get("items"));
        assertEquals(1,broadChecks.get());assertEquals(2,itemChecks.get());assertEquals(before,f.store.snapshot());assertEquals(0,reads.observed.puts);
    }
    @Test void customerFilteringPrecedesStateCountAndPaginationWithMixedTypedAndLegacyRows(){
        var f=completedKyc();var a=f.seed.f.app;
        var other=new SimulationSpec.Application("synthetic-other-fixture","synthetic-other-business","synthetic-other-customer",a.amountKrw(),a.payoutAccountId(),a.monthlyIncomeKrw(),a.maxLoanAmountKrw(),true,a.source());
        var catalog=new SimulationSpec.Catalog(List.of(a,other),f.seed.f.catalog.factsFor(a.customerId(),f.seed.f.clock.instant()));
        var writer=reader(f,catalog,(actor,op,workflow,customer)->true);
        var legacy=writer.start(new WorkflowStartBoundary.Command(SimulationFixture.ACTOR,f.seed.f.id(),other.request()));
        var reads=reader(f,catalog,(actor,op,workflow,customer)->customer==null||customer.equals(a.customerId()));var before=f.store.snapshot();
        assertEquals(403,assertThrows(SimulationFailure.class,()->reads.get(SimulationFixture.ACTOR,legacy.workflowId())).status());
        var page=reads.list(SimulationFixture.ACTOR,0,1);assertEquals(1,page.get("total"));assertEquals(1,((List<?>)page.get("items")).size());
        typedSummary((Map<String,Object>)((List<?>)page.get("items")).get(0),f);
        var next=reads.list(SimulationFixture.ACTOR,1,1);assertEquals(1,next.get("total"));assertEquals(List.of(),next.get("items"));
        var filtered=reads.list(SimulationFixture.ACTOR,(String)f.workflow().get("state"),0,10);assertEquals(1,filtered.get("total"));assertEquals(0,reads.observed.puts);assertEquals(before,f.store.snapshot());
    }
    @Test void legacyStartGetAndListRetainTheirExistingPositiveContract(){
        var seed=new VirtualGrantWorkflowBridgeTest.Fixture();var f=seed.f;var id=f.start();
        var observed=new ObservedReadStore(f.store);var reads=new VirtualWorkflowService(observed,f.catalog,seed.terms,f.access,f.clock,f::id);var before=f.store.snapshot();
        var dto=reads.get(SimulationFixture.ACTOR,id);
        assertEquals(id.toString(),dto.get("workflowId"));assertEquals("KYC_PENDING",dto.get("state"));assertEquals(1,dto.get("generation"));
        assertEquals(0,dto.get("usedRisk"));assertEquals(0,dto.get("kycRuns"));assertNotNull(dto.get("activeJob"));assertEquals(Boolean.FALSE,dto.get("canApprove"));
        var page=reads.list(SimulationFixture.ACTOR,0,10);assertEquals(1,page.get("total"));assertEquals(List.of(dto),page.get("items"));assertEquals(0,observed.puts);assertEquals(before,f.store.snapshot());
        assertTrue(f.store.snapshot().getOrDefault("virtual_workflow_lanes",Map.of()).isEmpty());
    }
    @Test void typedRootBeforeResultDoesNotInventApprovalOrLegacyJob(){
        var f=new VirtualGrantContinuationFixture();var reads=reader(f,f.seed.f.catalog,(actor,op,workflow,customer)->true);var before=f.store.snapshot();
        var dto=reads.get(SimulationFixture.ACTOR,VirtualGrantContinuationFixture.id(1));
        assertNull(dto.get("currentKycResultId"));assertNull(dto.get("currentLoanResultId"));assertNull(dto.get("activeJob"));
        assertEquals(Boolean.FALSE,dto.get("canApprove"));assertEquals(Boolean.FALSE,dto.get("canResume"));assertEquals(0,dto.get("kycRuns"));
        assertTrue(f.store.snapshot().getOrDefault("virtual_results",Map.of()).isEmpty());assertEquals(0,reads.observed.puts);assertEquals(before,f.store.snapshot());
    }
}
