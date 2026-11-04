package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.persistence.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;

/** Public trace join boundaries over actual synthetic history; no execution or authority proof. */
class VirtualTypedWorkflowTraceBoundaryTest {
    private static final String HEADS="virtual_grant_profile_current_heads", LANES="virtual_workflow_lanes";
    private static final String TARGETS="virtual_grant_profile_target_bindings", GRANTS="virtual_grant_profile_grants";
    private static final List<String> ARRAYS=List.of("runs","results","grants","dependencies","approvals","riskEvents","payments","auditEvents");
    private record Fault(String table,String key,String field,Object value,boolean missing) { }
    private static final class TraceStore implements TransactionalStore {
        final VirtualTransactionalStore actual=new VirtualTransactionalStore();
        Fault fault; boolean reverseRows; int hits,typedReads,puts,publications;
        public String mode(){return actual.mode();}
        public Map<String,Map<String,Map<String,Object>>> snapshot(){return actual.snapshot();}
        private void observed(String table){if(table.startsWith("virtual_grant_profile_")||table.equals(LANES))typedReads++;}
        private Map<String,Object> row(String table,String key,Map<String,Object> value){
            if(fault==null||value==null||!fault.table().equals(table)||!fault.key().equals(key))return value;
            hits++;if(fault.missing())return null;
            var copy=new LinkedHashMap<>(value);copy.put(fault.field(),fault.value());return Collections.unmodifiableMap(copy);
        }
        public <R> R transaction(Function<Tx,R> work){
            R result=actual.transaction(tx->work.apply(new Tx(){
                public Map<String,Object> get(String table,String key){observed(table);return row(table,key,tx.get(table,key));}
                public Map<String,Map<String,Object>> rows(String table){
                    observed(table);var source=tx.rows(table);var keys=new ArrayList<>(source.keySet());
                    if(reverseRows)Collections.reverse(keys);
                    var copy=new LinkedHashMap<String,Map<String,Object>>();
                    for(var key:keys){var value=row(table,key,source.get(key));if(value!=null)copy.put(key,value);}
                    return Collections.unmodifiableMap(copy);
                }
                public void put(String table,String key,Map<String,Object> value){puts++;tx.put(table,key,value);}
            }));publications++;return result;
        }
    }
    private static final class Fixture {
        final TraceStore store=new TraceStore();
        final VirtualGrantContinuationFixture typed=new VirtualGrantContinuationFixture(store);
        final VirtualWorkflowService service;
        final UUID workflow,target,grant,oldResult,currentResult;
        Fixture(){
            var first=typed.prepareCurrent();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,first.status());
            var old=typed.consume(1,first.receipt().inputSnapshotHash(),84001);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,old.status());oldResult=old.receipt().result().resultId();
            typed.blockAndRelease();var continuation=typed.firstCommand();
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,typed.advance(continuation).status());
            var prepared=typed.prepareCurrent();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,prepared.status());
            var result=typed.consume(2,prepared.receipt().inputSnapshotHash(),84002);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,result.status());currentResult=result.receipt().result().resultId();
            workflow=continuation.identity().workflowId();target=continuation.identity().targetRunId();grant=continuation.identity().grantId();
            service=reads(typed.seed.f.access);baseline();
        }
        VirtualWorkflowService reads(SimulationAccess access){return new VirtualWorkflowService(store,typed.seed.f.catalog,typed.terms,
                access,typed.seed.f.clock,typed.seed.f::id);}
        Map<String,Object> baseline(){
            assertNull(store.fault);var trace=service.trace(SimulationFixture.ACTOR,workflow);
            assertEquals(workflow.toString(),trace.get("workflowId"));assertEquals(2,trace.get("generation"));
            for(var key:ARRAYS)assertInstanceOf(List.class,trace.get(key));
            assertEquals(2,((List<?>)trace.get("grants")).size());assertEquals(2,((List<?>)trace.get("results")).size());
            assertEquals(List.of(),trace.get("runs"));assertEquals(Boolean.FALSE,trace.get("cryptographicAuthorityImplemented"));
            return trace;
        }
        void rejects(Fault f){
            var before=store.snapshot();int puts=store.puts,publications=store.publications;store.hits=0;store.fault=f;
            try{
                var failure=assertThrows(SimulationFailure.class,()->service.trace(SimulationFixture.ACTOR,workflow));
                assertEquals(503,failure.status());assertEquals("DEPENDENCY_UNAVAILABLE",failure.code());
                assertEquals("DEPENDENCY_UNAVAILABLE",failure.getMessage());assertNull(failure.getCause());
                assertEquals(0,failure.getSuppressed().length);assertTrue(store.hits>0,"trace did not observe selected fault");
                assertEquals(before,store.snapshot());assertEquals(puts,store.puts);assertEquals(publications,store.publications);
            }finally{store.fault=null;}
            baseline();
        }
    }

    @Test void coherentLookingHeadLaneAndGrantScopeMismatchesFailWithoutAnyPartialTrace(){
        var f=new Fixture();String workflow=f.workflow.toString();
        for(var fault:List.of(new Fault(HEADS,workflow,"generation",1,false),
                new Fault(HEADS,workflow,"rootGrantId",VirtualGrantContinuationFixture.id(84999).toString(),false),
                new Fault(LANES,workflow,"generation",1,false),
                new Fault(GRANTS,f.grant.toString(),"customerId","synthetic-other",false)))f.rejects(fault);
    }

    @Test void currentTargetCannotBorrowOldResultIdentityOrAnotherGrantWhileRetainingNativeShape(){
        var f=new Fixture();assertNotEquals(f.oldResult,f.currentResult);
        for(var fault:List.of(new Fault(TARGETS,f.target.toString(),"resultId",f.oldResult.toString(),false),
                new Fault(TARGETS,f.target.toString(),"grantId",VirtualGrantContinuationFixture.id(84998).toString(),false),
                new Fault(TARGETS,f.target.toString(),"generation",1,false)))f.rejects(fault);
    }

    @Test void reversingActualRowEnumerationKeepsTypedGenerationIdentityOrderStable(){
        var f=new Fixture();var original=f.baseline();var before=f.store.snapshot();int puts=f.store.puts;
        f.store.reverseRows=true;
        try{
            var reversed=f.service.trace(SimulationFixture.ACTOR,f.workflow);
            assertEquals(original.get("grants"),reversed.get("grants"));
            assertEquals(original.get("results"),reversed.get("results"));
            assertEquals(original.get("dependencies"),reversed.get("dependencies"));
            for(var key:List.of("grants","results")){
                var rows=(List<?>)reversed.get(key);assertEquals(2,rows.size());
                assertEquals(1,((Map<?,?>)rows.get(0)).get("generation"));
                assertEquals(2,((Map<?,?>)rows.get(1)).get("generation"));
            }
            assertEquals(puts,f.store.puts);assertEquals(before,f.store.snapshot());
        }finally{f.store.reverseRows=false;}
        f.baseline();
    }

    @Test void wrongWorkflowScopedReadAuthorityRefusesBeforeAnyTypedMetadataLookup(){
        var f=new Fixture();AtomicReference<UUID> checked=new AtomicReference<>();
        UUID allowedDifferentWorkflow=VirtualGrantContinuationFixture.id(84997);
        var access=new SimulationAccess((actor,operation,workflow,customer)->{
            if(operation!=SimulationAccess.Operation.READ)return false;
            checked.set(workflow);return allowedDifferentWorkflow.equals(workflow);
        });
        var restricted=f.reads(access);var before=f.store.snapshot();int puts=f.store.puts,publications=f.store.publications;
        f.store.typedReads=0;
        var failure=assertThrows(SimulationFailure.class,()->restricted.trace(SimulationFixture.ACTOR,f.workflow));
        assertEquals(403,failure.status());assertEquals("FORBIDDEN",failure.code());assertEquals(f.workflow,checked.get());
        assertEquals(0,f.store.typedReads);assertEquals(puts,f.store.puts);assertEquals(publications,f.store.publications);
        assertEquals(before,f.store.snapshot());f.baseline();
    }
}
