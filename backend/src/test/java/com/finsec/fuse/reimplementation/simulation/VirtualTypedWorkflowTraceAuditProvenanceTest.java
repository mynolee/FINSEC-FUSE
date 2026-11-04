package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.persistence.*;
import java.util.*;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;

/** Actual containment provenance with a single read-only audit transplant; source-only regression. */
class VirtualTypedWorkflowTraceAuditProvenanceTest {
    private record Fault(String table,String key,String field,Object value,boolean missing) { }
    private static final class TraceStore implements TransactionalStore {
        final VirtualTransactionalStore actual=new VirtualTransactionalStore();
        Fault fault; boolean reverseRows; int hits,typedReads,puts,publications;
        public String mode(){return actual.mode();}
        public Map<String,Map<String,Map<String,Object>>> snapshot(){return actual.snapshot();}
        private void observed(String table){if(table.startsWith("virtual_grant_profile_")||table.equals("virtual_workflow_lanes"))typedReads++;}
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

    @Test void foreignWorkflowAuditCannotBeAttributedByChangingOnlyItsLocalWorkflowId(){
        var store=new TraceStore();var typed=new VirtualGrantContinuationFixture(store);
        var prepared=typed.prepareCurrent();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,prepared.status());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,typed.consume(1,prepared.receipt().inputSnapshotHash(),85001).status());
        UUID subject=typed.oldRootCommand.identity().workflowId();
        var service=new VirtualWorkflowService(store,typed.seed.f.catalog,typed.terms,typed.seed.f.access,typed.seed.f.clock,typed.seed.f::id);
        UUID foreign=service.start(new WorkflowStartBoundary.Command(SimulationFixture.ACTOR,typed.seed.f.id(),typed.seed.f.second.request())).workflowId();
        assertNotEquals(subject,foreign);
        UUID q=typed.hold(new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.WORKFLOW,Map.of("workflowId",foreign.toString())));
        var subjectBefore=service.trace(SimulationFixture.ACTOR,subject);
        var foreignBefore=service.trace(SimulationFixture.ACTOR,foreign);
        var snapshot=store.snapshot();
        var audit=snapshot.get("virtual_audit").values().stream().filter(r->foreign.toString().equals(r.get("workflowId"))
                &&"QUARANTINE_ACTIVE".equals(r.get("eventType"))).findFirst().orElseThrow();
        String auditId=(String)audit.get("auditEventId");
        assertTrue(((List<?>)foreignBefore.get("auditEvents")).stream().anyMatch(r->auditId.equals(((Map<?,?>)r).get("auditEventId"))));
        assertFalse(((List<?>)subjectBefore.get("auditEvents")).stream().anyMatch(r->auditId.equals(((Map<?,?>)r).get("auditEventId"))));
        assertEquals(Map.of("workflowId",foreign.toString()),snapshot.get("virtual_quarantines").get(q.toString()).get("target"));
        int puts=store.puts,publications=store.publications;store.hits=0;
        store.fault=new Fault("virtual_audit",auditId,"workflowId",subject.toString(),false);
        try{
            var failure=assertThrows(SimulationFailure.class,()->service.trace(SimulationFixture.ACTOR,subject));
            assertEquals(503,failure.status());assertEquals("DEPENDENCY_UNAVAILABLE",failure.code());
            assertEquals("DEPENDENCY_UNAVAILABLE",failure.getMessage());assertNull(failure.getCause());
            assertEquals(0,failure.getSuppressed().length);
            assertTrue(store.hits>0,"selected foreign audit was not read");
            assertEquals(snapshot,store.snapshot());assertEquals(puts,store.puts);assertEquals(publications,store.publications);
        }finally{store.fault=null;}
        assertEquals(subjectBefore,service.trace(SimulationFixture.ACTOR,subject));
        assertEquals(foreignBefore,service.trace(SimulationFixture.ACTOR,foreign));
    }
}
