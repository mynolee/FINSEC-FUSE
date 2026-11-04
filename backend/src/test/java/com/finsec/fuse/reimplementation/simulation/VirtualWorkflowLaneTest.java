package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane.*;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit virtual rows only; no application provisioning or migration is performed. */
class VirtualWorkflowLaneTest {
    static final String LANES="virtual_workflow_lanes",WORKFLOWS="virtual_workflows";
    static UUID id(long n){return new UUID(15,n);}
    static Scope scope(){return new Scope(id(1),1,"synthetic-customer");}
    static Map<String,Object> workflow(Scope s){return Map.of("workflowId",s.workflowId().toString(),"generation",s.generation(),"customerId",s.customerId());}
    static Map<String,Object> lane(Scope s,String name){var r=new LinkedHashMap<>(workflow(s));r.put("lane",name);return r;}
    static void invalid(Runnable work){var e=assertThrows(SimulationFailure.class,work::run);assertEquals(400,e.status());assertEquals("INVALID_REQUEST",e.code());}

    @Test void typedRegistrationIsCreateOnlyAndSharesCallerTransactionWithWorkflowCreation(){
        var store=new VirtualTransactionalStore();Scope s=scope();
        store.transaction(tx->{registerTyped(tx,s);tx.put(WORKFLOWS,s.workflowId().toString(),workflow(s));requireTyped(tx,s);return null;});
        assertEquals(lane(s,"TYPED"),store.snapshot().get(LANES).get(s.workflowId().toString()));
        var before=store.snapshot();invalid(()->store.transaction(tx->{registerTyped(tx,s);return null;}));assertEquals(before,store.snapshot());
        var rollback=new VirtualTransactionalStore();
        assertThrows(IllegalStateException.class,()->rollback.transaction(tx->{registerTyped(tx,s);throw new IllegalStateException("synthetic abort");}));
        assertTrue(rollback.snapshot().isEmpty());
    }
    @Test void noLaneHistoricalWorkflowStaysLegacyWithoutImplicitRowWrite(){
        var store=new VirtualTransactionalStore();Scope s=scope();
        store.transaction(tx->{tx.put(WORKFLOWS,s.workflowId().toString(),workflow(s));return null;});var before=store.snapshot();
        store.transaction(tx->{requireLegacy(tx,s);return null;});assertEquals(before,store.snapshot());
        invalid(()->store.transaction(tx->{registerTyped(tx,s);return null;}));
        invalid(()->store.transaction(tx->{requireTyped(tx,s);return null;}));assertEquals(before,store.snapshot());
    }
    @Test void typedRequiresBothActualWorkflowAndExactLaneWithoutDetachedAbsenceFallback(){
        for(int mode=0;mode<3;mode++){
            var store=new VirtualTransactionalStore();Scope s=scope();
            final int m=mode;store.transaction(tx->{if(m==1)tx.put(WORKFLOWS,s.workflowId().toString(),workflow(s));
                if(m==2)registerTyped(tx,s);return null;});var before=store.snapshot();
            invalid(()->store.transaction(tx->{requireTyped(tx,s);return null;}));assertEquals(before,store.snapshot());
        }
    }
    @Test void generationCustomerAndMalformedLaneNeverInheritOrChangeOwnership(){
        for(String mode:List.of("generation","customer","unknown","extra","bool-generation")){
            var store=new VirtualTransactionalStore();Scope s=scope();var row=new LinkedHashMap<>(lane(s,"TYPED"));
            switch(mode){case "generation"->row.put("generation",2);case "customer"->row.put("customerId","other-customer");
                case "unknown"->row.put("lane","UNKNOWN");case "extra"->row.put("extra",true);default->row.put("generation",true);}
            store.transaction(tx->{tx.put(WORKFLOWS,s.workflowId().toString(),workflow(s));tx.put(LANES,s.workflowId().toString(),row);return null;});
            var before=store.snapshot();invalid(()->store.transaction(tx->{requireTyped(tx,s);return null;}));
            invalid(()->store.transaction(tx->{requireLegacy(tx,s);return null;}));assertEquals(before,store.snapshot());
        }
    }
    @Test void advancedWorkflowGenerationDoesNotImplicitlyAdvanceTypedLane(){
        var store=new VirtualTransactionalStore();Scope original=scope(),next=new Scope(original.workflowId(),2,original.customerId());
        store.transaction(tx->{registerTyped(tx,original);tx.put(WORKFLOWS,original.workflowId().toString(),workflow(next));return null;});
        var before=store.snapshot();invalid(()->store.transaction(tx->{requireTyped(tx,next);return null;}));
        invalid(()->store.transaction(tx->{requireTyped(tx,original);return null;}));assertEquals(before,store.snapshot());
    }
    @Test void requestedScopeCannotBorrowAnotherCustomerOrGenerationTypedWorkflow(){
        var store=new VirtualTransactionalStore();Scope s=scope();
        store.transaction(tx->{registerTyped(tx,s);tx.put(WORKFLOWS,s.workflowId().toString(),workflow(s));return null;});
        var before=store.snapshot();
        for(Scope wrong:List.of(new Scope(s.workflowId(),2,s.customerId()),new Scope(s.workflowId(),1,"other-customer"))){
            invalid(()->store.transaction(tx->{requireTyped(tx,wrong);return null;}));
            invalid(()->store.transaction(tx->{requireLegacy(tx,wrong);return null;}));
            assertEquals(before,store.snapshot());
        }
    }
}
