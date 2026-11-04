package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowResumeBoundary;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.grant.VirtualGrantTransactionJournal;
import com.finsec.fuse.reimplementation.persistence.*;
import java.time.Duration;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLaneTest.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real virtual business writers, explicit synthetic stored lane challenges, no activation. */
class VirtualWorkflowLaneBoundaryTest {
    static final class Counted implements TransactionalStore {
        final VirtualTransactionalStore store;int laneReads,puts;
        Counted(VirtualTransactionalStore store){this.store=store;}
        public String mode(){return store.mode();}
        public Map<String,Map<String,Map<String,Object>>> snapshot(){return store.snapshot();}
        public <R> R transaction(Function<Tx,R> work){return store.transaction(tx->work.apply(new Tx(){
            public Map<String,Object> get(String table,String key){if(table.equals(LANES))laneReads++;return tx.get(table,key);}
            public Map<String,Map<String,Object>> rows(String table){return tx.rows(table);}
            public void put(String table,String key,Map<String,Object> row){puts++;tx.put(table,key,row);}
        }));}
    }
    static VirtualWorkflowService service(SimulationFixture f,Counted counted,Supplier<UUID> ids){
        return new VirtualWorkflowService(counted,f.catalog,new SimulationSpec.RiskTerms("SYNTHETIC-POLICY-1",1,2,3,20,5,2,
                Duration.ofMinutes(5)),f.access,f.clock,ids);
    }
    static void challenge(SimulationFixture f,UUID workflow){
        f.store.transaction(tx->{var row=tx.get(WORKFLOWS,workflow.toString());
            var scope=new VirtualWorkflowLane.Scope(workflow,(Integer)row.get("generation"),(String)row.get("customerId"));
            // Adversarial stored-state fixture only; registerTyped cannot migrate this existing workflow.
            tx.put(LANES,workflow.toString(),lane(scope,"TYPED"));return null;});
    }
    static void noPoison(Counted counted,UUID request){
        var reply=new ActionJournal(counted).execute(ACTOR.actorId(),request,"synthetic-after-refusal","d".repeat(64),
                tx->Map.of("requestId",request.toString()));assertEquals(request.toString(),reply.get("requestId"));
    }

    @Test void legacyBusinessMutationWritersRejectTypedLaneForDifferentRequestIdsInSameTransaction(){
        for(int mode=0;mode<6;mode++){
            SimulationFixture f=new SimulationFixture();UUID workflow;
            if(mode==2||mode==3||mode==4)workflow=f.ready();else workflow=f.start();
            SimulationSpec.Observation observation=mode==1?f.observation(f.input(workflow),List.of(ID_FACT,FACE_FACT)):null;
            String hash=mode==2?(String)f.workflows.approvalPreview(ACTOR,workflow).get("reviewSnapshotHash"):null;
            if(mode==3||mode==4)f.approve(workflow);
            UUID reservation=mode==4?f.reserve(workflow):null;
            challenge(f,workflow);Counted counted=new Counted(f.store);var service=service(f,counted,f::id);
            for(int attempt=0;attempt<2;attempt++){
                UUID request=f.id();var before=f.store.snapshot();counted.laneReads=0;counted.puts=0;
                Runnable call=switch(mode){
                    case 0->()->service.prepareKyc(ACTOR,request,workflow);
                    case 1->()->service.observeKyc(ACTOR,request,observation);
                    case 2->()->service.approve(ACTOR,request,workflow,true,hash,"synthetic review");
                    case 3->()->service.reservePayment(ACTOR,request,workflow);
                    case 4->()->service.commitPayment(ACTOR,request,workflow,reservation);
                    default->()->service.resume(new WorkflowResumeBoundary.Command(ACTOR,request,workflow,
                            new WorkflowResumeBoundary.Request(1,"synthetic resume")));
                };
                invalid(call);assertEquals(1,counted.laneReads);assertEquals(0,counted.puts);
                assertEquals(before,f.store.snapshot());noPoison(counted,request);
            }
        }
    }

    @Test void startCannotClaimAnAlreadyRegisteredTypedWorkflowIdOrPoisonRequest(){
        SimulationFixture f=new SimulationFixture();UUID workflow=f.id();
        f.store.transaction(tx->{VirtualWorkflowLane.registerTyped(tx,new VirtualWorkflowLane.Scope(workflow,1,f.app.customerId()));return null;});
        Counted counted=new Counted(f.store);var service=service(f,counted,()->workflow);UUID request=f.id();var before=f.store.snapshot();
        invalid(()->service.start(new WorkflowStartBoundary.Command(ACTOR,request,f.app.request())));
        assertEquals(1,counted.laneReads);assertEquals(0,counted.puts);assertEquals(before,f.store.snapshot());noPoison(counted,request);
    }

    @Test void currentAuthorizationStillPrecedesLaneInspection(){
        SimulationFixture f=new SimulationFixture();UUID workflow=f.start();challenge(f,workflow);f.permitted.set(false);
        Counted counted=new Counted(f.store);var service=service(f,counted,f::id);var before=f.store.snapshot();
        var denied=assertThrows(SimulationFailure.class,()->service.prepareKyc(ACTOR,f.id(),workflow));
        assertEquals(403,denied.status());assertEquals(0,counted.laneReads);assertEquals(0,counted.puts);assertEquals(before,f.store.snapshot());
    }

    @Test void noLaneLegacyPaymentAndItsReplayRemainUnchangedWithoutImplicitLaneCreation(){
        SimulationFixture f=new SimulationFixture();UUID workflow=f.ready();f.approve(workflow);UUID reservation=f.reserve(workflow),request=f.id();
        var first=f.workflows.commitPayment(ACTOR,request,workflow,reservation);var before=f.store.snapshot();
        assertEquals("ALLOW",first.get("decision"));assertEquals(true,f.workflows.commitPayment(ACTOR,request,workflow,reservation).get("replayed"));
        assertEquals(before,f.store.snapshot());assertTrue(f.store.snapshot().getOrDefault(LANES,Map.of()).isEmpty());
        f.permitted.set(false);assertEquals(403,assertThrows(SimulationFailure.class,
                ()->f.workflows.commitPayment(ACTOR,request,workflow,reservation)).status());assertEquals(before,f.store.snapshot());
    }

    static StageCommand typedCommand(VirtualWorkflowLane.Scope scope){
        return new StageCommand(new CommandIdentity("synthetic-actor",id(10),"synthetic-stage","supplied-profile","supplied-digest",
                id(11),id(12),id(13),scope.workflowId(),scope.generation(),scope.customerId()),AllowedAction.EVALUATE_KYC);
    }
    @Test void strictApplicationJournalDoesNotTreatMissingWorkflowOrLaneAsDetachedReference(){
        for(int mode=0;mode<4;mode++){
            var store=new VirtualTransactionalStore();var scope=scope();final int m=mode;
            store.transaction(tx->{if(m==2||m==3)VirtualWorkflowLane.registerTyped(tx,scope);
                if(m==1||m==3)tx.put(WORKFLOWS,scope.workflowId().toString(),workflow(scope));return null;});
            var before=store.snapshot();var journal=new VirtualGrantTransactionJournal(store,()->id(20),65536);var command=typedCommand(scope);
            StageOutcome result=journal.transact(command,tx->{assertNull(tx.lookup(command));return StageOutcome.of(
                    Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH,null,EffectKnowledge.UNKNOWN);});
            assertEquals(mode==3?Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH:Status.UNCONFIRMED_BEFORE_ADMISSION,result.status());
            assertFalse(result.actualAuthority());assertFalse(result.durable());assertEquals(before,store.snapshot());
        }
    }

    @Test void strictApplicationCannotSeedAndDetachedFactoryCannotBorrowAnApplicationWorkflow(){
        var store=new VirtualTransactionalStore();var scope=scope();var command=typedCommand(scope);
        var root=new GrantSnapshot(id(11),id(12),id(13),scope.workflowId(),scope.generation(),scope.customerId(),AllowedAction.EVALUATE_KYC,GrantState.ISSUED);
        var strict=new VirtualGrantTransactionJournal(store,()->id(30),65536);
        var error=assertThrows(IllegalStateException.class,()->strict.seedSyntheticRoot(root));
        assertEquals("OWNED_GRANT_REFERENCE_FIXTURE_ONLY",error.getMessage());assertTrue(store.snapshot().isEmpty());
        store.transaction(tx->{tx.put(WORKFLOWS,scope.workflowId().toString(),workflow(scope));return null;});var before=store.snapshot();
        var detached=VirtualGrantTransactionJournal.detachedReference(store,()->id(31),65536);
        StageOutcome refused=detached.transact(command,tx->{tx.lookup(command);fail("application row cannot become detached");return null;});
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,refused.status());assertEquals(before,store.snapshot());
    }
}
