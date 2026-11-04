package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.grant.*;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.RunStatus.VALIDATED;
import static org.junit.jupiter.api.Assertions.*;

/** Deliberately permissive supplied resolver isolates the strict APP commit boundary. */
class VirtualGrantPreparedInputBoundaryTest {
    static final class Scenario {
        final VirtualGrantWorkflowBridgeTest.Fixture f=new VirtualGrantWorkflowBridgeTest.Fixture();
        final VirtualProductAssembly product=f.typed();
        final VirtualGrantTransactionJournal journal;
        int preparationChecks,resolutions;
        Scenario(){
            f.facts.next();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,product.grantWorkflows().startTyped(f.context,f.root).status());
            f.prepare(product.grantWorkflows());
            journal=new VirtualGrantTransactionJournal(f.f.store,()->VirtualGrantWorkflowBridgeTest.id(f.tokens.incrementAndGet()),65536);
        }
        GrantStageTransactionService service(int mode){return new GrantStageTransactionService(journal,new CurrentFactResolver(){
            public Gate current(ServerContext context,StageCommand command,OwnedTx tx){return Gate.CLEAR;}
            public ResolvedStage resolve(ServerContext context,StageCommand command,OutsidePreparedResult prepared,OwnedTx tx){
                resolutions++;
                tx.requireKycPreparation(command,f.preparedHash);preparationChecks++;
                var grant=tx.grant(command.identity().grantId());assertNotNull(grant);assertEquals(GrantState.ISSUED,grant.state());
                var status=com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.ResultStatus.VALIDATED;
                if(mode==2)return new ResolvedStage(grant,prepared,VALIDATED,status,List.of());
                return new ResolvedStage(grant,prepared,VALIDATED,status,List.of(),mode==0?null:mode==1?"f".repeat(64):f.preparedHash);
            }
            public Gate checkIssuance(ServerContext context,StageCommand command,UUID parent,GrantSnapshot child){throw new AssertionError("No child issuance");}
        });}
    }
    @Test void missingWrongAndLegacyConstructorHashCannotCommitAfterCorrectMarkerCheck(){
        for(int mode=0;mode<3;mode++){
            Scenario s=new Scenario();var before=s.f.f.store.snapshot();
            var out=s.service(mode).completeStage(s.f.context,s.f.stage(),s.f.result());
            assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,out.status());assertNull(out.receipt());
            assertEquals(1,s.resolutions);assertEquals(1,s.preparationChecks);
            assertEquals(before,s.f.f.store.snapshot(),"Rejected binding must not mutate grant, result, charge or global journal");
            assertEquals(0,s.f.providers.get());assertFalse(out.actualAuthority());assertFalse(out.durable());
        }
    }
    @Test void exactActualPreparationHashCommitsWithOtherwiseSameResolverAndResult(){
        Scenario s=new Scenario();var before=s.f.f.store.snapshot();
        var out=s.service(3).completeStage(s.f.context,s.f.stage(),s.f.result());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());assertNotNull(out.receipt());
        assertEquals(VirtualGrantWorkflowBridgeTest.id(600),out.receipt().result().resultId());
        assertEquals(1,s.resolutions);assertEquals(1,s.preparationChecks);
        assertNotEquals(before,s.f.f.store.snapshot());assertEquals(0,s.f.providers.get());
        assertFalse(out.actualAuthority());assertFalse(out.durable());
    }
}
