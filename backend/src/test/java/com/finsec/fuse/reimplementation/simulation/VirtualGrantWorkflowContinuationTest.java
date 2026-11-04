package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.grant.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.*;
import static org.junit.jupiter.api.Assertions.*;

class VirtualGrantWorkflowContinuationTest {
    @Test void actualCatalogBackedRemediationAdvancesInertGenerationAndPreservesOldRoot(){
        var f=new VirtualGrantContinuationFixture();var roots=f.store.snapshot().get("virtual_grant_profile_root_receipts");
        var oldGrant=f.store.snapshot().get("virtual_grant_profile_grants").get(f.oldRootCommand.identity().grantId().toString());
        f.blockAndRelease();var out=f.advance(f.firstCommand());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());assertEquals(ContinuationKind.ADVANCED,out.receipt().kind());
        assertEquals(2,out.receipt().committedGeneration());assertEquals("KYC_PENDING",f.workflow().get("state"));
        assertEquals("ALLOW",f.workflow().get("lastDecision"));assertEquals(List.of(),f.workflow().get("reasonCodes"));
        assertNull(f.workflow().get("activeJobId"));assertNull(f.workflow().get("currentKycResultId"));assertNull(f.workflow().get("currentLoanResultId"));
        assertEquals(f.newApplication.source().documentVersion(),f.workflow().get("documentVersion"));
        assertEquals(f.terms.baseLimit(),f.workflow().get("riskLimit"));assertEquals(0,f.workflow().get("usedRisk"));assertEquals(0,f.workflow().get("reservedRisk"));assertEquals(0,f.workflow().get("kycRuns"));
        roots.forEach((key,value)->assertEquals(value,f.store.snapshot().get("virtual_grant_profile_root_receipts").get(key)));
        assertEquals(oldGrant,f.store.snapshot().get("virtual_grant_profile_grants").get(f.oldRootCommand.identity().grantId().toString()));
        assertTrue(f.store.snapshot().getOrDefault("virtual_jobs",Map.of()).isEmpty());assertFalse(out.actualAuthority());assertFalse(out.durable());
    }
    @Test void missingOrDifferentCapturedCatalogCannotAdmitFreshCandidateButHistoryNeedsNoCatalog(){
        var f=new VirtualGrantContinuationFixture();f.blockAndRelease();var command=f.firstCommand();var before=f.store.snapshot();
        var missing=f.service(null).continueWorkflow(f.context,command);assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,missing.status());assertNull(missing.receipt());assertSame(before,f.store.snapshot());
        var different=f.service(new SimulationSpec.Catalog(List.of(),List.of())).continueWorkflow(f.context,command);
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,different.status());assertSame(before,f.store.snapshot());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,f.advance(command).status());var after=f.store.snapshot();
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,f.service(null).continueWorkflow(f.context,command).status());assertSame(after,f.store.snapshot());
    }
    @Test void exactGenerationTwoHistoryRemainsQueryableAfterActualGenerationThreeWithoutFreshResolution(){
        var f=new VirtualGrantContinuationFixture();f.blockAndRelease();var c2=f.firstCommand();var r2=f.advance(c2);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,r2.status());f.blockAndRelease();var c3=f.command(3,f.expected(r2.receipt()),6003);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,f.advance(c3).status());assertEquals(3,f.workflow().get("generation"));
        var before=f.store.snapshot();int resolutions=f.resolutions.get();
        var replay=f.continuations.reconcileContinuation(f.context,c2);assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,replay.status());assertEquals(r2.receipt(),replay.receipt());
        assertEquals(resolutions,f.resolutions.get());assertSame(before,f.store.snapshot());
        f.currentGate=Gate.REFUSED;var denied=f.continuations.reconcileContinuation(f.context,c2);assertEquals(Status.REFUSED_BEFORE_ADMISSION,denied.status());assertNull(denied.receipt());assertSame(before,f.store.snapshot());
    }
    @Test void wholeWorkflowPreparationCountAndFirstChargeSurviveAdvanceAndOldHashCannotConsumeNewTarget(){
        var f=new VirtualGrantContinuationFixture();var first=f.prepareCurrent();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,first.status());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,f.consume(1,first.receipt().inputSnapshotHash(),7201).status());
        var charges=f.store.snapshot().get("virtual_grant_profile_stage_charges");f.blockAndRelease();
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,f.advance(f.firstCommand()).status());assertEquals(1,f.workflow().get("kycRuns"));assertEquals(f.terms.kycPoints(),f.workflow().get("usedRisk"));
        var second=f.prepareCurrent();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,second.status());assertEquals(0,second.receipt().chargedPoints());assertEquals(2,second.receipt().kycRunsAfter());
        assertNotEquals(first.receipt().inputSnapshotHash(),second.receipt().inputSnapshotHash());assertEquals(charges,f.store.snapshot().get("virtual_grant_profile_stage_charges"));
        var before=f.store.snapshot();var wrong=f.consume(2,first.receipt().inputSnapshotHash(),7202);assertNotEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,wrong.status());assertNull(wrong.receipt());assertSame(before,f.store.snapshot());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,f.consume(2,second.receipt().inputSnapshotHash(),7203).status());
    }
    @Test void currentWorkflowCandidateSourceAndAgentHoldsBlockButUnusedOldRunDoesNotInherit(){
        for(int mode=0;mode<3;mode++){
            var f=new VirtualGrantContinuationFixture();f.blockAndRelease();
            var target=mode==0?new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.WORKFLOW,Map.of("workflowId",VirtualGrantContinuationFixture.id(1).toString())):
                    mode==1?new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.SOURCE_VERSION,Map.of("documentId",f.newApplication.source().documentId().toString(),"documentVersion",f.newApplication.source().documentVersion())):
                    new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.AGENT_VERSION,Map.of("agentId","synthetic-kyc","agentVersion",1));
            f.hold(target);var before=f.store.snapshot();var out=f.advance(f.firstCommand());assertNotEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());assertNull(out.receipt());assertSame(before,f.store.snapshot());
        }
        var f=new VirtualGrantContinuationFixture();f.hold(new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.RUN,Map.of("runId",f.oldRootCommand.identity().targetRunId().toString())));
        var out=f.advance(f.firstCommand());assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());assertEquals(2,f.workflow().get("generation"));
    }
    @Test void staleOldGrantCannotPrepareOrConsumeFreshWorkAfterAdvance(){
        var f=new VirtualGrantContinuationFixture();f.blockAndRelease();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,f.advance(f.firstCommand()).status());
        var before=f.store.snapshot();
        var preparation=new SyntheticKycPreparationService(f.journal,(context,command,tx)->Gate.CLEAR).prepare(f.context,f.seed.preparation());
        assertNotEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,preparation.status());assertNull(preparation.receipt());assertSame(before,f.store.snapshot());
        var stale=f.consume(1,"a".repeat(64),7301);
        assertNotEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,stale.status());assertNull(stale.receipt());assertSame(before,f.store.snapshot());
    }
    @Test void unsafeCatalogCandidateCommitsOnlyDedicatedDeniedProjectionWithoutNewRootHead(){
        var f=new VirtualGrantContinuationFixture();f.blockAndRelease();var a=f.newApplication;var d=a.source();
        var unsafe=new SimulationSpec.Source(d.documentId(),d.documentVersion(),d.text(),d.contentHash(),false);
        var app=new SimulationSpec.Application(a.fixtureId(),a.businessReference(),a.customerId(),a.amountKrw(),a.payoutAccountId(),a.monthlyIncomeKrw(),a.maxLoanAmountKrw(),a.ownsActiveAccount(),unsafe);
        var command=f.command(2,f.firstPrior(),7402,app);var before=f.store.snapshot();
        var out=f.service(new SimulationSpec.Catalog(List.of(app),List.of())).continueWorkflow(f.context,command);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());assertEquals(ContinuationKind.DENIED,out.receipt().kind());assertEquals(1,out.receipt().committedGeneration());assertNull(out.receipt().publishedHeadRevision());
        assertEquals("ON_HOLD",f.workflow().get("state"));assertEquals("DENY",f.workflow().get("lastDecision"));assertEquals(List.of("RESUME_BLOCKED"),f.workflow().get("reasonCodes"));
        for(String table:List.of("virtual_grant_profile_grants","virtual_grant_profile_target_bindings","virtual_grant_profile_root_receipts","virtual_workflow_lanes","virtual_grant_profile_stage_charges"))assertEquals(before.get(table),f.store.snapshot().get(table));
        assertEquals(before.get("virtual_grant_profile_current_heads"),f.store.snapshot().get("virtual_grant_profile_current_heads"));assertEquals(1,f.workflow().get("generation"));
    }
    static final class MissingCurrentReadStore implements com.finsec.fuse.reimplementation.persistence.TransactionalStore {
        final com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore delegate=new com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore();
        String hiddenTable;int hiddenReads;
        public String mode(){return delegate.mode();}
        public Map<String,Map<String,Map<String,Object>>> snapshot(){return delegate.snapshot();}
        public <R> R transaction(java.util.function.Function<Tx,R> work){return delegate.transaction(tx->work.apply(new Tx(){
            public Map<String,Object> get(String table,String key){
                if(table.equals(hiddenTable)&&key.equals(VirtualGrantContinuationFixture.id(1).toString())){hiddenReads++;return null;}
                return tx.get(table,key);
            }
            public Map<String,Map<String,Object>> rows(String table){return tx.rows(table);}
            public void put(String table,String key,Map<String,Object> row){tx.put(table,key,row);}
        }));}
    }
    static ContinuationCommand throughThree(VirtualGrantContinuationFixture f){
        f.blockAndRelease();var c2=f.firstCommand();var out=f.advance(c2);assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());
        f.blockAndRelease();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,f.advance(f.command(3,f.expected(out.receipt()),6003)).status());
        assertEquals(3,f.workflow().get("generation"));
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,f.continuations.reconcileContinuation(f.context,c2).status());return c2;
    }
    static void unconfirmedHistory(VirtualGrantContinuationFixture f,ContinuationCommand c2){
        var before=f.store.snapshot();int resolved=f.resolutions.get();var out=f.continuations.reconcileContinuation(f.context,c2);
        assertTrue(Set.of(Status.UNCONFIRMED_BEFORE_ADMISSION,Status.RECONCILIATION_UNCONFIRMED,Status.TRANSACTION_INVARIANT_UNCONFIRMED).contains(out.status()));
        assertNull(out.receipt());assertFalse(out.actualAuthority());assertFalse(out.durable());assertEquals(resolved,f.resolutions.get());assertSame(before,f.store.snapshot());
    }
    @Test void missingActualCurrentLaneOrGenerationThreeHeadCannotDiscloseValidOldGenerationReceipt(){
        for(String table:List.of("virtual_workflow_lanes","virtual_grant_profile_current_heads")){
            var store=new MissingCurrentReadStore();var f=new VirtualGrantContinuationFixture(store);var c2=throughThree(f);
            var oldOrigin=f.store.snapshot().get("virtual_grant_profile_generations").get(VirtualGrantContinuationFixture.id(1)+":2");
            store.hiddenTable=table;unconfirmedHistory(f,c2);assertTrue(store.hiddenReads>0);
            assertEquals(oldOrigin,f.store.snapshot().get("virtual_grant_profile_generations").get(VirtualGrantContinuationFixture.id(1)+":2"));
            store.hiddenTable=null;assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,f.continuations.reconcileContinuation(f.context,c2).status());
        }
    }
    @Test void actualCurrentCustomerGenerationLaneAndRootMismatchCannotBeHiddenByOldOwnHistory(){
        for(int mode=0;mode<4;mode++){
            var f=new VirtualGrantContinuationFixture();var c2=throughThree(f);final int variant=mode;
            f.store.transaction(tx->{String table=variant==2?"virtual_workflow_lanes":variant==3?"virtual_grant_profile_current_heads":"virtual_workflows";
                String key=VirtualGrantContinuationFixture.id(1).toString();var row=new LinkedHashMap<>(tx.get(table,key));
                if(variant==0)row.put("customerId","synthetic-wrong-current");
                if(variant==1)row.put("generation",0);
                if(variant==2)row.put("generation",2);
                if(variant==3)row.put("rootGrantId",VirtualGrantContinuationFixture.id(99999).toString());
                tx.put(table,key,row);return null;});
            unconfirmedHistory(f,c2);
        }
    }
    @Test void corruptedOwnOldGenerationOriginRemainsUnconfirmedAfterPositiveCurrentGenerationThree(){
        var f=new VirtualGrantContinuationFixture();var c2=throughThree(f);
        f.store.transaction(tx->{String key=VirtualGrantContinuationFixture.id(1)+":2";var row=new LinkedHashMap<>(tx.get("virtual_grant_profile_generations",key));
            row.put("rootTargetRunId",VirtualGrantContinuationFixture.id(99998).toString());tx.put("virtual_grant_profile_generations",key,row);return null;});
        unconfirmedHistory(f,c2);
    }

}
