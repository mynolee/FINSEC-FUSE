package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.*;
import com.finsec.fuse.reimplementation.persistence.*;
import java.util.*;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.Status;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static org.junit.jupiter.api.Assertions.*;

/** Same-transaction virtual control; raw pending-plan fixtures are not product preparation APIs. */
class VirtualGrantWorkflowControlTest {
    static final String W="virtual_workflows",REFS="virtual_grant_profile_target_bindings",GRANTS="virtual_grant_profile_grants",
            RESULTS="virtual_grant_profile_results",PLANS="virtual_grant_profile_payment_plans",INVALID="virtual_grant_profile_payment_invalidations";
    static UUID id(long n){return VirtualGrantWorkflowBridgeTest.id(n);}
    static Map<String,Object> row(Object... fields){var r=new LinkedHashMap<String,Object>();for(int i=0;i<fields.length;i+=2)r.put((String)fields[i],fields[i+1]);return r;}
    static final class Context {
        final VirtualGrantWorkflowBridgeTest.Fixture data=new VirtualGrantWorkflowBridgeTest.Fixture();
        final VirtualProductAssembly product=data.typed(); final RootCommand root;
        UUID legacy;
        Context(boolean mixed){
            if(mixed)legacy=product.workflows().start(new WorkflowStartBoundary.Command(ACTOR,data.f.id(),data.f.app.request())).workflowId();
            var old=data.root.workflowPlan();var a=old.application();
            var app=new SimulationSpec.Application("synthetic-typed-control","synthetic-typed-control-business",a.customerId(),a.amountKrw(),
                    a.payoutAccountId(),a.monthlyIncomeKrw(),a.maxLoanAmountKrw(),a.ownsActiveAccount(),a.source());
            var plan=new TypedWorkflowPlan(old.workflowId(),old.generation(),app,old.riskTerms(),old.laneReference(),old.targetRunId(),old.stageAgents());
            root=new RootCommand(data.root.identity(),data.root.inputs(),plan);data.facts.next();
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,product.grantWorkflows().startTyped(data.context,root).status());
        }
        VirtualWorkflowLane.Scope scope(){return new VirtualWorkflowLane.Scope(root.identity().workflowId(),1,root.identity().customerId());}
        void complete(){data.prepare(product.grantWorkflows());data.facts.next();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                product.grantWorkflows().completeAgentStage(data.context,data.stage(),data.result()).status());}
        Map<String,Object> workflow(){return data.f.store.snapshot().get(W).get(id(1).toString());}
        UUID hold(VirtualQuarantineService.Target target){return UUID.fromString((String)product.quarantines().create(ACTOR,data.f.id(),target,"SYNTHETIC_CONTROL","").get("quarantineId"));}
        VirtualQuarantineService.Target workflowTarget(){return new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.WORKFLOW,Map.of("workflowId",id(1).toString()));}
    }
    static Map<String,Object> reference(Context f,long grant,long action,long run,Long sourceRun,Long sourceResult,Long result,String agent){
        return row("workflowId",id(1).toString(),"generation",1,"customerId",f.root.identity().customerId(),"targetRunId",id(run).toString(),
                "grantId",id(grant).toString(),"actionId",id(action).toString(),"documentId",f.data.f.source.documentId().toString(),"documentVersion",1,
                "agentId",agent,"agentVersion",1,"sourceRunId",sourceRun==null?null:id(sourceRun).toString(),
                "sourceResultId",sourceResult==null?null:id(sourceResult).toString(),"resultId",result==null?null:id(result).toString());
    }
    static Map<String,Object> grant(Context f,long grant,long action,long run,String operation,String state){
        return row("grantId",id(grant).toString(),"actionId",id(action).toString(),"targetRunId",id(run).toString(),"workflowId",id(1).toString(),
                "generation",1,"customerId",f.root.identity().customerId(),"action",operation,"state",state);
    }
    /** Exact raw control fixture only: no app method currently prepares these pending plans. */
    static Map<String,Object> pendingPlan(Context f){
        f.complete();Map<String,Object> plan=row("grantId",id(403).toString(),"actionId",id(103).toString(),"paymentId",id(703).toString(),
                "targetRunId",id(203).toString(),"approvalId",id(704).toString(),"reservationId",id(705).toString(),"workflowId",id(1).toString(),
                "generation",1,"customerId",f.root.identity().customerId(),"applicationId",id(706).toString(),"amountKrw",1000L,
                "payoutAccountId",f.data.f.app.payoutAccountId().toString(),"securityPolicyVersion",f.data.terms.policyVersion(),
                "reservationState","RESERVED","approvalState","RESERVED");
        f.data.f.store.transaction(tx->{
            tx.put(GRANTS,id(402).toString(),grant(f,402,102,202,"CREATE_LOAN_RECOMMENDATION","CONSUMED"));
            tx.put(RESULTS,id(601).toString(),Map.of("resultId",id(601).toString()));
            tx.put(REFS,id(202).toString(),reference(f,402,102,202,201L,600L,601L,"synthetic-loan"));
            tx.put(GRANTS,id(403).toString(),grant(f,403,103,203,"EXECUTE_MOCK_PAYMENT","ISSUED"));
            tx.put(REFS,id(203).toString(),reference(f,403,103,203,202L,601L,null,"synthetic-payment"));
            tx.put(PLANS,id(705).toString(),plan);return null;});return plan;
    }

    @Test void typedRunAndResultTargetsUseReferenceUnionWithoutFakeLegacyRunRows(){
        for(boolean resultTarget:List.of(false,true)){
            Context f=new Context(false);if(resultTarget)f.complete();
            var target=new VirtualQuarantineService.Target(resultTarget?VirtualQuarantineService.Scope.RESULT:VirtualQuarantineService.Scope.RUN,
                    resultTarget?Map.of("resultId",id(600).toString()):Map.of("runId",id(201).toString()));
            var grants=f.data.f.store.snapshot().get(GRANTS);UUID q=f.hold(target);
            assertEquals("BLOCKED",f.workflow().get("state"));assertEquals(grants,f.data.f.store.snapshot().get(GRANTS));
            assertTrue(f.data.f.store.snapshot().getOrDefault("virtual_runs",Map.of()).isEmpty());
            var impact=f.product.quarantines().impact(ACTOR,q);assertEquals(List.of(id(201).toString()),impact.get("historicalRunIds"));
            assertEquals(0,((Map<?,?>)impact.get("actual")).get("runCount"));
            assertEquals(List.of(id(1).toString()),impact.get("currentAffectedWorkflowIds"));
        }
    }

    @Test void sourceAndExplicitStageAgentHoldBeforeConsumptionDoNotInventJobsOrResults(){
        for(boolean agent:List.of(false,true)){
            Context f=new Context(false);var target=agent?new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.AGENT_VERSION,
                    Map.of("agentId","synthetic-kyc","agentVersion",1)):new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.SOURCE_VERSION,
                    Map.of("documentId",f.data.f.source.documentId().toString(),"documentVersion",1));
            f.hold(target);assertEquals("BLOCKED",f.workflow().get("state"));assertEquals(1,f.workflow().get("generation"));assertNull(f.workflow().get("activeJobId"));
            assertEquals("ISSUED",f.data.f.store.snapshot().get(GRANTS).get(id(401).toString()).get("state"));
            assertTrue(f.data.f.store.snapshot().getOrDefault(RESULTS,Map.of()).isEmpty());
            assertTrue(f.data.f.store.snapshot().getOrDefault("virtual_jobs",Map.of()).isEmpty());
            assertThrows(SimulationFailure.class,()->f.data.f.store.transaction(tx->{VirtualGrantWorkflowControl.requireFreshBusiness(tx,f.scope());return null;}));
        }
    }

    @Test void mixedSourceHoldBlocksActualLegacyAndTypedRowsWithoutChangingTypedCounters(){
        Context f=new Context(true);UUID q=f.hold(new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.SOURCE_VERSION,
                Map.of("documentId",f.data.f.source.documentId().toString(),"documentVersion",1)));
        assertNotNull(q);assertEquals("BLOCKED",f.workflow().get("state"));
        assertEquals("BLOCKED",f.data.f.store.snapshot().get(W).get(f.legacy.toString()).get("state"));
        assertEquals(0,f.workflow().get("usedRisk"));assertEquals(0,f.workflow().get("reservedRisk"));assertEquals(1,f.workflow().get("generation"));
        assertEquals("ISSUED",f.data.f.store.snapshot().get(GRANTS).get(id(401).toString()).get("state"));
    }

    @Test void pendingPlanTombstoneSurvivesReleaseAndCannotBeReactivatedByStateLabel(){
        Context f=new Context(false);var plan=pendingPlan(f);var beforeHistory=f.data.f.store.snapshot().get("virtual_grant_profile_root_receipts");
        UUID q=f.hold(f.workflowTarget());var tomb=f.data.f.store.snapshot().get(INVALID).get(id(705).toString());
        assertEquals(plan,tomb.get("plan"));assertEquals(q.toString(),tomb.get("quarantineId"));assertEquals(plan,f.data.f.store.snapshot().get(PLANS).get(id(705).toString()));
        f.product.quarantines().release(ACTOR,f.data.f.id(),q,new VirtualQuarantineService.Remediation(DOCUMENT,2,List.of(ID_FACT),"synthetic checked",null,null));
        assertEquals("BLOCKED",f.workflow().get("state"));assertEquals(1,f.workflow().get("generation"));assertNull(f.workflow().get("activeJobId"));
        assertEquals(tomb,f.data.f.store.snapshot().get(INVALID).get(id(705).toString()));assertEquals(beforeHistory,f.data.f.store.snapshot().get("virtual_grant_profile_root_receipts"));
        f.data.f.store.transaction(tx->{VirtualGrantWorkflowControl.requireCurrent(tx,f.scope());return null;});
        // Adversarial raw state-label challenge, not a public resume/provisioning API.
        f.data.f.store.transaction(tx->{var w=new LinkedHashMap<>(tx.get(W,id(1).toString()));w.put("state","KYC_PENDING");tx.put(W,id(1).toString(),w);return null;});
        var before=f.data.f.store.snapshot();assertThrows(SimulationFailure.class,()->f.data.f.store.transaction(tx->{
            VirtualGrantWorkflowControl.requirePaymentPlanUsable(tx,f.scope(),id(705));return null;}));assertEquals(before,f.data.f.store.snapshot());
    }

    @Test void missingDuplicateAndCyclicReferenceGraphsRefuseWithoutMutation(){
        for(int mode=0;mode<3;mode++){
            Context f=new Context(false);f.complete();final int m=mode;
            f.data.f.store.transaction(tx->{var r=new LinkedHashMap<>(tx.get(REFS,id(201).toString()));
                if(m==0){r.put("sourceRunId",id(999).toString());r.put("sourceResultId",id(998).toString());}
                if(m==1){tx.put(REFS,id(999).toString(),r);return null;}
                if(m==2){r.put("sourceRunId",id(201).toString());r.put("sourceResultId",id(600).toString());}
                tx.put(REFS,id(201).toString(),r);return null;});var before=f.data.f.store.snapshot();
            assertThrows(SimulationFailure.class,()->f.data.f.store.transaction(tx->{VirtualGrantWorkflowControl.requireCurrent(tx,f.scope());return null;}));
            assertEquals(before,f.data.f.store.snapshot());
        }
    }

    @Test void oldGenerationReferencesAreNotCopiedIntoAnIndependentCurrentGeneration(){
        Context f=new Context(false);f.data.f.store.transaction(tx->{var w=new LinkedHashMap<>(tx.get(W,id(1).toString()));
            w.put("generation",2);tx.put(W,id(1).toString(),w);var lane=new LinkedHashMap<>(tx.get("virtual_workflow_lanes",id(1).toString()));
            lane.put("generation",2);tx.put("virtual_workflow_lanes",id(1).toString(),lane);return null;});var before=f.data.f.store.snapshot();
        assertThrows(SimulationFailure.class,()->f.data.f.store.transaction(tx->{VirtualGrantWorkflowControl.requireCurrent(tx,
                new VirtualWorkflowLane.Scope(id(1),2,f.root.identity().customerId()));return null;}));assertEquals(before,f.data.f.store.snapshot());
        assertEquals(1,f.data.f.store.snapshot().get(REFS).get(id(201).toString()).get("generation"));
    }

    static final class LateFailureStore implements TransactionalStore {
        final Context f;boolean legacyStaged;
        LateFailureStore(Context f){this.f=f;}
        public String mode(){return f.data.f.store.mode();}
        public Map<String,Map<String,Map<String,Object>>> snapshot(){return f.data.f.store.snapshot();}
        public <T>T transaction(Function<Tx,T> work){return f.data.f.store.transaction(tx->work.apply(new Tx(){
            public Map<String,Object> get(String table,String key){return tx.get(table,key);}
            public Map<String,Map<String,Object>> rows(String table){return tx.rows(table);}
            public void put(String table,String key,Map<String,Object> value){
                if(table.equals(W)&&key.equals(f.legacy.toString())&&"BLOCKED".equals(value.get("state")))legacyStaged=true;
                if(table.equals(W)&&key.equals(id(1).toString())&&"BLOCKED".equals(value.get("state"))){assertTrue(legacyStaged);throw new IllegalStateException("synthetic late typed write");}
                tx.put(table,key,value);
            }
        }));}
    }
    @Test void lateTypedWriteFailureRollsBackPreviouslyStagedLegacyHoldAndJournal(){
        Context f=new Context(true);LateFailureStore store=new LateFailureStore(f);
        var service=new VirtualQuarantineService(store,f.data.f.catalog,f.data.f.access,f.product.workflows(),
                (actor,target,remediation)->true,f.data.f.clock,f.data.f::id);var before=f.data.f.store.snapshot();
        var target=new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.SOURCE_VERSION,
                Map.of("documentId",f.data.f.source.documentId().toString(),"documentVersion",1));
        assertThrows(IllegalStateException.class,()->service.create(ACTOR,f.data.f.id(),target,"SYNTHETIC_CONTROL",""));
        assertTrue(store.legacyStaged);assertEquals(before,f.data.f.store.snapshot());
    }

    @Test void currentAuthorizationDenialPrecedesControlMutation(){
        Context f=new Context(false);f.data.f.permitted.set(false);var before=f.data.f.store.snapshot();
        assertEquals(403,assertThrows(SimulationFailure.class,()->f.hold(f.workflowTarget())).status());assertEquals(before,f.data.f.store.snapshot());
    }
    @Test void paidStateLabelAloneCannotExcludeUnpaidTypedWorkflowFromControl(){
        Context f=new Context(false);var grants=f.data.f.store.snapshot().get(GRANTS);
        f.data.f.store.transaction(tx->{var w=new LinkedHashMap<>(tx.get(W,id(1).toString()));w.put("state","PAID");tx.put(W,id(1).toString(),w);return null;});
        f.hold(f.workflowTarget());assertEquals("BLOCKED",f.workflow().get("state"));
        assertEquals(grants,f.data.f.store.snapshot().get(GRANTS));assertTrue(f.data.f.store.snapshot().getOrDefault("virtual_grant_profile_payments",Map.of()).isEmpty());
    }

    @Test void remediationDiagnosticRedactsCanaryWithoutChangingRecordValues(){
        String note="synthetic-note-canary";
        var r=new VirtualQuarantineService.Remediation(DOCUMENT,2,List.of(ID_FACT),note,"synthetic-kyc",1);
        assertEquals("Remediation[REDACTED]",String.valueOf(r));assertFalse(String.valueOf(r).contains(note));
        assertFalse(String.valueOf(r).contains(DOCUMENT.toString()));assertFalse(String.valueOf(r).contains("synthetic-kyc"));
        assertEquals(note,r.note());assertEquals(DOCUMENT,r.safeDocumentId());
        var equal=new VirtualQuarantineService.Remediation(DOCUMENT,2,List.of(ID_FACT),note,"synthetic-kyc",1);
        assertEquals(r,equal);assertEquals(r.hashCode(),equal.hashCode());
    }
}
