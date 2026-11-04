package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment;
import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.*;

/** Real reference Journal/services with explicitly permissive synthetic facts, never authority proof. */
class VirtualGrantEvaluationRefusalBoundaryTest {
    static UUID id(long n){return VirtualGrantWorkflowBridgeTest.id(n);}
    static final String W="virtual_workflows",G="virtual_grant_profile_grants",R="virtual_grant_profile_results",C="virtual_grant_profile_stage_charges";
    static final class Fixture {
        final VirtualGrantWorkflowBridgeTest.Fixture seed=new VirtualGrantWorkflowBridgeTest.Fixture();
        final AtomicInteger tokens=new AtomicInteger(1900);
        final VirtualGrantTransactionJournal journal=new VirtualGrantTransactionJournal(seed.f.store,()->id(tokens.incrementAndGet()),65536);
        final SimulationSpec.RiskTerms terms;
        final RootCommand root;
        final StageFacts facts=new StageFacts(this);
        final GrantStageTransactionService stages=new GrantStageTransactionService(journal,facts);
        final StageCommand loan;
        String inputHash;
        Fixture(int baseLimit){this(baseLimit,false);}
        Fixture(int baseLimit,boolean includePaymentAgent){
            var old=seed.root.workflowPlan();var t=old.riskTerms();
            terms=new SimulationSpec.RiskTerms(t.policyVersion(),1,2,t.payPoints(),baseLimit,t.additionalApprovalLimit(),t.maxAutomaticKycRuns(),t.approvalLifetime());
            var agents=new LinkedHashMap<>(old.stageAgents());agents.put(AllowedAction.CREATE_LOAN_RECOMMENDATION,new AgentReference("synthetic-loan",1));
            if(includePaymentAgent)agents.put(AllowedAction.EXECUTE_MOCK_PAYMENT,new AgentReference("synthetic-payment",1));
            var plan=new TypedWorkflowPlan(old.workflowId(),1,old.application(),terms,old.laneReference(),old.targetRunId(),agents);
            root=new RootCommand(seed.root.identity(),seed.root.inputs(),plan);seed.facts.next();
            var started=new SyntheticRootProvisionService(journal,seed.facts).provisionRoot(seed.context,root);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,started.status());
            var prepIdentity=identity(1802,401,101,201,"synthetic-explicit-preparation");
            var fact=new SimulationSpec.Fact(id(1999),root.identity().customerId(),SimulationSpec.Kind.ID_DOC,SimulationSpec.Outcome.PASS,true,
                    Instant.ofEpochSecond(100),Instant.ofEpochSecond(400));
            var prep=new PreparationCommand(prepIdentity,seed.f.source,List.of(fact),terms,Instant.ofEpochSecond(150));
            var prepared=new SyntheticKycPreparationService(journal,(context,command,tx)->Gate.CLEAR).prepare(seed.context,prep);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,prepared.status());assertEquals(Decision.PREPARED,prepared.receipt().decision());
            assertEquals(1,prepared.receipt().chargedPoints());inputHash=prepared.receipt().inputSnapshotHash();
            var kyc=new StageCommand(identity(1801,401,101,201,"synthetic-kyc-consumption"),AllowedAction.EVALUATE_KYC);
            assertNotEquals(prepIdentity.globalRequestId(),kyc.identity().globalRequestId());
            var completed=stages.completeStage(seed.context,kyc,result(1600));assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,completed.status());
            var child=new GrantSnapshot(id(1402),id(1102),id(1202),id(1),1,root.identity().customerId(),AllowedAction.CREATE_LOAN_RECOMMENDATION,GrantState.ISSUED);
            var issuance=new StageCommand(identity(1803,1402,1102,1202,"synthetic-loan-issuance"),AllowedAction.CREATE_LOAN_RECOMMENDATION);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,stages.issueSuccessor(seed.context,issuance,id(401),child).status());
            loan=new StageCommand(identity(1804,1402,1102,1202,"synthetic-loan-consumption"),AllowedAction.CREATE_LOAN_RECOMMENDATION);
        }
        CommandIdentity identity(long request,long grant,long action,long run,String operation){var i=seed.root.identity();
            return new CommandIdentity(i.actorId(),id(request),operation,i.canonicalizationVersion(),i.canonicalBodyDigest(),id(grant),id(action),id(run),i.workflowId(),1,i.customerId());}
        Map<String,Object> workflow(){return seed.f.store.snapshot().get(W).get(id(1).toString());}
        StageOutcome evaluateLoan(){return stages.completeStage(seed.context,loan,result(1601));}
    }
    static OutsidePreparedResult result(long n){return new OutsidePreparedResult(id(n),SyntheticGrantStageBinding.BusinessConclusion.POSITIVE,
            "AGENT_RESULT_BINDING_RECORD_1",new byte[]{1,2},new byte[]{3,4});}
    static final class StageFacts implements CurrentFactResolver {
        final Fixture f;Gate gate=Gate.CLEAR;long now=150;int resolutions;
        StageFacts(Fixture f){this.f=f;}
        public Gate current(ServerContext context,StageCommand command,OwnedTx tx){
            if(gate!=Gate.CLEAR)return gate;
            var t=new SyntheticGrantTemporalAssessment.TemporalFacts(now,100,400,SyntheticGrantTemporalAssessment.ChainPosition.ROOT,null);
            return SyntheticGrantTemporalAssessment.assess(t,f.seed.facts.rev()).blockers().isEmpty()?Gate.CLEAR:Gate.UNKNOWN;
        }
        public ResolvedStage resolve(ServerContext context,StageCommand command,OutsidePreparedResult prepared,OwnedTx tx){
            resolutions++;var grant=tx.grant(command.identity().grantId());assertNotNull(grant);
            if(command.action()==AllowedAction.EVALUATE_KYC)tx.requireKycPreparation(command,f.inputHash);
            return new ResolvedStage(grant,prepared,SyntheticGrantStageBinding.RunStatus.VALIDATED,
                    SyntheticGrantStageBinding.ResultStatus.VALIDATED,List.of(),command.action()==AllowedAction.EVALUATE_KYC?f.inputHash:null);
        }
        public Gate checkIssuance(ServerContext context,StageCommand command,UUID parent,GrantSnapshot child,OwnedTx tx){
            if(child.action()==AllowedAction.EXECUTE_MOCK_PAYMENT)tx.bindCurrentIssuanceTime(command,Instant.ofEpochSecond(now));
            return Gate.CLEAR;
        }
    }

    @Test void sufficientBudgetPositiveControlConsumesLoanAndChargesExactlyOnce(){
        Fixture f=new Fixture(3);var outcome=f.evaluateLoan();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,outcome.status());
        assertNull(outcome.evaluationRefusal());assertEquals(id(1601),outcome.receipt().result().resultId());
        var snapshot=f.seed.f.store.snapshot();assertEquals("CONSUMED",snapshot.get(G).get(id(1402).toString()).get("state"));
        assertEquals(3,f.workflow().get("usedRisk"));assertEquals(1,f.workflow().get("kycRuns"));
        assertEquals(2,snapshot.get(C).get(id(1)+":LOAN").get("points"));
        var before=f.seed.f.store.snapshot();assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,f.evaluateLoan().status());assertEquals(before,f.seed.f.store.snapshot());
    }
    @Test void insufficientBudgetCommitsOnlyDedicatedRefusalAndPreservesKycAndIssuedLoan(){
        Fixture f=new Fixture(1);var before=f.seed.f.store.snapshot();var outcome=f.evaluateLoan();
        assertEquals(Status.REFUSED_BEFORE_ADMISSION,outcome.status());assertNull(outcome.receipt());assertNotNull(outcome.evaluationRefusal());
        assertEquals("RISK_LIMIT_EXCEEDED",outcome.reason());assertEquals("ON_HOLD",outcome.evaluationRefusal().state());
        assertEquals("DENY",outcome.evaluationRefusal().decision());assertEquals(id(1600),outcome.evaluationRefusal().retainedKycResultId());
        assertEquals(EffectKnowledge.NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION,outcome.effectKnowledge());assertFalse(outcome.actualAuthority());assertFalse(outcome.durable());
        var after=f.seed.f.store.snapshot();assertEquals(before.get(R),after.get(R));assertFalse(after.get(R).containsKey(id(1601).toString()));
        assertEquals(before.get(G),after.get(G));assertEquals("ISSUED",after.get(G).get(id(1402).toString()).get("state"));
        assertEquals(before.get(C),after.get(C));assertFalse(after.get(C).containsKey(id(1)+":LOAN"));
        assertEquals("ON_HOLD",f.workflow().get("state"));assertEquals("DENY",f.workflow().get("lastDecision"));
        assertEquals(1,f.workflow().get("usedRisk"));assertEquals(0,f.workflow().get("reservedRisk"));assertEquals(1,f.workflow().get("kycRuns"));
        assertEquals(id(1600).toString(),f.workflow().get("currentKycResultId"));assertNull(f.workflow().get("currentLoanResultId"));
        assertNotNull(after.get(ActionJournal.TABLE).get(f.loan.identity().globalRequestId().toString()).get("reply"));
    }
    @Test void exactRefusalReplayAndReconcileDoNotResolveOrWriteAgain(){
        Fixture f=new Fixture(1);var first=f.evaluateLoan();var before=f.seed.f.store.snapshot();int resolves=f.facts.resolutions;
        var replay=f.evaluateLoan();assertEquals(first,replay);assertEquals(resolves,f.facts.resolutions);assertEquals(before,f.seed.f.store.snapshot());
        var reconciled=f.stages.reconcile(f.seed.context,f.loan);assertEquals(first,reconciled);assertEquals(before,f.seed.f.store.snapshot());
    }
    @Test void currentDenialAndOrdinaryExpiryPrecedeStoredRefusalDisclosure(){
        for(boolean expiry:List.of(false,true)){
            Fixture f=new Fixture(1);assertNotNull(f.evaluateLoan().evaluationRefusal());var before=f.seed.f.store.snapshot();int resolves=f.facts.resolutions;
            if(expiry)f.facts.now=400;else f.facts.gate=Gate.REFUSED;
            var denied=f.evaluateLoan();assertNull(denied.evaluationRefusal());assertNull(denied.receipt());
            assertEquals(expiry?Status.UNCONFIRMED_BEFORE_ADMISSION:Status.REFUSED_BEFORE_ADMISSION,denied.status());
            assertEquals(resolves,f.facts.resolutions);assertEquals(before,f.seed.f.store.snapshot());
        }
    }
    @Test void malformedExistingLedgerIsUnknownWithoutManufacturingRefusalOrNewResult(){
        Fixture f=new Fixture(1);f.seed.f.store.transaction(tx->{var row=new LinkedHashMap<>(tx.get(W,id(1).toString()));row.put("usedRisk",0);tx.put(W,id(1).toString(),row);return null;});
        var before=f.seed.f.store.snapshot();var outcome=f.evaluateLoan();assertNull(outcome.evaluationRefusal());assertNull(outcome.receipt());
        assertEquals(Status.TRANSACTION_INVARIANT_UNCONFIRMED,outcome.status());assertEquals(EffectKnowledge.UNKNOWN,outcome.effectKnowledge());
        assertEquals(before,f.seed.f.store.snapshot());
    }
}
