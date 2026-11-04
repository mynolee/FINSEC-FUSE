package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.auth.*;
import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.persistence.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.*;
import static org.junit.jupiter.api.Assertions.*;

/** Actual virtual services and explicit synthetic facts; no authoritative origin adapter substitute. */
public final class VirtualGrantContinuationFixture {
    final VirtualGrantWorkflowBridgeTest.Fixture seed=new VirtualGrantWorkflowBridgeTest.Fixture();
    public final TransactionalStore store;
    public final VirtualGrantTransactionJournal journal;
    public final SimulationSpec.RiskTerms terms=seed.terms;
    public final RootCommand oldRootCommand=seed.root;
    public final SyntheticGrantIssuerBindings.Prepared registry=seed.registry;
    public final SimulationSpec.Application newApplication;
    public final SimulationSpec.Catalog continuationCatalog;
    public final SyntheticTypedContinuationService continuations;
    public final VirtualQuarantineService quarantines;
    public final AtomicInteger tokens=new AtomicInteger(5000),resolutions=new AtomicInteger(),currentChecks=new AtomicInteger();
    public Gate currentGate=Gate.CLEAR;
    public final SyntheticTypedContinuationService.ContinuationServerContext context=new SyntheticTypedContinuationService.ContinuationServerContext(){
        public String actorId(){return seed.context.actorId();}public String subjectId(){return seed.context.subjectId();}
    };
    public VirtualGrantContinuationFixture(){this(new VirtualTransactionalStore());}
    public VirtualGrantContinuationFixture(TransactionalStore actualStore){
        store=Objects.requireNonNull(actualStore);journal=new VirtualGrantTransactionJournal(store,()->id(tokens.incrementAndGet()),65536);
        var a=seed.f.app;
        newApplication=new SimulationSpec.Application(a.fixtureId(),a.businessReference(),a.customerId(),a.amountKrw(),a.payoutAccountId(),a.monthlyIncomeKrw(),a.maxLoanAmountKrw(),a.ownsActiveAccount(),seed.f.replacement);
        continuationCatalog=new SimulationSpec.Catalog(List.of(newApplication),seed.f.catalog.factsFor(a.customerId(),seed.f.clock.instant()));
        var access=new SimulationAccess((actor,operation,workflow,customer)->seed.f.permitted.get());
        var legacy=new VirtualWorkflowService(store,seed.f.catalog,terms,access,seed.f.clock,seed.f::id);
        quarantines=new VirtualQuarantineService(store,seed.f.catalog,access,legacy,(actor,target,remediation)->seed.f.remediationVerified.get(),seed.f.clock,seed.f::id);
        seed.facts.next();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,new SyntheticRootProvisionService(journal,seed.facts).provisionRoot(seed.context,oldRootCommand).status());
        continuations=service(continuationCatalog);
    }
    public SyntheticTypedContinuationService service(SimulationSpec.Catalog catalog){
        var facts=new SyntheticTypedContinuationService.CurrentContinuationFactResolver(){
            public Gate current(SyntheticTypedContinuationService.ContinuationServerContext c,ContinuationCommand command,OwnedTypedContinuationPort.OwnedContinuationTx tx){
                currentChecks.incrementAndGet();if(currentGate!=Gate.CLEAR)return currentGate;
                if(!seed.f.permitted.get() || !c.actorId().equals(context.actorId()) || !c.subjectId().equals(context.subjectId()))return Gate.REFUSED;
                var root=command.newRoot().claims();
                var t=new SyntheticGrantTemporalAssessment.TemporalFacts(command.observedAt().getEpochSecond(),root.issuedAt(),root.expiresAt(),SyntheticGrantTemporalAssessment.ChainPosition.ROOT,null);
                return SyntheticGrantTemporalAssessment.assess(t,seed.facts.rev()).blockers().isEmpty()?Gate.CLEAR:Gate.UNKNOWN;
            }
            public ResolvedContinuation resolve(SyntheticTypedContinuationService.ContinuationServerContext c,ContinuationCommand command,SyntheticTypedContinuationBinding.CurrentBindings ticket,OwnedTypedContinuationPort.OwnedContinuationTx tx){
                resolutions.incrementAndGet();var k=seed.facts.key;var root=command.newRoot().claims();
                var time=new SyntheticGrantTemporalAssessment.TemporalFacts(command.observedAt().getEpochSecond(),root.issuedAt(),root.expiresAt(),SyntheticGrantTemporalAssessment.ChainPosition.ROOT,null);
                return new ResolvedContinuation(command,ticket,new IssuerFacts(registry,seed.facts.descriptor),new KeyFacts(k.expected(),k.snapshot(),SyntheticGrantTemporalAssessment.Fact.CLEAR,k.material(),time,seed.facts.rev(),k.currentUse()));
            }
        };
        return catalog==null?new SyntheticTypedContinuationService(journal,facts):new SyntheticTypedContinuationService(journal,facts,catalog);
    }
    public static UUID id(long n){return VirtualGrantWorkflowBridgeTest.id(n);}
    public VirtualWorkflowLane.Scope scope(int generation){return new VirtualWorkflowLane.Scope(id(1),generation,newApplication.customerId());}
    public PriorExpectation firstPrior(){var i=oldRootCommand.identity();return new OriginalGenerationOne(scope(1),i.grantId(),i.globalRequestId(),i.targetRunId(),0);}
    public PriorExpectation expected(ContinuationReceipt receipt){return new ExistingHead(new VirtualGrantGenerationHistory.ExpectedHead(scope(receipt.committedGeneration()),receipt.identity().grantId(),receipt.publishedHeadRevision()));}
    public ContinuationCommand firstCommand(){return command(2,firstPrior(),6002);}
    public ContinuationCommand command(int generation,PriorExpectation prior,long request){return command(generation,prior,request,newApplication);}
    public ContinuationCommand command(int generation,PriorExpectation prior,long request,SimulationSpec.Application application){
        long offset=generation*100L;var action=new SyntheticGrantV2Codec.Action(id(10000+offset),id(1),generation,AllowedAction.EVALUATE_KYC,application.customerId(),application.amountKrw(),application.payoutAccountId(),id(10001+offset),null,VirtualGrantWorkflowBridgeTest.EVIDENCE,null,terms.policyVersion());
        var m=new LinkedHashMap<String,Object>();m.put("actionId",action.actionId().toString());m.put("workflowId",id(1).toString());m.put("generation",generation);m.put("allowedAction",action.allowedAction().name());m.put("customerId",action.customerId());m.put("amountKrw",action.amountKrw());m.put("payoutAccountId",action.payoutAccountId().toString());m.put("targetRunId",action.targetRunId().toString());m.put("sourceResultId",null);m.put("evidenceBundleHash",VirtualGrantWorkflowBridgeTest.EVIDENCE);m.put("approvalId",null);m.put("policyVersion",terms.policyVersion());
        var c=oldRootCommand.inputs().claims();var claims=new SyntheticGrantV2Codec.Claims(c.format(),c.algorithm(),c.kid(),id(10002+offset),id(1),generation,c.rootAuthorizationId(),c.principalId(),c.originIntent(),c.issuer(),c.sourceAgent(),"synthetic-kyc",null,action.targetRunId(),action.allowedAction(),action.customerId(),action.amountKrw(),action.payoutAccountId(),null,action.evidenceBundleHash(),null,1,action.actionId(),CanonicalJson.sha256(m),terms.policyVersion(),id(10003+offset),null,100,400);
        var root=new RootInputs(VirtualGrantWorkflowBridgeTest.profile(),claims,action,SyntheticGrantV2Codec.prepare(VirtualGrantWorkflowBridgeTest.profile(),claims,action));
        var identity=new CommandIdentity(context.actorId(),id(request),"synthetic-continuation","synthetic-canonical",VirtualGrantWorkflowBridgeTest.HASH,claims.grantId(),action.actionId(),action.targetRunId(),id(1),generation,application.customerId());
        return new ContinuationCommand(identity,prior,root,application,terms,"synthetic-lane",oldRootCommand.workflowPlan().stageAgents(),Instant.ofEpochSecond(150));
    }
    public ContinuationOutcome advance(ContinuationCommand command){return continuations.continueWorkflow(context,command);}
    public Map<String,Object> workflow(){return store.snapshot().get("virtual_workflows").get(id(1).toString());}
    public UUID hold(VirtualQuarantineService.Target target){return UUID.fromString((String)quarantines.create(SimulationFixture.ACTOR,seed.f.id(),target,"SYNTHETIC_CONTAINMENT","").get("quarantineId"));}
    public void release(UUID q){quarantines.release(SimulationFixture.ACTOR,seed.f.id(),q,new VirtualQuarantineService.Remediation(SimulationFixture.DOCUMENT,2,List.of(SimulationFixture.ID_FACT),"synthetic checked",null,null));}
    public void blockAndRelease(){var q=hold(new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.WORKFLOW,Map.of("workflowId",id(1).toString())));release(q);assertEquals("BLOCKED",workflow().get("state"));}
    public SyntheticKycPreparationBinding.PreparationOutcome prepareCurrent(){
        int generation=(Integer)workflow().get("generation");
        UUID grant=generation==1?oldRootCommand.identity().grantId():id(10002+generation*100L);
        UUID action=generation==1?oldRootCommand.identity().actionId():id(10000+generation*100L);
        UUID target=generation==1?oldRootCommand.identity().targetRunId():id(10001+generation*100L);
        var source=generation==1?seed.f.source:newApplication.source();
        var command=new SyntheticKycPreparationBinding.PreparationCommand(new CommandIdentity(context.actorId(),id(7100+generation),"synthetic-preparation","synthetic-canonical",VirtualGrantWorkflowBridgeTest.HASH,grant,action,target,id(1),generation,newApplication.customerId()),source,seed.f.catalog.factsFor(newApplication.customerId(),seed.f.clock.instant()),terms,seed.f.clock.instant());
        var service=new SyntheticKycPreparationService(journal,(ctx,input,tx)->input.equals(command)&&seed.f.permitted.get()?Gate.CLEAR:Gate.UNKNOWN);
        return service.prepare(context,command);
    }
    public StageCommand stage(int generation,long request){return new StageCommand(new CommandIdentity(context.actorId(),id(request),"synthetic-stage","synthetic-canonical",VirtualGrantWorkflowBridgeTest.HASH,
            generation==1?oldRootCommand.identity().grantId():id(10002+generation*100L),generation==1?oldRootCommand.identity().actionId():id(10000+generation*100L),generation==1?oldRootCommand.identity().targetRunId():id(10001+generation*100L),id(1),generation,newApplication.customerId()),AllowedAction.EVALUATE_KYC);}
    public StageOutcome consume(int generation,String hash,long request){
        var command=stage(generation,request);var result=new OutsidePreparedResult(id(90000+generation),SyntheticGrantStageBinding.BusinessConclusion.POSITIVE,"AGENT_RESULT_BINDING_RECORD_1",new byte[]{1,2},new byte[]{3,4});
        var service=new GrantStageTransactionService(journal,new CurrentFactResolver(){
            public Gate current(ServerContext ctx,StageCommand c,OwnedTx tx){return currentGate;}
            public ResolvedStage resolve(ServerContext ctx,StageCommand c,OutsidePreparedResult p,OwnedTx tx){tx.requireKycPreparation(c,hash);return new ResolvedStage(tx.grant(c.identity().grantId()),p,SyntheticGrantStageBinding.RunStatus.VALIDATED,SyntheticGrantStageBinding.ResultStatus.VALIDATED,List.of(),hash);}
            public Gate checkIssuance(ServerContext ctx,StageCommand c,UUID parent,GrantSnapshot child,OwnedTx tx){throw new AssertionError("no implicit successor");}
        });return service.completeStage(context,command,result);
    }

}
