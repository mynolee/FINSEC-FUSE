package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.auth.*;
import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.Fact;
import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.*;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit real virtual graph calls; supplied facts are not authenticated authority. */
class VirtualGrantWorkflowBridgeTest {
    static UUID id(long n){return new UUID(17,n);}
    static final String HASH="a".repeat(64),EVIDENCE="c".repeat(64);
    static SyntheticGrantV2Codec.Profile profile(){return new SyntheticGrantV2Codec.Profile(16384,8192,8,64,1000,300);}
    static SyntheticGrantIssuerBindings.Binding binding(){return new SyntheticGrantIssuerBindings.Binding("synthetic-subject",id(7),
            "synthetic-principal","synthetic-issuer",SyntheticGrantIssuerBindings.Stage.KYC_EVALUATOR,AllowedAction.EVALUATE_KYC,
            "synthetic-customer-1",id(4),id(1),"synthetic-intent",new SyntheticGrantIssuerBindings.KeyReference(
            "synthetic-key","HMAC-SHA256","synthetic-owner-reference"));}
    static SyntheticGrantIssuerBindings.Prepared registry(){return SyntheticGrantIssuerBindings.prepare("synthetic-registry",List.of(binding()),
            new SyntheticGrantIssuerBindings.Limits(4,128));}
    static final class Fixture {
        final SimulationFixture f=new SimulationFixture();
        final SimulationSpec.RiskTerms terms=new SimulationSpec.RiskTerms("SYNTHETIC-POLICY-1",1,2,3,20,5,2,Duration.ofMinutes(5));
        final SyntheticGrantV2Codec.Action action=new SyntheticGrantV2Codec.Action(id(101),id(1),1,AllowedAction.EVALUATE_KYC,
                f.app.customerId(),f.app.amountKrw(),f.app.payoutAccountId(),id(201),null,EVIDENCE,null,terms.policyVersion());
        final SyntheticGrantV2Codec.Claims claims;
        final RootCommand root;
        final SyntheticGrantIssuerBindings.Prepared registry=registry();
        final Facts facts;
        String preparedHash;
        final AtomicInteger providers=new AtomicInteger(),tokens=new AtomicInteger(900);
        final SyntheticRootProvisionService.RootServerContext context=new SyntheticRootProvisionService.RootServerContext(){
            public String actorId(){return "synthetic-actor-alias";}public String subjectId(){return "synthetic-subject";}
        };
        Fixture(){
            var m=new LinkedHashMap<String,Object>();m.put("actionId",action.actionId().toString());m.put("workflowId",id(1).toString());
            m.put("generation",1);m.put("allowedAction",action.allowedAction().name());m.put("customerId",action.customerId());
            m.put("amountKrw",action.amountKrw());m.put("payoutAccountId",action.payoutAccountId().toString());
            m.put("targetRunId",action.targetRunId().toString());m.put("sourceResultId",null);m.put("evidenceBundleHash",EVIDENCE);
            m.put("approvalId",null);m.put("policyVersion",terms.policyVersion());
            claims=new SyntheticGrantV2Codec.Claims("FUSE-GRANT-v2","HMAC-SHA256","synthetic-key",id(401),id(1),1,id(4),
                    "synthetic-principal","synthetic-intent","synthetic-issuer","synthetic-source","synthetic-kyc",null,id(201),
                    action.allowedAction(),action.customerId(),action.amountKrw(),action.payoutAccountId(),null,EVIDENCE,null,1,
                    action.actionId(),CanonicalJson.sha256(m),terms.policyVersion(),id(5),null,100,400);
            var inputs=new RootInputs(profile(),claims,action,SyntheticGrantV2Codec.prepare(profile(),claims,action));
            var plan=new TypedWorkflowPlan(id(1),1,f.app,terms,"synthetic-lane",id(201),
                    Map.of(AllowedAction.EVALUATE_KYC,new AgentReference("synthetic-kyc",1)));
            var identity=new CommandIdentity(context.actorId(),id(800),"synthetic-root","supplied-command-profile",HASH,
                    id(401),id(101),id(201),id(1),1,f.app.customerId());root=new RootCommand(identity,inputs,plan);
            facts=new Facts(this);
        }
        VirtualProductAssembly.Inputs inputs(){return new VirtualProductAssembly.Inputs(f.store,f.catalog,terms,
                (actor,operation,workflow,customer)->f.permitted.get(),(actor,target,remediation)->f.remediationVerified.get(),List.of(),
                new VirtualExperimentService.PairEvaluator(){
                    public String mode(){return VirtualTransactionalStore.MODE;}
                    public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,String caseId,int repeat,Map<String,Object> shared){
                        providers.incrementAndGet();return new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.WAIT_APPROVAL,VirtualExperimentService.Reason.SYNTHETIC_REVIEW);}
                },f.clock,f::id,(request,operation,workflow,customer)->SimulationFixture.ACTOR,
                (request,operation,workflow)->SimulationFixture.ACTOR,new HttpLimits(4096,8192,16));}
        VirtualProductAssembly typed(){return VirtualProductAssembly.composeTyped(inputs(),new VirtualProductAssembly.TypedInputs(registry,facts,()->id(tokens.incrementAndGet()),65536));}
        StageCommand stage(){var i=root.identity();return new StageCommand(new CommandIdentity(i.actorId(),id(801),"synthetic-stage",
                i.canonicalizationVersion(),i.canonicalBodyDigest(),i.grantId(),i.actionId(),i.targetRunId(),i.workflowId(),1,i.customerId()),AllowedAction.EVALUATE_KYC);}
        SyntheticKycPreparationBinding.PreparationCommand preparation(){var i=root.identity();
            return new SyntheticKycPreparationBinding.PreparationCommand(new CommandIdentity(i.actorId(),id(802),"synthetic-prepare",
                    i.canonicalizationVersion(),i.canonicalBodyDigest(),i.grantId(),i.actionId(),i.targetRunId(),i.workflowId(),i.generation(),i.customerId()),
                    f.source,f.catalog.factsFor(i.customerId(),f.clock.instant()),terms,f.clock.instant());}
        void prepare(VirtualGrantWorkflowBridge bridge){facts.next();var c=preparation();
            var out=bridge.prepareKyc(context,c);assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());
            assertEquals(SyntheticKycPreparationBinding.Decision.PREPARED,out.receipt().decision());
            preparedHash=out.receipt().inputSnapshotHash();assertNotNull(preparedHash);
            assertEquals(terms.kycPoints(),out.receipt().chargedPoints());
            assertNotEquals(c.identity().globalRequestId(),stage().identity().globalRequestId());
            assertFalse(out.actualAuthority());assertFalse(out.durable());assertEquals(0,providers.get());}
        OutsidePreparedResult result(){return new OutsidePreparedResult(id(600),SyntheticGrantStageBinding.BusinessConclusion.POSITIVE,
                "AGENT_RESULT_BINDING_RECORD_1",new byte[]{1,2},new byte[]{3,4});}
    }
    static final class Facts implements VirtualGrantWorkflowBridge.Facts {
        final Fixture f;Gate gate=Gate.CLEAR;int rootChecks,rootResolves,stageLoads,paymentLoads;
        boolean replaceRegistry;OwnedRootProvisionPort.OwnedRootTx rootTx;OwnedTx stageTx;
        final VirtualGrantFactResolver.Descriptor descriptor;
        final VirtualGrantFactResolver.KeyFacts key;
        Facts(Fixture f){this.f=f;descriptor=new VirtualGrantFactResolver.Descriptor(f.context.actorId(),binding(),"synthetic-owner-reference","synthetic-key-version");
            var k=new SyntheticGrantKeyLifecycleAssessment.KeyBinding("synthetic-key","synthetic-issuer","HMAC-SHA256","synthetic-key-version");
            key=new VirtualGrantFactResolver.KeyFacts(k,new SyntheticGrantKeyLifecycleAssessment.KeySnapshot(k,SyntheticGrantKeyLifecycleAssessment.Lifecycle.ACTIVE),
                    SyntheticGrantKeyLifecycleAssessment.Ordering.BEFORE_RETIREMENT,SyntheticGrantKeyLifecycleAssessment.MaterialFact.AVAILABLE,Fact.CLEAR,
                    new SyntheticGrantKeyLifecycleAssessment.CurrentUseFacts(Fact.CLEAR,Fact.CLEAR,Fact.CLEAR,Fact.CLEAR,Fact.CLEAR,Fact.CLEAR));}
        void next(){rootTx=null;stageTx=null;}
        public Gate current(SyntheticRootProvisionService.RootServerContext c,RootCommand command,OwnedRootProvisionPort.OwnedRootTx tx){
            if(rootTx==null)rootTx=tx;else assertSame(rootTx,tx);rootChecks++;return gate;}
        public ResolvedRootProvision resolve(SyntheticRootProvisionService.RootServerContext c,RootCommand command,CurrentBindings ticket,OwnedRootProvisionPort.OwnedRootTx tx){
            assertSame(rootTx,tx);rootResolves++;
            var issuer=new IssuerFacts(replaceRegistry?registry():f.registry,descriptor);
            var k=new SyntheticRootProvisionBinding.KeyFacts(key.expected(),key.snapshot(),Fact.CLEAR,key.material(),time(),rev(),key.currentUse());
            return new ResolvedRootProvision(command,ticket,issuer,k);}
        SyntheticGrantTemporalAssessment.TemporalFacts time(){return new SyntheticGrantTemporalAssessment.TemporalFacts(150,100,400,
                SyntheticGrantTemporalAssessment.ChainPosition.ROOT,null);}
        SyntheticGrantTemporalAssessment.RevocationFacts rev(){return new SyntheticGrantTemporalAssessment.RevocationFacts(Fact.CLEAR,Fact.CLEAR,Fact.CLEAR,
                Fact.CLEAR,Fact.CLEAR,Fact.CLEAR,Fact.CLEAR,Fact.CLEAR,Fact.CLEAR);}
        public VirtualGrantFactResolver.Snapshot load(ServerContext context,StageCommand command,OwnedTx tx){
            if(stageTx==null)stageTx=tx;else assertSame(stageTx,tx);stageLoads++;
            var scope=new SyntheticGrantStageBinding.Scope(id(1),1,f.f.app.customerId());
            var body=new SyntheticGrantStageBinding.BodyBinding("synthetic-body-profile",new byte[]{'{','}'},HASH,Objects.requireNonNull(f.preparedHash),EVIDENCE,null,null,"synthetic-validation");
            var run=new SyntheticGrantStageBinding.RunSnapshot(id(201),id(101),scope,SyntheticGrantStageBinding.AgentRole.KYC,SyntheticGrantStageBinding.RunStatus.VALIDATED);
            var result=new SyntheticGrantStageBinding.ResultSnapshot(id(600),id(201),id(1),1,SyntheticGrantStageBinding.ResultStatus.VALIDATED,
                    SyntheticGrantStageBinding.BusinessConclusion.POSITIVE,body);
            var grant=new GrantSnapshot(id(401),id(101),id(201),id(1),1,f.f.app.customerId(),AllowedAction.EVALUATE_KYC,GrantState.ISSUED);
            var agent=new VirtualGrantFactResolver.AgentFacts(profile(),List.of(new SyntheticGrantChainStructure.Node(f.claims,f.action)),
                    new SyntheticGrantStageBinding.BindingProfile(2),run,result,new SyntheticGrantStageBinding.WorkflowSnapshot(scope),
                    new SyntheticGrantStageBinding.ExpectedResultBinding(id(600),body),new ResolvedStage(grant,f.result(),run.status(),result.status(),List.of(),f.preparedHash));
            var clear=new SyntheticGrantReplayAssessment.CurrentReadFacts(Fact.CLEAR,Fact.CLEAR,Fact.CLEAR,Fact.CLEAR,Fact.CLEAR,Fact.CLEAR,Fact.CLEAR);
            return new VirtualGrantFactResolver.Snapshot("synthetic-version",descriptor,clear,time(),rev(),key,agent,null);}
        public Fact versionChanged(ServerContext context,StageCommand command,OwnedTx tx,String expected){assertSame(stageTx,tx);assertEquals("synthetic-version",expected);return Fact.CLEAR;}
        public Gate current(ServerContext context,SyntheticKycPreparationBinding.PreparationCommand command,
                OwnedKycPreparationPort.OwnedPreparationTx tx){
            if(!f.f.permitted.get() || !context.actorId().equals(f.context.actorId()))return Gate.REFUSED;
            var expected=f.preparation();
            return command.identity().equals(expected.identity()) && command.source().equals(f.f.catalog.source(command.source().documentId(),command.source().documentVersion()))
                    && command.facts().equals(expected.facts()) && command.terms().equals(f.terms)
                    && command.preparedAt().equals(expected.preparedAt()) ? Gate.CLEAR:Gate.UNKNOWN;}
        public Gate current(SyntheticMockPaymentPlanService.PlanServerContext context,CommandIdentity identity,
                SyntheticMockPaymentPlanBinding.PlanOperation operation,OwnedMockPaymentPlanPort.OwnedPlanTx tx){return Gate.UNKNOWN;}
        public SyntheticMockPaymentPlanBinding.ResolvedEvidence resolveEvidence(SyntheticMockPaymentPlanService.PlanServerContext context,
                CommandIdentity identity,SyntheticMockPaymentPlanBinding.ReviewBindings bindings,OwnedMockPaymentPlanPort.OwnedPlanTx tx){
            throw new AssertionError("no implicit payment plan work");}
        public VirtualMockPaymentFactResolver.PaymentSnapshot loadPayment(ServerContext c,SyntheticMockPaymentTransactionBinding.PaymentCommand command,
                OwnedTx tx,VirtualGrantFactResolver.Snapshot base){paymentLoads++;throw new AssertionError("no implicit payment work");}
    }

    @Test void defaultLegacyGraphStaysExplicitlyUnconfiguredAndStillStartsLegacyWorkflow(){
        Fixture f=new Fixture();var product=VirtualProductAssembly.compose(f.inputs());
        var error=assertThrows(IllegalStateException.class,product::grantWorkflows);assertEquals("TYPED_WORKFLOW_NOT_CONFIGURED",error.getMessage());
        product.workflows().start(new WorkflowStartBoundary.Command(SimulationFixture.ACTOR,f.f.id(),f.f.app.request()));
        assertEquals(1,f.f.rows("virtual_workflows"));assertTrue(f.f.store.snapshot().getOrDefault("virtual_workflow_lanes",Map.of()).isEmpty());
        assertEquals(0,f.facts.rootResolves);assertEquals(0,f.providers.get());
    }
    @Test void typedCompositionHasNoRootJobProviderOrIdentifierSideEffects(){
        Fixture f=new Fixture();long ids=f.f.sequence.get();var product=f.typed();
        assertSame(f.f.store,product.store());assertTrue(product.store().snapshot().isEmpty());assertEquals(ids,f.f.sequence.get());
        assertEquals(900,f.tokens.get());assertEquals(0,f.facts.rootChecks);assertEquals(0,f.facts.stageLoads);assertEquals(0,f.providers.get());
        assertFalse(product.grantWorkflows().actualAuthorityEstablished());assertFalse(product.grantWorkflows().durable());
    }
    @Test void realRootServiceInitializesOneTypedWorkflowAndExactReplayWithoutJobDispatch(){
        Fixture f=new Fixture();var bridge=f.typed().grantWorkflows();f.facts.next();var first=bridge.startTyped(f.context,f.root);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,first.status());assertTrue(first.receipt().matches(f.root));
        var before=f.f.store.snapshot();assertEquals("TYPED",before.get("virtual_workflow_lanes").get(id(1).toString()).get("lane"));
        assertEquals(1,before.get("virtual_workflows").size());assertEquals(1,before.get("virtual_grant_profile_grants").size());
        assertTrue(before.getOrDefault("virtual_jobs",Map.of()).isEmpty());assertEquals(0,f.providers.get());
        f.facts.next();assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,bridge.startTyped(f.context,f.root).status());
        f.facts.next();assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,bridge.reconcileRoot(f.context,f.root).status());
        assertEquals(before,f.f.store.snapshot());assertEquals(1,f.facts.rootResolves);assertFalse(first.actualAuthority());assertFalse(first.durable());
    }
    @Test void currentDenialAndUnknownBeforeCachedRootDisclosurePreserveHistory(){
        Fixture f=new Fixture();var bridge=f.typed().grantWorkflows();f.facts.next();bridge.startTyped(f.context,f.root);var before=f.f.store.snapshot();
        for(Gate gate:List.of(Gate.REFUSED,Gate.UNKNOWN)){f.facts.gate=gate;f.facts.next();var denied=bridge.startTyped(f.context,f.root);
            assertEquals(gate==Gate.REFUSED?Status.REFUSED_BEFORE_ADMISSION:Status.UNCONFIRMED_BEFORE_ADMISSION,denied.status());
            assertNull(denied.receipt());assertEquals(before,f.f.store.snapshot());assertEquals(1,f.facts.rootResolves);}
    }
    @Test void equalRegistryContentFromAnotherPreparedInstanceIsNotTheGraphRegistry(){
        Fixture f=new Fixture();var product=f.typed();f.facts.replaceRegistry=true;f.facts.next();
        var result=product.grantWorkflows().startTyped(f.context,f.root);
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,result.status());assertNull(result.receipt());assertTrue(f.f.store.snapshot().isEmpty());
    }
    @Test void bridgeRejectsDetachedJournalRatherThanInferringApplicationContext(){
        Fixture f=new Fixture();var journal=VirtualGrantTransactionJournal.detachedReference(f.f.store,()->id(999),65536);
        var failure=assertThrows(IllegalStateException.class,()->new VirtualGrantWorkflowBridge(journal,f.registry,f.facts));
        assertEquals("OWNED_GRANT_APPLICATION_CONTEXT_REQUIRED",failure.getMessage());assertTrue(f.f.store.snapshot().isEmpty());
    }
    @Test void actualAgentCompletionThroughBridgeUsesResolverAndStrictSameStoreLane(){
        Fixture f=new Fixture();var product=f.typed();var bridge=product.grantWorkflows();f.facts.next();
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,bridge.startTyped(f.context,f.root).status());
        f.prepare(bridge);f.facts.next();var completed=bridge.completeAgentStage(f.context,f.stage(),f.result());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,completed.status());assertTrue(f.facts.stageLoads>=2);
        assertEquals(id(600),completed.receipt().result().resultId());
        var before=f.f.store.snapshot();f.facts.next();assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,bridge.reconcileStage(f.context,f.stage()).status());
        assertEquals(before,product.store().snapshot());assertEquals(0,f.facts.paymentLoads);assertEquals(0,f.providers.get());
        assertEquals(1,before.get("virtual_grant_profile_grants").size());assertFalse(completed.actualAuthority());assertFalse(completed.durable());
    }
    @Test void typedGraphLegacyWriterCannotUseAnotherRequestToMutateTheTypedRoot(){
        Fixture f=new Fixture();var product=f.typed();f.facts.next();
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,product.grantWorkflows().startTyped(f.context,f.root).status());
        var before=f.f.store.snapshot();
        var denied=assertThrows(SimulationFailure.class,()->product.workflows().prepareKyc(SimulationFixture.ACTOR,f.f.id(),id(1)));
        assertEquals(400,denied.status());assertEquals(before,f.f.store.snapshot());assertEquals(0,f.providers.get());
        f.facts.next();assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,product.grantWorkflows().reconcileRoot(f.context,f.root).status());
        assertEquals(before,f.f.store.snapshot());
    }
}
