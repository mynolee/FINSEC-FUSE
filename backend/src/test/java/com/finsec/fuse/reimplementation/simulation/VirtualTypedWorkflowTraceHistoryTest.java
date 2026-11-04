package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantV2Codec;
import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.persistence.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.*;
import static com.finsec.fuse.reimplementation.simulation.VirtualGrantWorkflowBridgeTest.id;
import static org.junit.jupiter.api.Assertions.*;

/** Actual virtual producers and metadata-only history; no provider, durable or authority proof. */
final class VirtualTypedWorkflowTraceHistoryTest {
    private static final String OPAQUE_CANARY="synthetic-trace-hidden-result-material";
    private static final Set<String> ARRAYS=Set.of("runs","results","grants","dependencies","approvals","riskEvents","payments","auditEvents");
    private static final Set<String> RESULT_KEYS=Set.of("resultId","runId","workflowId","generation","bindingProfile","bindingDigest");
    private static final Set<String> GRANT_KEYS=Set.of("grantId","actionId","targetRunId","workflowId","generation","action","state","status");
    private static final Set<String> DEPENDENCY_KEYS=Set.of("parentRunId","childRunId","parentResultId","generation");
    private static final class ObservedStore implements TransactionalStore {
        final VirtualTransactionalStore actual=new VirtualTransactionalStore(); int puts;
        public String mode(){return actual.mode();}
        public Map<String,Map<String,Map<String,Object>>> snapshot(){return actual.snapshot();}
        public <R> R transaction(java.util.function.Function<Tx,R> work){
            return actual.transaction(tx->work.apply(new Tx(){
                public Map<String,Object> get(String table,String key){return tx.get(table,key);}
                public Map<String,Map<String,Object>> rows(String table){return tx.rows(table);}
                public void put(String table,String key,Map<String,Object> row){puts++;tx.put(table,key,row);}
            }));
        }
    }
    private static final class Fixture {
        final VirtualGrantWorkflowBridgeTest.Fixture seed=new VirtualGrantWorkflowBridgeTest.Fixture();
        final ObservedStore store=new ObservedStore();
        final AtomicInteger tokens=new AtomicInteger(20000);
        final VirtualGrantTransactionJournal journal=new VirtualGrantTransactionJournal(store,()->id(tokens.incrementAndGet()),65536);
        final Map<AllowedAction,AgentReference> agents=Map.of(AllowedAction.EVALUATE_KYC,new AgentReference("synthetic-kyc",1),
                AllowedAction.CREATE_LOAN_RECOMMENDATION,new AgentReference("synthetic-loan",1));
        final RootCommand root;
        final SimulationSpec.Application candidate;
        final SimulationSpec.Catalog catalog;
        final VirtualQuarantineService quarantine;
        final SyntheticTypedContinuationService.ContinuationServerContext context=new SyntheticTypedContinuationService.ContinuationServerContext(){
            public String actorId(){return seed.context.actorId();}public String subjectId(){return seed.context.subjectId();}
        };
        final GrantSnapshot loan;
        ContinuationCommand expectedContinuation;
        Fixture(){
            var p=seed.root.workflowPlan();
            root=new RootCommand(seed.root.identity(),seed.root.inputs(),new TypedWorkflowPlan(p.workflowId(),p.generation(),p.application(),p.riskTerms(),
                    p.laneReference(),p.targetRunId(),agents));
            seed.facts.next();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,new SyntheticRootProvisionService(journal,seed.facts).provisionRoot(seed.context,root).status());
            var a=seed.f.app;
            candidate=new SimulationSpec.Application(a.fixtureId(),a.businessReference(),a.customerId(),a.amountKrw(),a.payoutAccountId(),
                    a.monthlyIncomeKrw(),a.maxLoanAmountKrw(),a.ownsActiveAccount(),seed.f.replacement);
            catalog=new SimulationSpec.Catalog(List.of(candidate),seed.f.catalog.factsFor(a.customerId(),seed.f.clock.instant()));
            var access=new SimulationAccess((actor,op,workflow,customer)->seed.f.permitted.get());
            var legacy=new VirtualWorkflowService(store,seed.f.catalog,seed.terms,access,seed.f.clock,seed.f::id);
            quarantine=new VirtualQuarantineService(store,seed.f.catalog,access,legacy,(actor,target,remediation)->seed.f.remediationVerified.get(),seed.f.clock,seed.f::id);
            loan=new GrantSnapshot(id(5501),id(5502),id(5503),id(1),1,a.customerId(),AllowedAction.CREATE_LOAN_RECOMMENDATION,GrantState.ISSUED);
        }
        CommandIdentity identity(int generation,long request,UUID grant,UUID action,UUID target){
            return new CommandIdentity(context.actorId(),id(request),"synthetic-trace-stage","synthetic-canonical",VirtualGrantWorkflowBridgeTest.HASH,
                    grant,action,target,id(1),generation,seed.f.app.customerId());
        }
        SyntheticKycPreparationBinding.PreparationReceipt prepare(int generation,UUID grant,UUID action,UUID target){
            var source=generation==1?seed.f.source:candidate.source();
            var c=new SyntheticKycPreparationBinding.PreparationCommand(identity(generation,7600+generation,grant,action,target),source,
                    seed.f.catalog.factsFor(seed.f.app.customerId(),seed.f.clock.instant()),seed.terms,seed.f.clock.instant());
            var service=new SyntheticKycPreparationService(journal,(ctx,value,tx)->value.equals(c)&&context.actorId().equals(ctx.actorId())
                    &&seed.f.permitted.get()?Gate.CLEAR:Gate.UNKNOWN);
            var out=service.prepare(context,c);assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());assertNotNull(out.receipt());
            assertEquals(SyntheticKycPreparationBinding.Decision.PREPARED,out.receipt().decision());return out.receipt();
        }
        StageOutcome consume(int generation,UUID grant,UUID action,UUID target,String inputHash){
            var c=new StageCommand(identity(generation,7700+generation,grant,action,target),AllowedAction.EVALUATE_KYC);
            var prepared=new OutsidePreparedResult(id(90000+generation),SyntheticGrantStageBinding.BusinessConclusion.POSITIVE,
                    "AGENT_RESULT_BINDING_RECORD_1",OPAQUE_CANARY.getBytes(StandardCharsets.US_ASCII),new byte[]{3,4});
            var service=new GrantStageTransactionService(journal,new CurrentFactResolver(){
                public Gate current(ServerContext ctx,StageCommand value,OwnedTx tx){return c.equals(value)&&context.actorId().equals(ctx.actorId())
                        &&seed.f.permitted.get()?Gate.CLEAR:Gate.UNKNOWN;}
                public ResolvedStage resolve(ServerContext ctx,StageCommand value,OutsidePreparedResult material,OwnedTx tx){
                    assertEquals(c,value);tx.requireKycPreparation(value,inputHash);
                    return new ResolvedStage(tx.grant(grant),material,SyntheticGrantStageBinding.RunStatus.VALIDATED,
                            SyntheticGrantStageBinding.ResultStatus.VALIDATED,List.of(),inputHash);
                }
                public Gate checkIssuance(ServerContext ctx,StageCommand value,UUID parent,GrantSnapshot child,OwnedTx tx){throw new AssertionError("no implicit child");}
            });
            var out=service.completeStage(context,c,prepared);assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());assertNotNull(out.receipt());return out;
        }
        StageOutcome firstResult(){
            var i=root.identity();var p=prepare(1,i.grantId(),i.actionId(),i.targetRunId());return consume(1,i.grantId(),i.actionId(),i.targetRunId(),p.inputSnapshotHash());
        }
        void issueUsedDependency(){
            var c=new StageCommand(identity(1,7801,loan.grantId(),loan.actionId(),loan.targetRunId()),loan.action());
            var parent=root.identity().grantId();
            var service=new GrantStageTransactionService(journal,new CurrentFactResolver(){
                public Gate current(ServerContext ctx,StageCommand value,OwnedTx tx){return c.equals(value)&&context.actorId().equals(ctx.actorId())
                        &&seed.f.permitted.get()?Gate.CLEAR:Gate.UNKNOWN;}
                public ResolvedStage resolve(ServerContext ctx,StageCommand value,OutsidePreparedResult prepared,OwnedTx tx){throw new AssertionError("issuance is separate");}
                public Gate checkIssuance(ServerContext ctx,StageCommand value,UUID p,GrantSnapshot child,OwnedTx tx){
                    var actual=tx.grant(parent);return c.equals(value)&&parent.equals(p)&&loan.equals(child)&&actual!=null
                            &&actual.state()==GrantState.CONSUMED?Gate.CLEAR:Gate.UNKNOWN;
                }
            });
            var out=service.issueSuccessor(context,c,parent,loan);assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());
            assertNotNull(out.receipt());assertEquals(ReceiptKind.ISSUANCE,out.receipt().kind());
        }
        UUID hold(VirtualQuarantineService.Scope kind,Map<String,Object> target){
            return UUID.fromString((String)quarantine.create(SimulationFixture.ACTOR,seed.f.id(),new VirtualQuarantineService.Target(kind,target),
                    "SYNTHETIC_CONTAINMENT","").get("quarantineId"));
        }
        ContinuationReceipt advance(){
            var a=new SyntheticGrantV2Codec.Action(id(10200),id(1),2,AllowedAction.EVALUATE_KYC,candidate.customerId(),candidate.amountKrw(),
                    candidate.payoutAccountId(),id(10201),null,VirtualGrantWorkflowBridgeTest.EVIDENCE,null,seed.terms.policyVersion());
            var body=new LinkedHashMap<String,Object>();body.put("actionId",a.actionId().toString());body.put("workflowId",id(1).toString());body.put("generation",2);
            body.put("allowedAction",a.allowedAction().name());body.put("customerId",a.customerId());body.put("amountKrw",a.amountKrw());body.put("payoutAccountId",a.payoutAccountId().toString());
            body.put("targetRunId",a.targetRunId().toString());body.put("sourceResultId",null);body.put("evidenceBundleHash",a.evidenceBundleHash());body.put("approvalId",null);body.put("policyVersion",a.policyVersion());
            var c=root.inputs().claims();var claims=new SyntheticGrantV2Codec.Claims(c.format(),c.algorithm(),c.kid(),id(10202),id(1),2,c.rootAuthorizationId(),
                    c.principalId(),c.originIntent(),c.issuer(),c.sourceAgent(),"synthetic-kyc",null,a.targetRunId(),a.allowedAction(),a.customerId(),a.amountKrw(),
                    a.payoutAccountId(),null,a.evidenceBundleHash(),null,1,a.actionId(),CanonicalJson.sha256(body),seed.terms.policyVersion(),id(10203),null,100,400);
            var material=new RootInputs(root.inputs().profile(),claims,a,SyntheticGrantV2Codec.prepare(root.inputs().profile(),claims,a));
            expectedContinuation=new ContinuationCommand(identity(2,7902,claims.grantId(),a.actionId(),a.targetRunId()),
                    new OriginalGenerationOne(new VirtualWorkflowLane.Scope(id(1),1,c.customerId()),root.identity().grantId(),root.identity().globalRequestId(),root.identity().targetRunId(),0),
                    material,candidate,seed.terms,root.workflowPlan().laneReference(),agents,Instant.ofEpochSecond(150));
            var facts=new SyntheticTypedContinuationService.CurrentContinuationFactResolver(){
                public Gate current(SyntheticTypedContinuationService.ContinuationServerContext ctx,ContinuationCommand value,OwnedTypedContinuationPort.OwnedContinuationTx tx){
                    return value.equals(expectedContinuation)&&context.actorId().equals(ctx.actorId())&&context.subjectId().equals(ctx.subjectId())&&seed.f.permitted.get()?Gate.CLEAR:Gate.UNKNOWN;
                }
                public ResolvedContinuation resolve(SyntheticTypedContinuationService.ContinuationServerContext ctx,ContinuationCommand value,
                        SyntheticTypedContinuationBinding.CurrentBindings ticket,OwnedTypedContinuationPort.OwnedContinuationTx tx){
                    var issuer=new IssuerFacts(seed.registry,seed.facts.descriptor);var k=seed.facts.key;
                    return new ResolvedContinuation(value,ticket,issuer,new KeyFacts(k.expected(),k.snapshot(),SyntheticGrantTemporalAssessment.Fact.CLEAR,k.material(),
                            new SyntheticGrantTemporalAssessment.TemporalFacts(150,100,400,SyntheticGrantTemporalAssessment.ChainPosition.ROOT,null),seed.facts.rev(),k.currentUse()));
                }
            };
            var out=new SyntheticTypedContinuationService(journal,facts,catalog).continueWorkflow(context,expectedContinuation);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());assertNotNull(out.receipt());assertEquals(ContinuationKind.ADVANCED,out.receipt().kind());return out.receipt();
        }
        VirtualWorkflowService reader(){return new VirtualWorkflowService(store,catalog,seed.terms,
                new SimulationAccess((actor,op,workflow,customer)->seed.f.permitted.get()),seed.f.clock,seed.f::id);}
        Map<String,Object> trace(){
            var before=store.snapshot();int writes=store.puts;var result=reader().trace(SimulationFixture.ACTOR,id(1));
            assertEquals(before,store.snapshot());assertEquals(writes,store.puts);assertEquals(id(1).toString(),result.get("workflowId"));
            assertEquals(false,result.get("cryptographicAuthorityImplemented"));assertEquals(VirtualTransactionalStore.MODE,result.get("executionMode"));
            for(String array:ARRAYS)assertInstanceOf(List.class,result.get(array));
            assertTrue(rows(result,"runs").isEmpty());
            for(var row:rows(result,"results"))assertEquals(RESULT_KEYS,row.keySet());
            for(var row:rows(result,"grants")){assertEquals(GRANT_KEYS,row.keySet());assertEquals(row.get("state"),row.get("status"));}
            for(var row:rows(result,"dependencies"))assertEquals(DEPENDENCY_KEYS,row.keySet());
            assertMetadataOnly(result);return result;
        }
    }
    @SuppressWarnings("unchecked") private static List<Map<String,Object>> rows(Map<String,Object> trace,String key){return (List<Map<String,Object>>)trace.get(key);}
    private static void assertMetadataOnly(Object value){
        if(value instanceof Map<?,?> map){
            for(var e:map.entrySet()){
                assertFalse(Set.of("body","businessConclusion","outcome","bindingBytes","canonicalBytes","frame","unsignedFrame","claimsBytes","actionBytes",
                        "sourceText","text","canonicalInput","modelInput","reply","identity","attemptToken").contains(e.getKey()));
                assertMetadataOnly(e.getValue());
            }
        }else if(value instanceof List<?> list)for(var item:list)assertMetadataOnly(item);
        else if(value instanceof String text)assertNotEquals(OPAQUE_CANARY,text);
    }
    private static void historyUnderOldHold(VirtualQuarantineService.Scope kind){
        var f=new Fixture();var old=f.firstResult();f.issueUsedDependency();
        var oldResult=old.receipt().result().resultId();var oldTarget=f.root.identity().targetRunId();
        var q=f.hold(kind,kind==VirtualQuarantineService.Scope.RUN?Map.of("runId",oldTarget.toString()):Map.of("resultId",oldResult.toString()));
        var held=f.reader().get(SimulationFixture.ACTOR,id(1));assertTrue(((List<?>)held.get("activeQuarantines")).contains(q.toString()));
        assertEquals(Boolean.TRUE,held.get("canResume"));
        var before=f.trace();assertEquals(1,rows(before,"results").size());assertEquals(1,rows(before,"dependencies").size());
        var advanced=f.advance();var p=f.prepare(2,advanced.identity().grantId(),advanced.identity().actionId(),advanced.identity().targetRunId());
        var next=f.consume(2,advanced.identity().grantId(),advanced.identity().actionId(),advanced.identity().targetRunId(),p.inputSnapshotHash());
        var after=f.trace();assertEquals(2,after.get("generation"));assertEquals(2,rows(after,"results").size());assertEquals(3,rows(after,"grants").size());
        var metadata=rows(after,"results");assertTrue(metadata.stream().anyMatch(r->oldResult.toString().equals(r.get("resultId"))&&Integer.valueOf(1).equals(r.get("generation"))));
        assertTrue(metadata.stream().anyMatch(r->next.receipt().result().resultId().toString().equals(r.get("resultId"))&&Integer.valueOf(2).equals(r.get("generation"))));
        assertEquals(rows(before,"dependencies"),rows(after,"dependencies"));
        assertEquals(List.of(Map.of("parentRunId",oldTarget.toString(),"childRunId",f.loan.targetRunId().toString(),"parentResultId",oldResult.toString(),"generation",1)),rows(after,"dependencies"));
        assertTrue(rows(after,"dependencies").stream().noneMatch(d->advanced.identity().targetRunId().toString().equals(d.get("childRunId"))));
        assertEquals("ACTIVE",f.store.snapshot().get("virtual_quarantines").get(q.toString()).get("status"));
        var current=f.reader().get(SimulationFixture.ACTOR,id(1));assertFalse(((List<?>)current.get("activeQuarantines")).contains(q.toString()));
        var encoded=CanonicalJson.write(after);assertFalse(encoded.contains(f.seed.f.source.text()));assertFalse(encoded.contains(f.candidate.source().text()));
        assertFalse(encoded.contains(OPAQUE_CANARY));assertFalse(encoded.contains(HexFormat.of().formatHex(OPAQUE_CANARY.getBytes(StandardCharsets.US_ASCII))));
    }
    @Test void oldRunHoldKeepsHistoricalMetadataWithoutCreatingNewGenerationBusinessDependency(){historyUnderOldHold(VirtualQuarantineService.Scope.RUN);}
    @Test void oldResultHoldKeepsHistoricalMetadataWithoutDisclosingConclusionOrOpaqueMaterial(){historyUnderOldHold(VirtualQuarantineService.Scope.RESULT);}
    @Test void currentWorkflowSourceAndAgentContainmentRemainMetadataReadable(){
        for(var kind:List.of(VirtualQuarantineService.Scope.WORKFLOW,VirtualQuarantineService.Scope.SOURCE_VERSION,VirtualQuarantineService.Scope.AGENT_VERSION)){
            var f=new Fixture();f.firstResult();
            Map<String,Object> target=switch(kind){
                case WORKFLOW->Map.of("workflowId",id(1).toString());
                case SOURCE_VERSION->Map.of("documentId",f.seed.f.source.documentId().toString(),"documentVersion",f.seed.f.source.documentVersion());
                case AGENT_VERSION->Map.of("agentId","synthetic-kyc","agentVersion",1);
                default->throw new AssertionError("explicit stable scopes only");
            };
            var q=f.hold(kind,target);var before=f.store.snapshot();var trace=f.trace();
            assertEquals(1,rows(trace,"results").size());assertEquals(1,trace.get("generation"));
            var view=f.reader().get(SimulationFixture.ACTOR,id(1));assertTrue(((List<?>)view.get("activeQuarantines")).contains(q.toString()));
            assertEquals(Boolean.FALSE,view.get("canApprove"));
            if(kind!=VirtualQuarantineService.Scope.SOURCE_VERSION)assertEquals(Boolean.FALSE,view.get("canResume"));
            assertEquals(before,f.store.snapshot());assertMetadataOnly(trace);
        }
    }
}
