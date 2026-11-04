package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantV2Codec;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import java.util.function.Function;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane.Scope;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBindingTest.RootFixture;
import static com.finsec.fuse.reimplementation.grant.VirtualGrantFactResolverTest.id;
import static org.junit.jupiter.api.Assertions.*;

/** Owned preparation and retained accounting contracts over synthetic in-memory rows. */
final class VirtualGrantEvaluationAccountingTest {
    private static final String WORKFLOWS="virtual_workflows", MARKERS="virtual_grant_profile_kyc_preparations",
            INPUTS="virtual_grant_profile_kyc_inputs", CHARGES="virtual_grant_profile_stage_charges";
    static final class Fixture {
        final RootFixture root=new RootFixture(); final PrefixFaultStore store=new PrefixFaultStore();
        final SimulationSpec.RiskTerms terms; Scope scope;
        final VirtualGrantTransactionJournal journal;
        final SyntheticKycPreparationService preparation;
        final Set<PreparationCommand> expectedPreparations=new LinkedHashSet<>();
        SyntheticTypedContinuationBinding.ContinuationCommand expectedContinuation;
        final PreparationCommand command; final PreparedInput input;
        Fixture(int kycCost,int maxRuns) { this(kycCost,maxRuns,null); }
        Fixture(int kycCost,int maxRuns,Integer baseLimit) {
            var old=root.terms;
            terms=new SimulationSpec.RiskTerms(old.policyVersion(),kycCost,old.loanPoints(),old.payPoints(),baseLimit==null?old.baseLimit():baseLimit,
                    old.additionalApprovalLimit(),maxRuns,old.approvalLifetime());
            var plan=new SyntheticRootProvisionBinding.TypedWorkflowPlan(root.plan.workflowId(),1,root.application,terms,
                    root.plan.laneReference(),root.plan.targetRunId(),root.plan.stageAgents());
            var command=new SyntheticRootProvisionBinding.RootCommand(root.identity,root.inputs,plan);
            AtomicInteger tokens=new AtomicInteger(900);
            journal=new VirtualGrantTransactionJournal(store,()->id(tokens.incrementAndGet()),65536);
            var facts=new SyntheticRootProvisionService.CurrentRootFactResolver() {
                public Gate current(SyntheticRootProvisionService.RootServerContext c,SyntheticRootProvisionBinding.RootCommand r,
                                    OwnedRootProvisionPort.OwnedRootTx tx) {
                    return command.equals(r) && root.identity.actorId().equals(c.actorId())
                            && root.issuer.binding().subjectId().equals(c.subjectId()) ? Gate.CLEAR:Gate.UNKNOWN;
                }
                public SyntheticRootProvisionBinding.ResolvedRootProvision resolve(SyntheticRootProvisionService.RootServerContext c,
                        SyntheticRootProvisionBinding.RootCommand r,SyntheticRootProvisionBinding.CurrentBindings b,OwnedRootProvisionPort.OwnedRootTx tx) {
                    return new SyntheticRootProvisionBinding.ResolvedRootProvision(r,b,root.issuer,root.keyFacts);
                }
            };
            var actor=new SyntheticRootProvisionService.RootServerContext() {
                public String actorId(){return root.identity.actorId();}
                public String subjectId(){return root.issuer.binding().subjectId();}
            };
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,new SyntheticRootProvisionService(journal,facts).provisionRoot(actor,command).status());
            scope=new Scope(root.plan.workflowId(),1,root.application.customerId());
            this.command=new PreparationCommand(identity(id(501),root.identity.grantId(),root.identity.actionId(),root.identity.targetRunId(),
                    "synthetic-preparation-actor"),root.source,List.of(),terms,Instant.ofEpochSecond(150));
            input=prepareRequested(this.command);
            expectedPreparations.add(this.command);
            preparation=new SyntheticKycPreparationService(journal,(context,c,tx)->
                    context!=null && c.identity().actorId().equals(context.actorId()) && expectedPreparations.contains(c)
                    && root.source.equals(c.source()) && c.facts().isEmpty() && terms.equals(c.terms())
                    && scope.workflowId().equals(c.identity().workflowId()) && scope.generation()==c.identity().generation()
                    && scope.customerId().equals(c.identity().customerId()) ? Gate.CLEAR:Gate.UNKNOWN);
        }
        CommandIdentity identity(UUID request,UUID grant,UUID action,UUID target,String actor) {
            return new CommandIdentity(actor,request,"synthetic-prepare","synthetic-command-version","a".repeat(64),grant,action,target,
                    root.identity.workflowId(),1,root.identity.customerId());
        }
        PreparationOutcome attempt(PreparationCommand c) {
            expectedPreparations.add(c);
            return preparation.prepare(()->c.identity().actorId(),c);
        }
        PreparationMarker prepare() { return prepare(command); }
        PreparationMarker prepare(PreparationCommand c) {
            var outcome=attempt(c);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,outcome.status());
            assertNotNull(outcome.receipt()); assertEquals(Decision.PREPARED,outcome.receipt().decision());
            assertEquals(PreparationEffect.COMMITTED_IN_PROCESS,outcome.effect());
            return store.transaction(tx->VirtualGrantEvaluationAccounting.requirePrepared(tx,
                    new StageCommand(c.identity(),AllowedAction.EVALUATE_KYC),prepareRequested(c).inputSnapshotHash()));
        }
        VirtualGrantEvaluationAccounting.Counters counters() {return store.transaction(tx->VirtualGrantEvaluationAccounting.readVerified(tx,scope));}
        void workflow(String field,Object value) {
            store.transaction(tx->{var row=new LinkedHashMap<>(tx.get(WORKFLOWS,scope.workflowId().toString()));row.put(field,value);
                tx.put(WORKFLOWS,scope.workflowId().toString(),row);return null;});
        }
        SyntheticTypedContinuationBinding.ContinuationCommand nextCommand() {
            var c=root.inputs.claims();
            var action=new SyntheticGrantV2Codec.Action(id(902),scope.workflowId(),2,AllowedAction.EVALUATE_KYC,
                    c.customerId(),c.amountKrw(),c.payoutAccountId(),id(903),null,c.evidenceBundleHash(),null,terms.policyVersion());
            var claims=new SyntheticGrantV2Codec.Claims(c.format(),c.algorithm(),c.kid(),id(901),c.workflowId(),2,
                    c.rootAuthorizationId(),c.principalId(),c.originIntent(),c.issuer(),c.sourceAgent(),c.targetAgent(),null,
                    action.targetRunId(),action.allowedAction(),c.customerId(),c.amountKrw(),c.payoutAccountId(),null,
                    c.evidenceBundleHash(),null,1,action.actionId(),VirtualGrantFactResolverTest.payload(action),terms.policyVersion(),
                    id(904),null,c.issuedAt(),c.expiresAt());
            var newRoot=new SyntheticRootProvisionBinding.RootInputs(root.inputs.profile(),claims,action,
                    SyntheticGrantV2Codec.prepare(root.inputs.profile(),claims,action));
            var identity=new CommandIdentity(root.identity.actorId(),id(504),"synthetic-continuation","synthetic-command-version",
                    "a".repeat(64),claims.grantId(),action.actionId(),action.targetRunId(),scope.workflowId(),2,scope.customerId());
            expectedContinuation=new SyntheticTypedContinuationBinding.ContinuationCommand(identity,
                    new SyntheticTypedContinuationBinding.OriginalGenerationOne(scope,root.identity.grantId(),root.identity.globalRequestId(),
                            root.identity.targetRunId(),0),newRoot,root.application,terms,root.plan.laneReference(),root.plan.stageAgents(),Instant.ofEpochSecond(150));
            return expectedContinuation;
        }
        SyntheticTypedContinuationBinding.ContinuationOutcome advance(SyntheticTypedContinuationBinding.ContinuationCommand c) {
            var facts=new SyntheticTypedContinuationService.CurrentContinuationFactResolver() {
                public Gate current(SyntheticTypedContinuationService.ContinuationServerContext actor,
                        SyntheticTypedContinuationBinding.ContinuationCommand value,OwnedTypedContinuationPort.OwnedContinuationTx tx) {
                    return value.equals(expectedContinuation) && root.identity.actorId().equals(actor.actorId())
                            && root.issuer.binding().subjectId().equals(actor.subjectId()) ? Gate.CLEAR:Gate.UNKNOWN;
                }
                public SyntheticTypedContinuationBinding.ResolvedContinuation resolve(SyntheticTypedContinuationService.ContinuationServerContext actor,
                        SyntheticTypedContinuationBinding.ContinuationCommand value,SyntheticTypedContinuationBinding.CurrentBindings current,
                        OwnedTypedContinuationPort.OwnedContinuationTx tx) {
                    return new SyntheticTypedContinuationBinding.ResolvedContinuation(value,current,root.issuer,root.keyFacts);
                }
            };
            var actor=new SyntheticTypedContinuationService.ContinuationServerContext() {
                public String actorId(){return root.identity.actorId();}
                public String subjectId(){return root.issuer.binding().subjectId();}
            };
            return new SyntheticTypedContinuationService(journal,facts,
                    new SimulationSpec.Catalog(List.of(root.application),List.of())).continueWorkflow(actor,c);
        }
        PreparationCommand secondTarget() {
            // Explicit synthetic old-state setup; new root and preparation use the actual services.
            workflow("state","ON_HOLD");
            var next=nextCommand();var advanced=advance(next);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,advanced.status());
            assertNotNull(advanced.receipt());assertEquals(SyntheticTypedContinuationBinding.ContinuationKind.ADVANCED,advanced.receipt().kind());
            scope=next.requestedScope();var i=next.identity();
            return new PreparationCommand(new CommandIdentity("synthetic-other-preparer",id(502),"synthetic-prepare",
                    "synthetic-command-version","a".repeat(64),i.grantId(),i.actionId(),i.targetRunId(),i.workflowId(),2,i.customerId()),
                    root.source,List.of(),terms,Instant.ofEpochSecond(151));
        }
    }
    static final class PrefixFaultStore implements TransactionalStore {
        final VirtualTransactionalStore delegate=new VirtualTransactionalStore();
        final Set<String> prefixWrites=new LinkedHashSet<>();
        boolean failReceipt,receiptAttempted,completeAccountingPrefix;
        public String mode(){return delegate.mode();}
        public Map<String,Map<String,Map<String,Object>>> snapshot(){return delegate.snapshot();}
        public <R> R transaction(Function<Tx,R> work) {
            return delegate.transaction(tx->work.apply(new Tx() {
                public Map<String,Object> get(String table,String key){return tx.get(table,key);}
                public Map<String,Map<String,Object>> rows(String table){return tx.rows(table);}
                public void put(String table,String key,Map<String,Object> row){
                    tx.put(table,key,row);
                    if(failReceipt) {
                        if(Set.of(INPUTS,MARKERS,CHARGES,WORKFLOWS).contains(table))prefixWrites.add(table);
                        if(table.equals("virtual_grant_profile_preparation_receipts")) {
                            receiptAttempted=true;completeAccountingPrefix=prefixWrites.containsAll(Set.of(INPUTS,MARKERS,CHARGES,WORKFLOWS));
                            throw new IllegalStateException("synthetic-late-preparation-receipt-failure");
                        }
                    }
                }
            }));
        }
    }
    private static void malformed(org.junit.jupiter.api.function.Executable work) {
        var failure=assertThrows(OwnedGrantTransactionPort.Stop.class,work);
        assertEquals(Status.TRANSACTION_INVARIANT_UNCONFIRMED,failure.status);
    }

    @Test void actualRootZeroCountersRequireRealRootTermsAndTypedScopeNotCachedZero() {
        var f=new Fixture(3,2);
        assertEquals(new VirtualGrantEvaluationAccounting.Counters(0,0,0,false,false),f.counters());
        f.workflow("usedRisk",1); malformed(f::counters);
    }

    @Test void firstChargeAndExplicitZeroChargeBothHaveConcreteMarkerAndLedger() {
        for(int cost:List.of(0,3)) {
            var f=new Fixture(cost,2); var marker=f.prepare();
            assertEquals(cost,marker.chargedPoints()); assertEquals(cost,marker.usedRiskAfter()); assertEquals(1,marker.kycRunsAfter());
            assertEquals(new VirtualGrantEvaluationAccounting.Counters(cost,0,1,true,false),f.counters());
            var row=f.store.snapshot().get(CHARGES).get(f.scope.workflowId()+":KYC");
            assertNotNull(row);assertEquals(cost,row.get("points"));assertNull(row.get("resultId"));
            assertEquals(f.command.identity().globalRequestId().toString(),row.get("phaseRequestId"));
        }
    }

    @Test void secondDistinctTargetInSameWorkflowAddsRunButNeverAnotherFirstCharge() {
        var f=new Fixture(3,2); f.prepare(); var second=f.secondTarget();
        assertEquals(2,second.identity().generation());
        assertNotEquals(f.command.identity().targetRunId(),second.identity().targetRunId());
        var marker=f.prepare(second);
        assertEquals(0,marker.chargedPoints());assertEquals(3,marker.usedRiskAfter());assertEquals(2,marker.kycRunsAfter());
        assertEquals(new VirtualGrantEvaluationAccounting.Counters(3,0,2,true,false),f.counters());
        assertEquals(1,f.store.snapshot().get(CHARGES).size());assertEquals(2,f.store.snapshot().get(MARKERS).size());
        assertEquals(f.command.identity().globalRequestId().toString(),f.store.snapshot().get(CHARGES).get(f.scope.workflowId()+":KYC").get("phaseRequestId"));
        assertEquals(1,f.store.snapshot().get(CHARGES).get(f.scope.workflowId()+":KYC").get("generation"));
    }

    @Test void consumptionActorRequestAndOperationAreSeparateFromPreparationIdentity() {
        var f=new Fixture(3,2);var marker=f.prepare();var i=f.command.identity();
        var observer=new CommandIdentity("synthetic-observation-actor",id(600),"synthetic-consume","synthetic-other-version","b".repeat(64),
                i.grantId(),i.actionId(),i.targetRunId(),i.workflowId(),i.generation(),i.customerId());
        var stage=new StageCommand(observer,AllowedAction.EVALUATE_KYC);var before=f.store.snapshot();
        assertEquals(marker,f.store.transaction(tx->VirtualGrantEvaluationAccounting.requirePrepared(tx,stage,f.input.inputSnapshotHash())));
        assertEquals(before,f.store.snapshot());
        malformed(()->f.store.transaction(tx->VirtualGrantEvaluationAccounting.requirePrepared(tx,stage,"f".repeat(64))));
        assertEquals(before,f.store.snapshot());
    }

    @Test void duplicateExactTargetCannotOverwriteMarkerWithDifferentPhaseRequest() {
        var f=new Fixture(3,2);f.prepare();var i=f.command.identity();
        var another=new PreparationCommand(f.identity(id(999),i.grantId(),i.actionId(),i.targetRunId(),"synthetic-other"),
                f.root.source,List.of(),f.terms,Instant.ofEpochSecond(152));var before=f.store.snapshot();
        var rejected=f.attempt(another);
        assertEquals(Status.IDENTITY_CONFLICT,rejected.status());assertNull(rejected.receipt());
        assertEquals(before,f.store.snapshot());
    }

    @Test void invalidMarkerHashClosedShapeAndNativeOrdinalCannotBeReadAsValid() {
        for(String field:List.of("inputSnapshotHash","extra","kycRunsAfter")) {
            var f=new Fixture(3,2);f.prepare();
            f.store.transaction(tx->{var row=new LinkedHashMap<>(tx.get(MARKERS,f.command.identity().targetRunId().toString()));
                row.put(field,field.equals("inputSnapshotHash")?"f".repeat(64):field.equals("extra")?true:1L);
                tx.put(MARKERS,f.command.identity().targetRunId().toString(),row);return null;});
            var before=f.store.snapshot();malformed(f::counters);assertEquals(before,f.store.snapshot());
        }
    }

    @Test void malformedNativeWorkflowCounterAliasesRefuseWithoutRepairOrLateCharge() {
        for(Object value:List.of(true,1L,-1)) {
            var f=new Fixture(3,2);f.workflow("usedRisk",value);var before=f.store.snapshot();
            malformed(f::counters);assertEquals(before,f.store.snapshot());
        }
    }

    @Test void preparedInputKeyOrderAndDetachedNestedMapsArePreservedOnStorage() {
        var f=new Fixture(3,2);var before=CanonicalJson.write(f.input.canonicalInput());var marker=f.prepare();
        assertEquals(List.of("requestId","workflowId","generation","runId","customerId","policyVersion","evidenceFacts","documents"),
                new ArrayList<>(f.input.canonicalInput().keySet()));
        assertEquals(before,CanonicalJson.write(f.input.canonicalInput()));
        assertThrows(UnsupportedOperationException.class,()->f.input.canonicalInput().clear());
        var stored=f.store.snapshot().get(INPUTS).get(f.command.identity().targetRunId().toString());
        assertThrows(UnsupportedOperationException.class,()->stored.clear());
        assertEquals(f.input.inputSnapshotHash(),stored.get("inputSnapshotHash"));
        assertFalse(marker.toString().contains(f.root.source.text()));
    }

    @Test void callbackFailureAfterActualHelperWritesRollsBackWholePreparationPrefix() {
        var f=new Fixture(3,2);var before=f.store.snapshot();
        f.store.failReceipt=true;
        var failed=f.attempt(f.command);
        assertTrue(f.store.receiptAttempted);assertTrue(f.store.completeAccountingPrefix);
        assertEquals(Set.of(INPUTS,MARKERS,CHARGES,WORKFLOWS),f.store.prefixWrites);
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,failed.status());assertNull(failed.receipt());
        assertEquals(PreparationEffect.NO_NEW_PREPARATION_ATTEMPT_THIS_INVOCATION,failed.effect());
        f.store.failReceipt=false;
        assertEquals(before,f.store.snapshot());assertEquals(new VirtualGrantEvaluationAccounting.Counters(0,0,0,false,false),f.counters());
    }

    @Test void validLedgerButInsufficientBudgetAndMaxRunsRefuseAtMutationWithoutNewCharge() {
        var f=new Fixture(3,2,0);
        assertEquals(new VirtualGrantEvaluationAccounting.Counters(0,0,0,false,false),f.counters());var before=f.store.snapshot();
        var refused=f.attempt(f.command);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,refused.status());assertNotNull(refused.receipt());
        assertEquals(Decision.ON_HOLD,refused.receipt().decision());assertEquals(Refusal.RISK_LIMIT_EXCEEDED,refused.receipt().refusal());
        assertEquals(new VirtualGrantEvaluationAccounting.Counters(0,0,0,false,false),f.counters());
        for(String table:List.of(INPUTS,MARKERS,CHARGES))assertEquals(before.get(table),f.store.snapshot().get(table));
        assertEquals("ON_HOLD",f.store.snapshot().get(WORKFLOWS).get(f.scope.workflowId().toString()).get("state"));
        var g=new Fixture(3,1);g.prepare();g.workflow("state","ON_HOLD");var prior=g.store.snapshot();
        var denied=g.advance(g.nextCommand());
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,denied.status());assertNotNull(denied.receipt());
        assertEquals(SyntheticTypedContinuationBinding.ContinuationKind.DENIED,denied.receipt().kind());
        assertEquals(1,denied.receipt().committedGeneration());
        assertEquals(new VirtualGrantEvaluationAccounting.Counters(3,0,1,true,false),g.counters());
        for(String table:List.of(INPUTS,MARKERS,CHARGES,"virtual_grant_profile_grants","virtual_workflow_lanes"))
            assertEquals(prior.get(table),g.store.snapshot().get(table));
    }

    @Test void missingScopeAndConsumedGrantWithoutPreparedMarkerCannotUseZeroFallback() {
        var f=new Fixture(3,2);
        assertThrows(RuntimeException.class,()->f.store.transaction(tx->VirtualGrantEvaluationAccounting.readVerified(tx,
                new Scope(id(999),1,f.scope.customerId()))));
        f.store.transaction(tx->{var key=f.command.identity().grantId().toString();
            var row=new LinkedHashMap<>(tx.get("virtual_grant_profile_grants",key));row.put("state","CONSUMED");
            tx.put("virtual_grant_profile_grants",key,row);return null;});
        var before=f.store.snapshot();malformed(f::counters);assertEquals(before,f.store.snapshot());
    }
}
