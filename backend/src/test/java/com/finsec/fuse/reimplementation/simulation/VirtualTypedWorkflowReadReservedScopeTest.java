package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment;
import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanService.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;
import static com.finsec.fuse.reimplementation.simulation.VirtualGrantContinuationFixture.id;
import static org.junit.jupiter.api.Assertions.*;

/** Real generation-two reservation, with a single-field read mask over synthetic in-memory rows. */
final class VirtualTypedWorkflowReadReservedScopeTest {
    private static final String RISK="virtual_grant_profile_payment_risk_reservations",
            PLANS="virtual_grant_profile_payment_plans",GRANTS="virtual_grant_profile_grants";
    static final class MaskStore implements TransactionalStore {
        final VirtualTransactionalStore delegate=new VirtualTransactionalStore();
        UUID reservation,paymentGrant;boolean armed,masked,oldOriginRead,planRead,lastPaymentGrantRead;int puts;
        public String mode(){return delegate.mode();}
        public Map<String,Map<String,Map<String,Object>>> snapshot(){return delegate.snapshot();}
        void arm(){masked=false;oldOriginRead=false;planRead=false;lastPaymentGrantRead=false;armed=true;}
        public <R> R transaction(Function<Tx,R> work){
            return delegate.transaction(tx->work.apply(new Tx(){
                public Map<String,Object> get(String table,String key){
                    var row=tx.get(table,key);
                    if(armed&&masked){
                        if(table.equals("virtual_grant_profile_generations")&&key.equals(id(1)+":1")){
                            assertNotNull(row);assertEquals(1,row.get("generation"));oldOriginRead=true;
                        }
                        if(table.equals(PLANS)&&key.equals(reservation.toString())){
                            assertNotNull(row);assertEquals(2,row.get("generation"));planRead=true;
                        }
                        if(planRead&&table.equals(GRANTS)&&key.equals(paymentGrant.toString())){
                            assertNotNull(row);assertEquals(2,row.get("generation"));lastPaymentGrantRead=true;
                        }
                    }
                    return row;
                }
                public Map<String,Map<String,Object>> rows(String table){
                    var rows=tx.rows(table);
                    if(!armed||!table.equals(RISK))return rows;
                    var actual=rows.get(reservation.toString());assertNotNull(actual);assertEquals(2,actual.get("generation"));
                    var changed=new LinkedHashMap<>(actual);changed.put("generation",1);
                    var untouched=new LinkedHashMap<>(changed);untouched.put("generation",2);assertEquals(actual,untouched);
                    var result=new LinkedHashMap<>(rows);result.put(reservation.toString(),Collections.unmodifiableMap(changed));
                    masked=true;return Collections.unmodifiableMap(result);
                }
                public void put(String table,String key,Map<String,Object> value){puts++;tx.put(table,key,value);}
            }));
        }
    }
    static final class Scenario {
        final MaskStore store=new MaskStore();
        final VirtualGrantContinuationFixture f=new VirtualGrantContinuationFixture(store);
        final Instant now=Instant.ofEpochSecond(150);
        final Set<StageCommand> expectedStages=new LinkedHashSet<>();
        final Map<StageCommand,OutsidePreparedResult> expectedResults=new LinkedHashMap<>();
        final Map<StageCommand,GrantSnapshot> expectedChildren=new LinkedHashMap<>();
        final Map<StageCommand,UUID> expectedParents=new LinkedHashMap<>();
        final GrantStageTransactionService stages;
        final GrantSnapshot loan,payment;
        final StageCommand loanConsumption;
        final EvidenceSnapshot evidence;
        final ApprovalSnapshot approval;
        final PaymentDomain reserved;
        final SyntheticMockPaymentPlanService plans;
        final Map<CommandIdentity,PlanOperation> expectedPlans=new LinkedHashMap<>();
        final PlanServerContext reviewer=()->f.context.actorId();
        Scenario(){
            // A supported old RUN hold establishes BLOCKED; independent continuation does not reuse it.
            f.hold(new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.RUN,
                    Map.of("runId",f.oldRootCommand.identity().targetRunId().toString())));
            var base=f.firstCommand();var agents=new LinkedHashMap<>(base.stageAgents());
            agents.put(AllowedAction.CREATE_LOAN_RECOMMENDATION,new SyntheticRootProvisionBinding.AgentReference("synthetic-loan",1));
            agents.put(AllowedAction.EXECUTE_MOCK_PAYMENT,new SyntheticRootProvisionBinding.AgentReference("synthetic-payment",1));
            var next=new SyntheticTypedContinuationBinding.ContinuationCommand(base.identity(),base.prior(),base.newRoot(),
                    base.application(),base.originalTerms(),base.laneReference(),agents,base.observedAt());
            var advanced=f.advance(next);assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,advanced.status());
            assertNotNull(advanced.receipt());assertEquals(2,advanced.receipt().committedGeneration());
            var prepared=f.prepareCurrent();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,prepared.status());assertNotNull(prepared.receipt());
            var inputHash=prepared.receipt().inputSnapshotHash();
            stages=new GrantStageTransactionService(f.journal,new CurrentFactResolver(){
                public Gate current(ServerContext actor,StageCommand command,OwnedTx tx){
                    if(!f.context.actorId().equals(actor.actorId())||!expectedStages.contains(command)
                            ||command.identity().generation()!=2||!command.identity().workflowId().equals(id(1))
                            ||!command.identity().customerId().equals(f.newApplication.customerId()))return Gate.UNKNOWN;
                    var c=next.newRoot().claims();var time=new SyntheticGrantTemporalAssessment.TemporalFacts(now.getEpochSecond(),
                            c.issuedAt(),c.expiresAt(),SyntheticGrantTemporalAssessment.ChainPosition.ROOT,null);
                    return SyntheticGrantTemporalAssessment.assess(time,f.seed.facts.rev()).blockers().isEmpty()?Gate.CLEAR:Gate.UNKNOWN;
                }
                public ResolvedStage resolve(ServerContext actor,StageCommand command,OutsidePreparedResult result,OwnedTx tx){
                    assertSame(expectedResults.get(command),result);var grant=tx.grant(command.identity().grantId());assertNotNull(grant);
                    if(command.action()==AllowedAction.EVALUATE_KYC)tx.requireKycPreparation(command,inputHash);
                    return new ResolvedStage(grant,result,SyntheticGrantStageBinding.RunStatus.VALIDATED,
                            SyntheticGrantStageBinding.ResultStatus.VALIDATED,List.of(),command.action()==AllowedAction.EVALUATE_KYC?inputHash:null);
                }
                public Gate checkIssuance(ServerContext actor,StageCommand command,UUID parent,GrantSnapshot child,OwnedTx tx){
                    if(!child.equals(expectedChildren.get(command))||!parent.equals(expectedParents.get(command)))return Gate.UNKNOWN;
                    if(current(actor,command,tx)!=Gate.CLEAR)return Gate.UNKNOWN;
                    if(child.action()==AllowedAction.EXECUTE_MOCK_PAYMENT)tx.bindCurrentIssuanceTime(command,now);
                    return Gate.CLEAR;
                }
            });
            var kyc=f.stage(2,8301);expectedStages.add(kyc);var kycResult=result(8601);expectedResults.put(kyc,kycResult);
            var kycDone=stages.completeStage(f.context,kyc,kycResult);assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,kycDone.status());
            loan=new GrantSnapshot(id(8401),id(8402),id(8403),id(1),2,f.newApplication.customerId(),AllowedAction.CREATE_LOAN_RECOMMENDATION,GrantState.ISSUED);
            var issueLoan=new StageCommand(identity(8302,loan,"synthetic-loan-issue"),loan.action());
            expectIssue(issueLoan,kyc.identity().grantId(),loan);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,stages.issueSuccessor(f.context,issueLoan,kyc.identity().grantId(),loan).status());
            loanConsumption=new StageCommand(identity(8303,loan,"synthetic-loan-complete"),loan.action());
            expectedStages.add(loanConsumption);var loanResult=result(8602);expectedResults.put(loanConsumption,loanResult);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,stages.completeStage(f.context,loanConsumption,loanResult).status());
            assertEquals("WAIT_APPROVAL",f.workflow().get("state"));
            var fact=new SimulationSpec.Fact(id(8702),f.newApplication.customerId(),SimulationSpec.Kind.ID_DOC,SimulationSpec.Outcome.PASS,true,
                    Instant.ofEpochSecond(100),Instant.ofEpochSecond(400));
            evidence=new EvidenceSnapshot(id(8701),kycResult.resultId(),loanResult.resultId(),VirtualGrantWorkflowBridgeTest.EVIDENCE,
                    VirtualGrantWorkflowBridgeTest.HASH,f.newApplication.source(),List.of(fact.evidenceId()),List.of(fact));
            plans=new SyntheticMockPaymentPlanService(f.journal,new LocalPlanFacts(){
                public Gate current(PlanServerContext actor,CommandIdentity identity,PlanOperation operation,OwnedMockPaymentPlanPort.OwnedPlanTx tx){
                    return f.context.actorId().equals(actor.actorId())&&expectedPlans.get(identity)==operation
                            &&identity.generation()==2&&identity.workflowId().equals(id(1))?Gate.CLEAR:Gate.UNKNOWN;
                }
                public ResolvedEvidence resolveEvidence(PlanServerContext actor,CommandIdentity identity,ReviewBindings bindings,OwnedMockPaymentPlanPort.OwnedPlanTx tx){
                    assertEquals(2,bindings.workflow().scope().generation());assertEquals(id(1),bindings.workflow().scope().workflowId());
                    assertEquals(evidence.kycResultId(),bindings.evaluation().kycReceipt().result().resultId());
                    assertEquals(evidence.loanResultId(),bindings.evaluation().loanReceipt().result().resultId());
                    return new ResolvedEvidence(bindings,evidence);
                }
            });
            var reviewIdentity=identity(8304,loan,"synthetic-plan-review");expectedPlans.put(reviewIdentity,PlanOperation.REVIEW);
            var draft=new ReviewCommand(reviewIdentity,id(8801),ReviewDecision.APPROVE,VirtualGrantWorkflowBridgeTest.HASH,
                    now,now.plus(f.terms.approvalLifetime()),"synthetic review");
            var captured=new AtomicReference<ReviewBindings>();var before=store.snapshot();
            // Obtain the hash input from actual owned reads, then roll back the provisional request.
            var preview=f.journal.review(draft,tx->{assertNull(tx.lookupReview(draft));tx.admitReview(draft);
                captured.set(tx.readReviewBindings(draft));throw OwnedGrantTransactionPort.stop(Status.UNCONFIRMED_BEFORE_ADMISSION);});
            assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,preview.status());assertNotNull(captured.get());assertEquals(before,store.snapshot());
            var review=new ReviewCommand(reviewIdentity,id(8801),ReviewDecision.APPROVE,reviewHash(material(captured.get(),evidence,now)),
                    now,now.plus(f.terms.approvalLifetime()),"synthetic review");
            var reviewed=plans.review(reviewer,review);assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,reviewed.status());assertNotNull(reviewed.receipt());
            approval=reviewed.receipt().approval();assertEquals(ApprovalPlanState.AVAILABLE,approval.state());
            payment=new GrantSnapshot(id(8501),id(8502),id(8503),id(1),2,f.newApplication.customerId(),AllowedAction.EXECUTE_MOCK_PAYMENT,GrantState.ISSUED);
            reserved=new PaymentDomain(payment.grantId(),payment.actionId(),id(8802),payment.targetRunId(),approval.approvalId(),id(8803),
                    id(1),2,payment.customerId(),evidence.applicationId(),f.newApplication.amountKrw(),f.newApplication.payoutAccountId(),
                    f.terms.policyVersion(),ReservationState.RESERVED,ApprovalState.RESERVED);
            var issuePayment=new StageCommand(identity(8305,payment,"synthetic-payment-issue"),payment.action());
            expectIssue(issuePayment,loan.grantId(),payment);
            var issued=stages.issueSuccessor(f.context,issuePayment,loan.grantId(),payment,new PaymentIssuanceProof(approval,reserved,now));
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,issued.status());assertNotNull(issued.receipt());
            var reserveIdentity=identity(8306,payment,"synthetic-payment-reserve");expectedPlans.put(reserveIdentity,PlanOperation.RESERVE);
            var outcome=plans.reserve(reviewer,new ReserveCommand(reserveIdentity,reserved,approval.reviewSnapshotHash(),now));
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,outcome.status());assertNotNull(outcome.receipt());
            assertEquals(PlanOperation.RESERVE,outcome.receipt().purpose());assertEquals(reserved,outcome.receipt().domain());
            assertEquals(2,outcome.receipt().approval().material().scope().generation());
            store.reservation=reserved.reservationId();store.paymentGrant=payment.grantId();
        }
        private void expectIssue(StageCommand command,UUID parent,GrantSnapshot child){
            expectedStages.add(command);expectedParents.put(command,parent);expectedChildren.put(command,child);
        }
        private CommandIdentity identity(long request,GrantSnapshot grant,String operation){
            var root=f.oldRootCommand.identity();return new CommandIdentity(f.context.actorId(),id(request),operation,
                    root.canonicalizationVersion(),root.canonicalBodyDigest(),grant.grantId(),grant.actionId(),grant.targetRunId(),
                    grant.workflowId(),grant.generation(),grant.customerId());
        }
        VirtualWorkflowService reader(){return new VirtualWorkflowService(store,f.continuationCatalog,f.terms,
                new SimulationAccess((actor,operation,workflow,customer)->f.seed.f.permitted.get()),f.seed.f.clock,f.seed.f::id);}
        @SuppressWarnings("unchecked") Map<String,Object> positiveRead(){
            var before=store.snapshot();int writes=store.puts;var service=reader();
            var detail=service.get(SimulationFixture.ACTOR,id(1));var page=service.list(SimulationFixture.ACTOR,0,10);
            assertEquals(1,page.get("total"));var items=(List<?>)page.get("items");assertEquals(1,items.size());
            assertEquals(detail,(Map<String,Object>)items.get(0));assertEquals(2,detail.get("generation"));
            assertEquals("PAYMENT_RESERVED",detail.get("state"));assertEquals(f.terms.payPoints(),detail.get("reservedRisk"));
            assertEquals(f.terms.kycPoints()+f.terms.loanPoints(),detail.get("usedRisk"));
            assertEquals(f.terms.baseLimit(),detail.get("riskLimit"));assertEquals(Boolean.FALSE,detail.get("canApprove"));
            assertEquals(before,store.snapshot());assertEquals(writes,store.puts);return detail;
        }
    }
    private static OutsidePreparedResult result(long n){return new OutsidePreparedResult(id(n),SyntheticGrantStageBinding.BusinessConclusion.POSITIVE,
            "AGENT_RESULT_BINDING_RECORD_1",new byte[]{1,2},new byte[]{3,4});}
    @Test void reservedGenerationTwoRiskCannotBorrowValidGenerationOneOriginToMatchItsPlan(){
        var s=new Scenario();var positive=s.positiveRead();
        var old=s.store.transaction(tx->VirtualGrantGenerationHistory.validate(tx,
                new VirtualWorkflowLane.Scope(id(1),1,s.f.newApplication.customerId())));
        assertEquals(s.f.terms,old.terms());assertEquals(1,old.scope().generation());
        var actual=s.store.snapshot().get(RISK).get(s.reserved.reservationId().toString());
        assertEquals(2,actual.get("generation"));assertEquals(s.f.terms.payPoints(),actual.get("points"));assertEquals("RESERVED",actual.get("state"));
        for(boolean list:List.of(false,true)){
            var before=s.store.snapshot();int puts=s.store.puts;s.store.arm();
            var failure=assertThrows(SimulationFailure.class,()->{
                if(list)s.reader().list(SimulationFixture.ACTOR,0,10);else s.reader().get(SimulationFixture.ACTOR,id(1));
            });
            assertEquals(503,failure.status());assertEquals("DEPENDENCY_UNAVAILABLE",failure.code());
            assertTrue(s.store.masked);assertTrue(s.store.oldOriginRead);assertTrue(s.store.planRead);assertTrue(s.store.lastPaymentGrantRead);
            assertEquals(puts,s.store.puts);assertEquals(before,s.store.snapshot());
            assertEquals(2,s.store.snapshot().get(RISK).get(s.reserved.reservationId().toString()).get("generation"));
            s.store.armed=false;assertEquals(positive,s.positiveRead());
        }
    }
}
