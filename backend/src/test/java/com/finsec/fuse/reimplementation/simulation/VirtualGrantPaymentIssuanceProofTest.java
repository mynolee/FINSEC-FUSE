package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.grant.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.RecordComponent;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanService.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real APP Journal proof joins over synthetic facts; no issuer, wall-clock or authority proof. */
final class VirtualGrantPaymentIssuanceProofTest {
    static UUID id(long n){return VirtualGrantWorkflowBridgeTest.id(n);}
    enum Bind { NORMAL, NONE, REPEAT, CONFLICT, CROSS_COMMAND }
    static final class Fixture {
        final VirtualGrantEvaluationRefusalBoundaryTest.Fixture app=new VirtualGrantEvaluationRefusalBoundaryTest.Fixture(3,true);
        final GrantSnapshot child;
        final StageCommand command;
        final PlanServerContext reviewer=()->app.loan.identity().actorId();
        final ApprovalSnapshot approval;
        final PaymentDomain intended;
        final GrantStageTransactionService stages;
        Instant point=Instant.ofEpochSecond(150);Bind bind=Bind.NORMAL;int issuanceChecks,currentChecks;
        Fixture(){
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,app.evaluateLoan().status());
            var i=app.loan.identity();
            child=new GrantSnapshot(id(2401),id(2101),id(2201),i.workflowId(),i.generation(),i.customerId(),AllowedAction.EXECUTE_MOCK_PAYMENT,GrantState.ISSUED);
            command=new StageCommand(identity(2801,child,"synthetic-payment-child"),AllowedAction.EXECUTE_MOCK_PAYMENT);
            var evidence=new EvidenceSnapshot(id(2900),id(1600),id(1601),"c".repeat(64),"a".repeat(64),app.seed.f.source,
                    List.of(id(1999)),List.of(new SimulationSpec.Fact(id(1999),i.customerId(),SimulationSpec.Kind.ID_DOC,SimulationSpec.Outcome.PASS,true,
                            Instant.ofEpochSecond(100),Instant.ofEpochSecond(400))));
            var reviewIdentity=new CommandIdentity(i.actorId(),id(2800),"synthetic-plan-review",i.canonicalizationVersion(),i.canonicalBodyDigest(),
                    i.grantId(),i.actionId(),i.targetRunId(),i.workflowId(),i.generation(),i.customerId());
            // Test-only preview obtains actual read bindings in an intentionally rolled-back owned callback.
            // It neither manufactures a successful receipt nor uses a success stub.
            var draft=new ReviewCommand(reviewIdentity,id(2901),ReviewDecision.APPROVE,"a".repeat(64),point,point.plus(app.terms.approvalLifetime()),"synthetic-comment");
            var captured=new AtomicReference<ReviewBindings>();var before=app.seed.f.store.snapshot();
            var preview=app.journal.review(draft,tx->{assertNull(tx.lookupReview(draft));tx.admitReview(draft);
                captured.set(tx.readReviewBindings(draft));throw OwnedGrantTransactionPort.stop(Status.UNCONFIRMED_BEFORE_ADMISSION);});
            assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,preview.status());assertNotNull(captured.get());
            assertEquals(before,app.seed.f.store.snapshot());
            var review=new ReviewCommand(reviewIdentity,id(2901),ReviewDecision.APPROVE,reviewHash(material(captured.get(),evidence,point)),
                    point,point.plus(app.terms.approvalLifetime()),"synthetic-comment");
            LocalPlanFacts facts=new LocalPlanFacts(){
                public Gate current(PlanServerContext c,CommandIdentity identity,PlanOperation op,OwnedMockPaymentPlanPort.OwnedPlanTx tx){return Gate.CLEAR;}
                public ResolvedEvidence resolveEvidence(PlanServerContext c,CommandIdentity identity,ReviewBindings b,OwnedMockPaymentPlanPort.OwnedPlanTx tx){return new ResolvedEvidence(b,evidence);}
            };
            var reviewed=new SyntheticMockPaymentPlanService(app.journal,facts).review(reviewer,review);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,reviewed.status());approval=reviewed.receipt().approval();
            assertEquals(ApprovalPlanState.AVAILABLE,approval.state());assertEquals("APPROVED",app.workflow().get("state"));
            intended=new PaymentDomain(child.grantId(),child.actionId(),id(2903),child.targetRunId(),approval.approvalId(),id(2902),
                    child.workflowId(),child.generation(),child.customerId(),evidence.applicationId(),approval.material().amountKrw(),
                    approval.material().payoutAccountId(),approval.material().policyVersion(),ReservationState.RESERVED,ApprovalState.RESERVED);
            CurrentFactResolver issuanceFacts=new CurrentFactResolver(){
                public Gate current(ServerContext c,StageCommand command,OwnedTx tx){currentChecks++;return Gate.CLEAR;}
                public ResolvedStage resolve(ServerContext c,StageCommand command,OutsidePreparedResult p,OwnedTx tx){throw new AssertionError("issuance must not resolve evaluation");}
                public Gate checkIssuance(ServerContext c,StageCommand stage,UUID parent,GrantSnapshot grant,OwnedTx tx){
                    issuanceChecks++;
                    if(bind==Bind.NONE)return Gate.CLEAR;
                    tx.bindCurrentIssuanceTime(stage,point);
                    if(bind==Bind.REPEAT)tx.bindCurrentIssuanceTime(stage,point);
                    if(bind==Bind.CONFLICT)tx.bindCurrentIssuanceTime(stage,point.plusSeconds(1));
                    if(bind==Bind.CROSS_COMMAND)tx.bindCurrentIssuanceTime(new StageCommand(identity(2999,child,"synthetic-other-command"),AllowedAction.EXECUTE_MOCK_PAYMENT),point);
                    return Gate.CLEAR;
                }
            };
            stages=new GrantStageTransactionService(app.journal,issuanceFacts);
        }
        CommandIdentity identity(long request,GrantSnapshot grant,String operation){var i=app.loan.identity();return new CommandIdentity(i.actorId(),id(request),operation,
                i.canonicalizationVersion(),i.canonicalBodyDigest(),grant.grantId(),grant.actionId(),grant.targetRunId(),grant.workflowId(),grant.generation(),grant.customerId());}
        StageOutcome issue(PaymentIssuanceProof proof){return stages.issueSuccessor(app.seed.context,command,app.loan.identity().grantId(),child,proof);}
        PaymentIssuanceProof proof(){return new PaymentIssuanceProof(approval,intended,point);}
    }
    @SuppressWarnings("unchecked")
    static <T extends Record>T changed(T value,String field,Object replacement)throws Exception{
        var components=value.getClass().getRecordComponents();var types=new Class<?>[components.length];var values=new Object[components.length];boolean found=false;
        for(int n=0;n<components.length;n++){RecordComponent c=components[n];types[n]=c.getType();values[n]=c.getAccessor().invoke(value);
            if(c.getName().equals(field)){values[n]=replacement;found=true;}}
        assertTrue(found);try{return(T)value.getClass().getConstructor(types).newInstance(values);}catch(InvocationTargetException e){
            if(e.getCause()instanceof RuntimeException failure)throw failure;throw e;}
    }
    static void refused(Fixture f,PaymentIssuanceProof proof,Status status){
        var before=f.app.seed.f.store.snapshot();int checks=f.issuanceChecks;var result=f.issue(proof);
        assertEquals(status,result.status());assertNull(result.receipt());assertEquals(checks+1,f.issuanceChecks);
        assertEquals(before,f.app.seed.f.store.snapshot());
        assertFalse(f.app.seed.f.store.snapshot().get("virtual_grant_profile_grants").containsKey(f.child.grantId().toString()));
    }

    @Test void actualAppApprovedSameLoanAndExactBoundPointAllowExplicitPaymentChild(){
        var f=new Fixture();var result=f.issue(f.proof());assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,result.status());
        assertEquals(ReceiptKind.ISSUANCE,result.receipt().kind());assertEquals(f.app.loan.identity().grantId(),result.receipt().parentGrantId());
        assertEquals(1,f.issuanceChecks);assertFalse(result.actualAuthority());assertFalse(result.durable());
    }
    @Test void missingProofAndOtherwiseValidUnboundPointCannotBecomeFreshIssuance(){
        var missing=new Fixture();refused(missing,null,Status.UNCONFIRMED_BEFORE_ADMISSION);
        var unbound=new Fixture();unbound.bind=Bind.NONE;refused(unbound,unbound.proof(),Status.UNCONFIRMED_BEFORE_ADMISSION);
    }
    @Test void backdatedOrSubsecondProofCannotChooseAnotherCurrentSnapshotPoint(){
        var backdated=new Fixture();backdated.point=backdated.point.plusSeconds(1);
        refused(backdated,new PaymentIssuanceProof(backdated.approval,backdated.intended,Instant.ofEpochSecond(150)),Status.UNCONFIRMED_BEFORE_ADMISSION);
        var nanos=new Fixture();refused(nanos,new PaymentIssuanceProof(nanos.approval,nanos.intended,nanos.point.plusNanos(1)),Status.UNCONFIRMED_BEFORE_ADMISSION);
    }
    @Test void exactLatchedButExpiredOrBeforeCreationApprovalPointIsRefused(){
        var expired=new Fixture();expired.point=expired.approval.expiresAt();refused(expired,expired.proof(),Status.REFUSED_BEFORE_ADMISSION);
        var early=new Fixture();early.point=early.approval.createdAt().minusSeconds(1);refused(early,early.proof(),Status.REFUSED_BEFORE_ADMISSION);
    }
    @Test void suppliedApprovalHashScopeAndConsumedDescriptorCannotReplaceActualStoredReview()throws Exception{
        for(String field:List.of("reviewSnapshotHash","material","state")){
            var f=new Fixture();Object replacement=field.equals("reviewSnapshotHash")?"f".repeat(64):field.equals("state")?ApprovalPlanState.CONSUMED:
                    changed(f.approval.material(),"loanResultId",id(999));
            var supplied=changed(f.approval,field,replacement);
            refused(f,new PaymentIssuanceProof(supplied,f.intended,f.point),Status.UNCONFIRMED_BEFORE_ADMISSION);
        }
    }
    @Test void intendedDomainCannotBorrowAnotherScopeApplicationAmountOrApproval()throws Exception{
        for(String field:List.of("workflowId","applicationId","approvalId","amountKrw")){
            var f=new Fixture();Object replacement=field.equals("amountKrw")?f.intended.amountKrw()+1:id(999);
            var supplied=changed(f.intended,field,replacement);
            refused(f,new PaymentIssuanceProof(f.approval,supplied,f.point),Status.IDENTITY_CONFLICT);
        }
    }
    @Test void actualCurrentLoanPointerMustStillMatchTheCoherentReviewedParent(){
        var f=new Fixture();f.app.seed.f.store.transaction(tx->{var key=f.command.identity().workflowId().toString();
            var row=new LinkedHashMap<>(tx.get("virtual_workflows",key));row.put("currentLoanResultId",id(999).toString());
            tx.put("virtual_workflows",key,row);return null;});
        refused(f,f.proof(),Status.REFUSED_BEFORE_ADMISSION);
    }
    @Test void identicalRebindIsAllowedButConflictingAndCrossCommandBindingCannotCommit(){
        var exact=new Fixture();exact.bind=Bind.REPEAT;assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,exact.issue(exact.proof()).status());
        var conflict=new Fixture();conflict.bind=Bind.CONFLICT;refused(conflict,conflict.proof(),Status.UNCONFIRMED_BEFORE_ADMISSION);
        var cross=new Fixture();cross.bind=Bind.CROSS_COMMAND;refused(cross,cross.proof(),Status.IDENTITY_CONFLICT);
    }
    @Test void exactHistoricalIssuanceDoesNotReapplyFreshApprovalProofOrTimeGate(){
        var f=new Fixture();var first=f.issue(f.proof());assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,first.status());
        var before=f.app.seed.f.store.snapshot();int calls=f.issuanceChecks;f.point=f.approval.expiresAt();f.bind=Bind.CONFLICT;
        var replay=f.issue(null);assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,replay.status());assertEquals(first.receipt(),replay.receipt());
        assertEquals(calls,f.issuanceChecks);assertEquals(before,f.app.seed.f.store.snapshot());
    }
}
