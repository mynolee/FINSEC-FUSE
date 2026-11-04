package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane.Scope;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.TypedContinuationPendingAdmission.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBindingTest.*;
import static org.junit.jupiter.api.Assertions.*;

/** Pure supplied-evidence classification; no owned adapter, producer or generation transition. */
class TypedContinuationPendingAdmissionTest {
    static final Profile PROFILE=new Profile(4,8);
    static final class Fixture {
        final SyntheticMockPaymentPlanBindingTest.Fixture f=new SyntheticMockPaymentPlanBindingTest.Fixture();
        final PreparedReview review=f.approved();
        final PreparedReservation reserve=prepareReservation(f.reserve(f.domain(),NOW),f.reservation(f.bindings(3,0,25),review.approval()),f.evidence());
        final PlanReceipt reviewReceipt=new PlanReceipt(1,PlanOperation.REVIEW,f.review(f.bindings(3,0,20),ReviewDecision.APPROVE).identity(),review.approval(),null,0);
        final PlanReceipt reserveReceipt=new PlanReceipt(1,PlanOperation.RESERVE,f.reserve(f.domain(),NOW).identity(),reserve.approval(),f.domain(),f.terms.payPoints());
        final LocalPlanRecord localReview=new LocalPlanRecord(reviewReceipt,H),localReserve=new LocalPlanRecord(reserveReceipt,J);
        final GlobalPlanRecord globalReview=new GlobalPlanRecord(reviewReceipt.identity(),H,reviewReceipt,GlobalState.COMPLETED),
                globalReserve=new GlobalPlanRecord(reserveReceipt.identity(),J,reserveReceipt,GlobalState.COMPLETED);
        final RiskReservation risk=new RiskReservation(id(42),id(43),id(41),id(31),id(32),id(33),f.scope,f.terms.policyVersion(),f.terms.payPoints(),RiskState.RESERVED);
        final ProducerObservation producer=new ProducerObservation(id(42),ProducerState.NO_EXECUTION_OBSERVED,null);
        ReservationEvidence evidence(){return evidence(globalReserve,f.evaluations.loanReference(),f.evaluations.loanReceipt());}
        ReservationEvidence evidence(GlobalPlanRecord global,VirtualGrantTransactionJournal.TypedReference loanRef,Receipt loanReceipt){
            return new ReservationEvidence(localReview,globalReview,localReserve,global,reserve.approval(),f.domain(),
                    f.reservation(f.bindings(3,0,25),review.approval()).paymentGrant(),reference(31,32,33,23L,24L,null),
                    f.evaluations.loanGrant(),loanReceipt,loanRef);
        }
        Snapshot snapshot(){return snapshot(f.terms,f.terms.payPoints(),List.of(evidence()),List.of(risk),List.of(producer),List.of());}
        Snapshot snapshot(SimulationSpec.RiskTerms terms,int reserved,List<ReservationEvidence> evidence,List<RiskReservation> risks,List<ProducerObservation> producers,List<UnsettledRequest> requests){
            return new Snapshot(f.scope,terms,reserved,evidence,risks,producers,requests);
        }
        RiskReservation risk(int points,RiskState state,Scope scope){return new RiskReservation(risk.reservationId(),risk.paymentId(),risk.approvalId(),risk.grantId(),risk.actionId(),risk.targetRunId(),scope,risk.policyVersion(),points,state);}
    }
    static void nonAuthorizing(Assessment out){
        assertFalse(out.mutationPermitted());assertFalse(out.continuationAuthorized());assertFalse(out.queryCompletenessEstablished());
        assertFalse(out.producerTruthEstablished());assertFalse(out.actualAuthority());
    }
    static void unknown(Snapshot snapshot){var out=assess(PROFILE,Use.FRESH_ADMISSION,snapshot);assertEquals(Outcome.RECONCILIATION_UNKNOWN,out.outcome());nonAuthorizing(out);}
    static ReservationEvidence second(Fixture f,GrantSnapshot loan,Receipt loanReceipt,VirtualGrantTransactionJournal.TypedReference loanRef){
        var old=f.reviewReceipt.approval();
        var ri=identity(510,loan.grantId().getLeastSignificantBits(),loan.actionId().getLeastSignificantBits(),loan.targetRunId().getLeastSignificantBits());
        var available=new ApprovalSnapshot(id(51),ri.globalRequestId(),ri.actorId(),old.decision(),old.material(),old.reviewSnapshotHash(),old.createdAt(),old.expiresAt(),old.extraRiskLimit(),old.riskLimit(),ApprovalPlanState.AVAILABLE);
        var reserved=new ApprovalSnapshot(id(51),ri.globalRequestId(),ri.actorId(),old.decision(),old.material(),old.reviewSnapshotHash(),old.createdAt(),old.expiresAt(),old.extraRiskLimit(),old.riskLimit(),ApprovalPlanState.RESERVED);
        var d=new SyntheticMockPaymentTransactionBinding.PaymentDomain(id(61),id(62),id(73),id(63),id(51),id(72),id(1),1,CUSTOMER,id(4),1000,id(3),f.f.terms.policyVersion(),
                SyntheticMockPaymentTransactionBinding.ReservationState.RESERVED,SyntheticMockPaymentTransactionBinding.ApprovalState.RESERVED);
        var review=new PlanReceipt(1,PlanOperation.REVIEW,ri,available,null,0);
        var reserve=new PlanReceipt(1,PlanOperation.RESERVE,identity(520,61,62,63),reserved,d,3);
        return new ReservationEvidence(new LocalPlanRecord(review,H),new GlobalPlanRecord(ri,H,review,GlobalState.COMPLETED),
                new LocalPlanRecord(reserve,J),new GlobalPlanRecord(reserve.identity(),J,reserve,GlobalState.COMPLETED),reserved,d,
                grant(61,62,63,com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction.EXECUTE_MOCK_PAYMENT,GrantState.ISSUED),
                reference(61,62,63,loan.targetRunId().getLeastSignificantBits(),24L,null),loan,loanReceipt,loanRef);
    }
    static Snapshot pair(Fixture f,ReservationEvidence second){
        var d=second.currentPlan();var risk=new RiskReservation(d.reservationId(),d.paymentId(),d.approvalId(),d.grantId(),d.actionId(),d.targetRunId(),f.f.scope,d.securityPolicyVersion(),3,RiskState.RESERVED);
        return f.snapshot(f.f.terms,6,List.of(f.evidence(),second),List.of(f.risk,risk),List.of(f.producer,new ProducerObservation(d.reservationId(),ProducerState.NO_EXECUTION_OBSERVED,null)),List.of());
    }
    @Test void conflictingParentReceiptOrReusedResultCannotSupportTwoOtherwiseCoherentReservations(){
        var f=new Fixture();
        var changedReceipt=receipt(502,21,22,23,24,com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion.POSITIVE);
        unknown(pair(f,second(f,f.f.evaluations.loanGrant(),changedReceipt,f.f.evaluations.loanReference())));
        var otherLoan=grant(81,82,83,com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction.CREATE_LOAN_RECOMMENDATION,GrantState.CONSUMED);
        var reusedResult=receipt(503,81,82,83,24,com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion.POSITIVE);
        unknown(pair(f,second(f,otherLoan,reusedResult,reference(81,82,83,13L,14L,24L))));
    }
    @Test void identicalParentReceiptValueMaySupportTwoDistinctReservationsWithoutBlanketDuplicateBan(){
        var f=new Fixture();var old=f.f.evaluations.loanReceipt();
        var copy=new Receipt(old.identity(),old.kind(),new OutsidePreparedResult(old.result().resultId(),old.result().businessConclusion(),old.result().bindingProfile(),old.result().bindingBytes(),old.result().bindingDigest()),old.parentGrantId());
        assertEquals(old,copy);assertNotSame(old,copy);
        var s=pair(f,second(f,f.f.evaluations.loanGrant(),copy,f.f.evaluations.loanReference()));
        var out=assess(PROFILE,Use.FRESH_ADMISSION,s);assertEquals(Outcome.REFUSE_NO_MUTATION,out.outcome());assertEquals(2,out.matchedReservations());nonAuthorizing(out);
    }
    @Test void coherentNonemptyEvidenceRefusesWithoutOfferingMutationOrAuthority(){
        var f=new Fixture();var before=f.snapshot();var out=assess(PROFILE,Use.FRESH_ADMISSION,before);
        assertEquals(Outcome.REFUSE_NO_MUTATION,out.outcome());assertEquals(Reason.STRUCTURALLY_MATCHED_PENDING,out.reason());
        assertEquals(1,out.matchedReservations());assertEquals(before,f.snapshot());nonAuthorizing(out);
    }
    @Test void emptySuppliedInventoryCannotAuthorizeOrProveCompleteness(){
        var f=new Fixture();var out=assess(PROFILE,Use.FRESH_ADMISSION,f.snapshot(f.f.terms,0,List.of(),List.of(),List.of(),List.of()));
        assertEquals(Outcome.EMPTY_EVIDENCE_NOT_AUTHORIZATION,out.outcome());assertEquals(0,out.matchedReservations());nonAuthorizing(out);
        unknown(f.snapshot(f.f.terms,0,List.of(),List.of(f.risk),List.of(f.producer),List.of()));
    }
    @Test void missingDuplicateOrOrphanRecordsCannotBeSkippedAsEmpty(){
        var f=new Fixture();
        unknown(f.snapshot(f.f.terms,3,List.of(f.evidence()),List.of(),List.of(f.producer),List.of()));
        unknown(f.snapshot(f.f.terms,3,List.of(f.evidence()),List.of(f.risk),List.of(),List.of()));
        unknown(f.snapshot(f.f.terms,3,List.of(f.evidence(),f.evidence()),List.of(f.risk),List.of(f.producer),List.of()));
        unknown(f.snapshot(f.f.terms,3,List.of(f.evidence()),List.of(f.risk,f.risk),List.of(f.producer),List.of()));
        var missing=new ReservationEvidence(null,f.globalReview,f.localReserve,f.globalReserve,f.reserve.approval(),f.f.domain(),
                f.evidence().paymentGrant(),f.evidence().paymentReference(),f.f.evaluations.loanGrant(),f.f.evaluations.loanReceipt(),f.f.evaluations.loanReference());
        unknown(f.snapshot(f.f.terms,3,List.of(missing),List.of(f.risk),List.of(f.producer),List.of()));
    }
    @Test void zeroPaymentIsUnknownWhileLegalZeroStageTermsRemainUnchanged(){
        var f=new Fixture();unknown(f.snapshot(f.f.terms,0,List.of(f.evidence()),List.of(f.risk(0,RiskState.RESERVED,f.f.scope)),List.of(f.producer),List.of()));
        var t=f.f.terms;var zeroStages=new SimulationSpec.RiskTerms(t.policyVersion(),0,0,t.payPoints(),t.baseLimit(),t.additionalApprovalLimit(),t.maxAutomaticKycRuns(),t.approvalLifetime());
        var out=assess(PROFILE,Use.FRESH_ADMISSION,f.snapshot(zeroStages,3,List.of(f.evidence()),List.of(f.risk),List.of(f.producer),List.of()));
        assertEquals(Outcome.REFUSE_NO_MUTATION,out.outcome());assertEquals(0,zeroStages.kycPoints());assertEquals(0,zeroStages.loanPoints());nonAuthorizing(out);
        // This classifier has no KYC-count/first-charge ledger input; it does not prove accounting reset or ledger validity.
    }
    @Test void mixedRiskScopeConsumedStateAndAggregateMismatchRemainUnknown(){
        var f=new Fixture();
        for(var risk:List.of(f.risk(3,RiskState.CONSUMED,f.f.scope),f.risk(3,RiskState.RESERVED,new Scope(id(1),2,CUSTOMER)),f.risk(3,RiskState.RESERVED,new Scope(id(1),1,"synthetic-other"))))
            unknown(f.snapshot(f.f.terms,3,List.of(f.evidence()),List.of(risk),List.of(f.producer),List.of()));
        unknown(f.snapshot(f.f.terms,2,List.of(f.evidence()),List.of(f.risk),List.of(f.producer),List.of()));
    }
    @Test void pendingGlobalAndFullIdentityFingerprintSubstitutionCannotLookCompleted(){
        var f=new Fixture();var i=f.reserveReceipt.identity();
        var other=new CommandIdentity("synthetic-other",i.globalRequestId(),i.operation(),i.canonicalizationVersion(),i.canonicalBodyDigest(),i.grantId(),i.actionId(),i.targetRunId(),i.workflowId(),i.generation(),i.customerId());
        for(var global:List.of(new GlobalPlanRecord(i,J,f.reserveReceipt,GlobalState.PENDING),new GlobalPlanRecord(i,J,f.reserveReceipt,GlobalState.COMMIT_UNKNOWN),
                new GlobalPlanRecord(other,J,f.reserveReceipt,GlobalState.COMPLETED),new GlobalPlanRecord(i,H,f.reserveReceipt,GlobalState.COMPLETED)))
            unknown(f.snapshot(f.f.terms,3,List.of(f.evidence(global,f.f.evaluations.loanReference(),f.f.evaluations.loanReceipt())),List.of(f.risk),List.of(f.producer),List.of()));
    }
    @Test void unresolvedProducerAndPostAcknowledgementUncertaintyAreNotAbsence(){
        var f=new Fixture();
        for(var state:List.of(ProducerState.IN_FLIGHT,ProducerState.COMMIT_UNKNOWN,ProducerState.EXECUTED,ProducerState.UNCONFIRMED))
            unknown(f.snapshot(f.f.terms,3,List.of(f.evidence()),List.of(f.risk),List.of(new ProducerObservation(id(42),state,f.reserveReceipt.identity())),List.of()));
        for(var state:List.of(GlobalState.PENDING,GlobalState.COMMIT_UNKNOWN,GlobalState.UNCONFIRMED))
            unknown(f.snapshot(f.f.terms,3,List.of(f.evidence()),List.of(f.risk),List.of(f.producer),List.of(new UnsettledRequest(f.reserveReceipt.identity(),state))));
    }
    @Test void wrongLoanDocumentAndVersionCannotBorrowPaymentDocumentJoin(){
        var f=new Fixture();var r=f.f.evaluations.loanReference();
        for(int mode=0;mode<2;mode++){
            var wrong=new VirtualGrantTransactionJournal.TypedReference(r.workflowId(),r.generation(),r.customerId(),r.targetRunId(),r.grantId(),r.actionId(),
                    mode==0?id(999):r.documentId(),mode==1?r.documentVersion()+1:r.documentVersion(),r.agentId(),r.agentVersion(),r.sourceRunId(),r.sourceResultId(),r.resultId());
            unknown(f.snapshot(f.f.terms,3,List.of(f.evidence(f.globalReserve,wrong,f.f.evaluations.loanReceipt())),List.of(f.risk),List.of(f.producer),List.of()));
        }
    }
    @Test void wrongKycResultAndSelfParentCannotBorrowOtherwiseValidLoanHistory(){
        var f=new Fixture();var r=f.f.evaluations.loanReference();
        for(int mode=0;mode<2;mode++){
            var wrong=new VirtualGrantTransactionJournal.TypedReference(r.workflowId(),r.generation(),r.customerId(),r.targetRunId(),r.grantId(),r.actionId(),
                    r.documentId(),r.documentVersion(),r.agentId(),r.agentVersion(),mode==1?r.targetRunId():r.sourceRunId(),mode==0?id(999):r.sourceResultId(),r.resultId());
            unknown(f.snapshot(f.f.terms,3,List.of(f.evidence(f.globalReserve,wrong,f.f.evaluations.loanReceipt())),List.of(f.risk),List.of(f.producer),List.of()));
        }
    }
    @Test void loanConsumptionCannotAliasReviewOrReserveGlobalRequest(){
        var f=new Fixture();var old=f.f.evaluations.loanReceipt();
        for(var phase:List.of(f.reviewReceipt.identity(),f.reserveReceipt.identity())){
            var i=old.identity();var alias=new CommandIdentity(i.actorId(),phase.globalRequestId(),i.operation(),i.canonicalizationVersion(),i.canonicalBodyDigest(),i.grantId(),i.actionId(),i.targetRunId(),i.workflowId(),i.generation(),i.customerId());
            var receipt=new Receipt(alias,old.kind(),old.result(),old.parentGrantId());
            unknown(f.snapshot(f.f.terms,3,List.of(f.evidence(f.globalReserve,f.f.evaluations.loanReference(),receipt)),List.of(f.risk),List.of(f.producer),List.of()));
        }
    }
    @Test void historyIsOutsideFreshRuleAndDoesNotBecomeNewExecutionPermission(){
        var f=new Fixture();var s=f.snapshot(f.f.terms,3,List.of(f.evidence()),List.of(f.risk),List.of(f.producer),List.of(new UnsettledRequest(f.reserveReceipt.identity(),GlobalState.COMMIT_UNKNOWN)));
        var out=assess(PROFILE,Use.HISTORICAL_REPLAY,s);assertEquals(Outcome.OUTSIDE_FRESH_RULE,out.outcome());assertEquals(Reason.HISTORY_NOT_FRESH,out.reason());nonAuthorizing(out);
    }
    @Test void copiedListsRedactedEvidenceAndExplicitBoundsDoNotCreateTrustedFacts(){
        var f=new Fixture();var entries=new ArrayList<>(List.of(f.evidence()));var risks=new ArrayList<>(List.of(f.risk));
        var s=f.snapshot(f.f.terms,3,entries,risks,List.of(f.producer),List.of());entries.clear();risks.clear();
        assertEquals(1,s.reservations().size());assertEquals(1,s.riskInventory().size());assertThrows(UnsupportedOperationException.class,()->s.reservations().clear());
        assertFalse(s.toString().contains(SECRET));assertFalse(f.evidence().toString().contains(id(42).toString()));
        var bad=assertThrows(IllegalArgumentException.class,()->new Profile(0,1));assertEquals("INVALID_PENDING_ADMISSION",bad.getMessage());assertNull(bad.getCause());
        var out=assess(new Profile(1,1),Use.FRESH_ADMISSION,f.snapshot(f.f.terms,3,List.of(f.evidence(),f.evidence()),List.of(f.risk),List.of(f.producer),List.of()));
        assertEquals(Outcome.RECONCILIATION_UNKNOWN,out.outcome());nonAuthorizing(out);
    }
}
