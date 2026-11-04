package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane.Scope;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;

/** Independent in-source review/reservation fixtures; no actual payment or authority. */
class SyntheticMockPaymentPlanBindingTest {
    static UUID id(long n) { return new UUID(71,n); }
    static final String CUSTOMER="synthetic-plan-customer", ACTOR="synthetic-reviewer-alias";
    static final Instant NOW=Instant.ofEpochSecond(100);
    static final String H="a".repeat(64), J="b".repeat(64), SECRET="synthetic-source-canary";
    static CommandIdentity identity(long request,long grant,long action,long run) {
        return new CommandIdentity(ACTOR,id(request),"synthetic-plan-phase","synthetic-canonical-profile",H,
                id(grant),id(action),id(run),id(1),1,CUSTOMER);
    }
    static GrantSnapshot grant(long g,long a,long run,AllowedAction kind,GrantState state) {
        return new GrantSnapshot(id(g),id(a),id(run),id(1),1,CUSTOMER,kind,state);
    }
    static Receipt receipt(long request,long g,long a,long run,long result,BusinessConclusion conclusion) {
        return new Receipt(identity(request,g,a,run),ReceiptKind.CONSUMPTION,
                new OutsidePreparedResult(id(result),conclusion,"AGENT_RESULT_BINDING_RECORD_1",new byte[]{1},new byte[]{2}),null);
    }
    static VirtualGrantTransactionJournal.TypedReference reference(long g,long a,long run,Long sourceRun,Long sourceResult,Long result) {
        return new VirtualGrantTransactionJournal.TypedReference(id(1),1,CUSTOMER,id(run),id(g),id(a),id(2),1,"synthetic-agent",1,
                sourceRun==null?null:id(sourceRun),sourceResult==null?null:id(sourceResult),result==null?null:id(result));
    }
    static final class Fixture {
        final SimulationSpec.RiskTerms terms=new SimulationSpec.RiskTerms("synthetic-policy",1,2,3,20,5,2,Duration.ofSeconds(60));
        final Scope scope=new Scope(id(1),1,CUSTOMER);
        final SimulationSpec.Source source=new SimulationSpec.Source(id(2),1,SECRET,SimulationSpec.rawHash(SECRET),true);
        final SimulationSpec.Fact fact=new SimulationSpec.Fact(id(90),CUSTOMER,SimulationSpec.Kind.ID_DOC,SimulationSpec.Outcome.PASS,true,
                Instant.EPOCH,Instant.ofEpochSecond(1000));
        final EvaluationSnapshot evaluations=new EvaluationSnapshot(grant(11,12,13,AllowedAction.EVALUATE_KYC,GrantState.CONSUMED),
                receipt(101,11,12,13,14,BusinessConclusion.POSITIVE),reference(11,12,13,null,null,14L),
                grant(21,22,23,AllowedAction.CREATE_LOAN_RECOMMENDATION,GrantState.CONSUMED),
                receipt(102,21,22,23,24,BusinessConclusion.POSITIVE),reference(21,22,23,13L,14L,24L));
        ReviewBindings bindings(int used,int reserved,int limit) {
            return new ReviewBindings(new WorkflowSnapshot(scope,"synthetic-business",id(2),1,1000,id(3),used,reserved,limit,terms),evaluations);
        }
        EvidenceSnapshot evidence() { return evidence(source,List.of(id(90)),List.of(fact),id(4),id(14),id(24)); }
        EvidenceSnapshot evidence(SimulationSpec.Source source,List<UUID> ids,List<SimulationSpec.Fact> facts,UUID app,UUID kyc,UUID loan) {
            return new EvidenceSnapshot(app,kyc,loan,H,J,source,ids,facts);
        }
        ReviewCommand review(ReviewBindings b,ReviewDecision choice) {
            return new ReviewCommand(identity(110,21,22,23),id(41),choice,reviewHash(material(b,evidence(),NOW)),NOW,NOW.plusSeconds(60),"synthetic-comment-canary");
        }
        PreparedReview approved() { var b=bindings(3,0,20);return prepareReview(review(b,ReviewDecision.APPROVE),b,evidence()); }
        PaymentDomain domain(UUID application,long amount,UUID payout,String policy) {
            return new PaymentDomain(id(31),id(32),id(43),id(33),id(41),id(42),id(1),1,CUSTOMER,application,amount,payout,policy,
                    ReservationState.RESERVED,ApprovalState.RESERVED);
        }
        PaymentDomain domain() { return domain(id(4),1000,id(3),terms.policyVersion()); }
        ReservationBindings reservation(ReviewBindings b,ApprovalSnapshot approval) {
            return new ReservationBindings(b,approval,grant(31,32,33,AllowedAction.EXECUTE_MOCK_PAYMENT,GrantState.ISSUED),
                    reference(31,32,33,23L,24L,null));
        }
        ReserveCommand reserve(PaymentDomain d,Instant now) { return new ReserveCommand(identity(120,31,32,33),d,approved().approval().reviewSnapshotHash(),now); }
    }
    static void invalid(Runnable action) {
        var e=assertThrows(IllegalArgumentException.class,action::run);
        assertEquals("INVALID_MOCK_PAYMENT_PLAN",e.getMessage());assertNull(e.getCause());
    }

    @Test void canonicalReviewHashUsesExplicitSafeFieldsAndNeverSourceText() {
        Fixture f=new Fixture();var m=material(f.bindings(3,0,20),f.evidence(),NOW);
        var fields=new LinkedHashMap<String,Object>();
        fields.put("workflowId",id(1).toString());fields.put("generation",1);fields.put("customerId",CUSTOMER);fields.put("applicationId",id(4).toString());
        fields.put("amountKrw",1000L);fields.put("payoutAccountId",id(3).toString());fields.put("kycResultId",id(14).toString());fields.put("loanResultId",id(24).toString());
        fields.put("evidenceBundleHash",H);fields.put("loanResultHash",J);fields.put("documentId",id(2).toString());fields.put("documentVersion",1);
        fields.put("sourceContentHash",f.source.contentHash());fields.put("policyVersion",f.terms.policyVersion());fields.put("usedRisk",3);fields.put("reservedRisk",0);fields.put("riskLimitAfterApproval",25);
        assertEquals(CanonicalJson.sha256(fields),reviewHash(m));assertFalse(String.valueOf(m).contains(SECRET));
        var other=f.evidence(f.source,List.of(id(90)),List.of(f.fact),id(999),id(14),id(24));
        assertNotEquals(reviewHash(m),reviewHash(material(f.bindings(3,0,20),other,NOW)));
    }
    @Test void evidenceListsAreDetachedAndRequireExactUniqueUsableCustomerSet() {
        Fixture f=new Fixture();var ids=new ArrayList<>(List.of(id(90)));var facts=new ArrayList<>(List.of(f.fact));
        var e=f.evidence(f.source,ids,facts,id(4),id(14),id(24));ids.clear();facts.clear();
        assertEquals(List.of(id(90)),e.evidenceIds());assertEquals(List.of(f.fact),e.evidence());
        assertThrows(UnsupportedOperationException.class,()->e.evidenceIds().add(id(91)));
        invalid(()->f.evidence(f.source,List.of(id(90),id(90)),List.of(f.fact),id(4),id(14),id(24)));
        invalid(()->material(f.bindings(3,0,20),f.evidence(f.source,List.of(),List.of(f.fact),id(4),id(14),id(24)),NOW));
        var expired=new SimulationSpec.Fact(id(90),CUSTOMER,SimulationSpec.Kind.ID_DOC,SimulationSpec.Outcome.PASS,true,Instant.EPOCH,NOW);
        var foreign=new SimulationSpec.Fact(id(90),"synthetic-other",SimulationSpec.Kind.ID_DOC,SimulationSpec.Outcome.PASS,true,Instant.EPOCH,NOW.plusSeconds(1));
        var failed=new SimulationSpec.Fact(id(90),CUSTOMER,SimulationSpec.Kind.ID_DOC,SimulationSpec.Outcome.FAIL,true,Instant.EPOCH,NOW.plusSeconds(1));
        for(var fact:List.of(expired,foreign,failed))invalid(()->material(f.bindings(3,0,20),f.evidence(f.source,List.of(id(90)),List.of(fact),id(4),id(14),id(24)),NOW));
    }
    @Test void sourceCoordinatesAndResultLinksMustMatchActualSuppliedSnapshots() {
        Fixture f=new Fixture();var unsafe=new SimulationSpec.Source(id(2),1,SECRET,SimulationSpec.rawHash(SECRET),false);
        var wrongDoc=new SimulationSpec.Source(id(222),1,SECRET,SimulationSpec.rawHash(SECRET),true);
        for(var source:List.of(unsafe,wrongDoc))invalid(()->material(f.bindings(3,0,20),f.evidence(source,List.of(id(90)),List.of(f.fact),id(4),id(14),id(24)),NOW));
        invalid(()->material(f.bindings(3,0,20),f.evidence(f.source,List.of(id(90)),List.of(f.fact),id(4),id(999),id(24)),NOW));
    }
    @Test void negativeOrUnconsumedEvaluationAndBrokenLoanParentCannotApprove() {
        Fixture f=new Fixture();var original=f.bindings(3,0,20);
        var negative=new EvaluationSnapshot(f.evaluations.kycGrant(),receipt(101,11,12,13,14,BusinessConclusion.NEGATIVE),f.evaluations.kycReference(),
                f.evaluations.loanGrant(),f.evaluations.loanReceipt(),f.evaluations.loanReference());
        var unconsumed=new EvaluationSnapshot(grant(11,12,13,AllowedAction.EVALUATE_KYC,GrantState.ISSUED),f.evaluations.kycReceipt(),f.evaluations.kycReference(),
                f.evaluations.loanGrant(),f.evaluations.loanReceipt(),f.evaluations.loanReference());
        var wrongParent=new EvaluationSnapshot(f.evaluations.kycGrant(),f.evaluations.kycReceipt(),f.evaluations.kycReference(),
                f.evaluations.loanGrant(),f.evaluations.loanReceipt(),reference(21,22,23,99L,14L,24L));
        for(var e:List.of(negative,unconsumed,wrongParent))invalid(()->material(new ReviewBindings(original.workflow(),e),f.evidence(),NOW));
    }
    @Test void approveAndRejectUseExactExplicitLifetimeAndExistingRiskTerms() {
        Fixture f=new Fixture();var b=f.bindings(3,0,20);
        for(var decision:ReviewDecision.values()) {
            var prepared=prepareReview(f.review(b,decision),b,f.evidence());var a=prepared.approval();
            assertEquals(decision,a.decision());assertEquals(NOW.plusSeconds(60),a.expiresAt());assertEquals(3,a.material().usedRisk());
            assertEquals(decision==ReviewDecision.APPROVE?5:0,a.extraRiskLimit());assertEquals(decision==ReviewDecision.APPROVE?25:20,a.riskLimit());
            assertEquals(decision==ReviewDecision.APPROVE?ApprovalPlanState.AVAILABLE:ApprovalPlanState.REJECTED,a.state());
        }
        var c=f.review(b,ReviewDecision.APPROVE);
        invalid(()->prepareReview(new ReviewCommand(c.identity(),c.approvalId(),c.decision(),c.expectedReviewSnapshotHash(),NOW,NOW.plusSeconds(61),c.comment()),b,f.evidence()));
        invalid(()->prepareReview(new ReviewCommand(c.identity(),c.approvalId(),c.decision(),J,NOW,c.expiresAt(),c.comment()),b,f.evidence()));
    }
    @Test void reservationBindsAllDomainFieldsAndReservesExactlyExistingPayPoints() {
        Fixture f=new Fixture();var b=f.bindings(3,0,25);var a=f.approved().approval();
        var p=prepareReservation(f.reserve(f.domain(),NOW),f.reservation(b,a),f.evidence());
        assertEquals(3,p.riskPoints());assertEquals(ApprovalPlanState.RESERVED,p.approval().state());assertEquals(ApprovalPlanState.AVAILABLE,a.state());
        for(var d:List.of(f.domain(id(999),1000,id(3),f.terms.policyVersion()),f.domain(id(4),1001,id(3),f.terms.policyVersion()),
                f.domain(id(4),1000,id(999),f.terms.policyVersion()),f.domain(id(4),1000,id(3),"synthetic-other-policy")))
            invalid(()->prepareReservation(f.reserve(d,NOW),f.reservation(b,a),f.evidence()));
    }
    @Test void expiredReservedOrStaleReviewCannotReserveAndCapacityDoesNotWrap() {
        Fixture f=new Fixture();var b=f.bindings(3,0,25);var a=f.approved().approval();
        invalid(()->prepareReservation(f.reserve(f.domain(),a.expiresAt()),f.reservation(b,a),f.evidence()));
        for(var state:List.of(ApprovalPlanState.RESERVED,ApprovalPlanState.CONSUMED)) {
            var unavailable=new ApprovalSnapshot(a.approvalId(),a.reviewRequestId(),a.reviewerActorId(),a.decision(),a.material(),a.reviewSnapshotHash(),a.createdAt(),a.expiresAt(),a.extraRiskLimit(),a.riskLimit(),state);
            invalid(()->prepareReservation(f.reserve(f.domain(),NOW),f.reservation(b,unavailable),f.evidence()));
            assertEquals(state,unavailable.state());assertEquals(ApprovalPlanState.AVAILABLE,a.state());
        }
        invalid(()->prepareReservation(f.reserve(f.domain(),NOW),f.reservation(f.bindings(4,0,25),a),f.evidence()));
        var high=f.bindings(Integer.MAX_VALUE,0,25);var hm=material(high,f.evidence(),NOW);
        var ha=new ApprovalSnapshot(id(41),id(110),ACTOR,ReviewDecision.APPROVE,hm,reviewHash(hm),NOW,NOW.plusSeconds(60),5,25,ApprovalPlanState.AVAILABLE);
        var hc=new ReserveCommand(identity(120,31,32,33),f.domain(),reviewHash(hm),NOW);
        invalid(()->prepareReservation(hc,f.reservation(high,ha),f.evidence()));
    }
    @Test void capacityEqualityAdmitsButOnePointBeyondWithMatchingReviewRefuses() {
        Fixture f=new Fixture();
        for(int used:List.of(20,21)) {
            var b=f.bindings(used,2,25);var m=material(b,f.evidence(),NOW);
            var a=new ApprovalSnapshot(id(41),id(110),ACTOR,ReviewDecision.APPROVE,m,reviewHash(m),NOW,NOW.plusSeconds(60),5,25,ApprovalPlanState.AVAILABLE);
            var c=new ReserveCommand(identity(120,31,32,33),f.domain(),reviewHash(m),NOW);
            if(used==20)assertEquals(3,prepareReservation(c,f.reservation(b,a),f.evidence()).riskPoints());
            else invalid(()->prepareReservation(c,f.reservation(b,a),f.evidence()));
        }
    }
    @Test void malformedIdentityDomainAndOutcomeShapesFailClosed() {
        Fixture f=new Fixture();invalid(()->new ReserveCommand(identity(120,999,32,33),f.domain(),H,NOW));
        var a=f.approved().approval();invalid(()->new PlanReceipt(1,PlanOperation.REVIEW,identity(110,21,22,23),a,f.domain(),0));
        invalid(()->new PlanOutcome(Status.COMMIT_UNKNOWN,new PlanReceipt(1,PlanOperation.REVIEW,identity(110,21,22,23),a,null,0),PlanEffect.UNKNOWN));
        var unknown=new PlanOutcome(Status.COMMIT_UNKNOWN,null,PlanEffect.UNKNOWN);assertFalse(unknown.actualAuthority());assertFalse(unknown.durable());
    }
    @Test void diagnosticsExcludeSourceCommentIdentifiersAndRetainExplicitAccessors() {
        Fixture f=new Fixture();var b=f.bindings(3,0,20);var command=f.review(b,ReviewDecision.APPROVE);var p=prepareReview(command,b,f.evidence());
        for(Object o:List.of(command,f.evidence(),p,p.approval(),p.approval().material(),new PlanReceipt(1,PlanOperation.REVIEW,command.identity(),p.approval(),null,0))) {
            var text=String.valueOf(o);assertFalse(text.contains(SECRET));assertFalse(text.contains(command.comment()));assertFalse(text.contains(id(41).toString()));
        }
        assertEquals("synthetic-comment-canary",command.comment());assertEquals(id(4),p.approval().material().applicationId());
    }
}
