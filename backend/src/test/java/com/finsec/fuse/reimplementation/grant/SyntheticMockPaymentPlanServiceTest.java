package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBindingTest.*;

/** Strict fake protocol tests; a returned fake receipt is not actual Journal/store commit proof. */
class SyntheticMockPaymentPlanServiceTest {
    static final class Tx implements OwnedMockPaymentPlanPort.OwnedPlanTx {
        final List<String> events;
        final Fixture data=new Fixture();
        final ReviewBindings reviewBindings=data.bindings(3,0,20);
        final ReservationBindings reservationBindings=data.reservation(data.bindings(3,0,25),data.approved().approval());
        PlanReceipt priorReview,priorReserve;PreparedReview recordedReview;PreparedReservation recordedReserve;
        Tx(List<String> events){this.events=events;}
        public PlanReceipt lookupReview(ReviewCommand c){events.add("lookup-review");return priorReview;}
        public PlanReceipt lookupReservation(ReserveCommand c){events.add("lookup-reserve");return priorReserve;}
        public void admitReview(ReviewCommand c){events.add("admit-review");}
        public void admitReservation(ReserveCommand c){events.add("admit-reserve");}
        public ReviewBindings readReviewBindings(ReviewCommand c){events.add("read-review");return reviewBindings;}
        public ReservationBindings readReservationBindings(ReserveCommand c){events.add("read-reserve");return reservationBindings;}
        public PlanReceipt recordReview(ReviewCommand c,PreparedReview p){
            events.add("record-review");assertSame(reviewBindings,p.bindings());assertEquals(c,p.command());recordedReview=p;
            return new PlanReceipt(1,PlanOperation.REVIEW,c.identity(),p.approval(),null,0);
        }
        public PlanReceipt recordReservation(ReserveCommand c,PreparedReservation p){
            events.add("record-reserve");assertSame(reservationBindings,p.bindings());assertEquals(c,p.command());recordedReserve=p;
            return new PlanReceipt(1,PlanOperation.RESERVE,c.identity(),p.approval(),c.domain(),p.riskPoints());
        }
    }
    static final class Port implements OwnedMockPaymentPlanPort {
        final List<String> events=new ArrayList<>();final Tx tx=new Tx(events);
        public PlanOutcome review(ReviewCommand c,PlanWork work){events.add("enter-review");return work.apply(tx);}
        public PlanOutcome reserve(ReserveCommand c,PlanWork work){events.add("enter-reserve");return work.apply(tx);}
        public StageOutcome transact(StageCommand c,Work work){throw new AssertionError("unexpected stage transaction");}
        public SyntheticRootProvisionBinding.RootOutcome provisionRoot(SyntheticRootProvisionBinding.RootCommand c,RootWork work){throw new AssertionError("unexpected root provision");}
    }
    static final class Facts implements SyntheticMockPaymentPlanService.LocalPlanFacts {
        final Port port;Gate gate=Gate.CLEAR,second=Gate.CLEAR;int checks,resolves;boolean detached;
        Facts(Port port){this.port=port;}
        public Gate current(SyntheticMockPaymentPlanService.PlanServerContext c,CommandIdentity i,PlanOperation op,OwnedMockPaymentPlanPort.OwnedPlanTx tx){
            assertSame(port.tx,tx);assertEquals(ACTOR,c.actorId());port.events.add("current-"+op);return ++checks==1?gate:second;
        }
        public ResolvedEvidence resolveEvidence(SyntheticMockPaymentPlanService.PlanServerContext c,CommandIdentity i,ReviewBindings b,OwnedMockPaymentPlanPort.OwnedPlanTx tx){
            assertSame(port.tx,tx);port.events.add("evidence");resolves++;
            assertTrue(b==port.tx.reviewBindings || b==port.tx.reservationBindings.review());
            return new ResolvedEvidence(detached?new ReviewBindings(b.workflow(),b.evaluation()):b,port.tx.data.evidence());
        }
    }
    static final class Harness {
        final Port port=new Port();final Facts facts=new Facts(port);
        final SyntheticMockPaymentPlanService service=new SyntheticMockPaymentPlanService(port,facts);
        final SyntheticMockPaymentPlanService.PlanServerContext context=()->ACTOR;
        ReviewCommand review(){return port.tx.data.review(port.tx.reviewBindings,ReviewDecision.APPROVE);}
        ReserveCommand reserve(){return port.tx.data.reserve(port.tx.data.domain(),NOW);}
    }
    static void stopped(Status status,Runnable work){assertEquals(status,assertThrows(Stop.class,work::run).status);}

    @Test void reviewUsesOneOwnedContextAndCurrentChecksBeforeLookupAndRecord() {
        Harness h=new Harness();var c=h.review();var outcome=h.service.review(h.context,c);
        assertEquals(List.of("enter-review","current-REVIEW","lookup-review","admit-review","read-review","evidence","current-REVIEW","record-review"),h.port.events);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,outcome.status());assertSame(h.port.tx.recordedReview.approval(),outcome.receipt().approval());
        assertEquals(5,outcome.receipt().approval().extraRiskLimit());assertFalse(outcome.actualAuthority());assertFalse(outcome.durable());
    }
    @Test void reserveUsesDifferentPurposeAndExactDomainWithoutConsumingGrant() {
        Harness h=new Harness();var c=h.reserve();var outcome=h.service.reserve(h.context,c);
        assertEquals(List.of("enter-reserve","current-RESERVE","lookup-reserve","admit-reserve","read-reserve","evidence","current-RESERVE","record-reserve"),h.port.events);
        assertEquals(c.domain(),outcome.receipt().domain());assertEquals(3,outcome.receipt().riskPoints());
        assertEquals(ApprovalPlanState.RESERVED,outcome.receipt().approval().state());
        assertEquals(GrantState.ISSUED,h.port.tx.reservationBindings.paymentGrant().state());assertNull(h.port.tx.recordedReview);
    }
    @Test void currentRefusalAndUnknownNeverDiscloseExistingHistory() {
        for(Gate gate:List.of(Gate.REFUSED,Gate.UNKNOWN)){
            Harness h=new Harness();var c=h.review();var a=h.port.tx.data.approved().approval();
            h.port.tx.priorReview=new PlanReceipt(1,PlanOperation.REVIEW,c.identity(),a,null,0);h.facts.gate=gate;
            stopped(gate==Gate.REFUSED?Status.REFUSED_BEFORE_ADMISSION:Status.UNCONFIRMED_BEFORE_ADMISSION,()->h.service.review(h.context,c));
            assertEquals(List.of("enter-review","current-REVIEW"),h.port.events);assertEquals(0,h.facts.resolves);
        }
    }
    @Test void actorMismatchRefusesBeforeResolverAndHistory() {
        Harness h=new Harness();stopped(Status.REFUSED_BEFORE_ADMISSION,()->h.service.reserve(()->"synthetic-other",h.reserve()));
        assertEquals(List.of("enter-reserve"),h.port.events);assertEquals(0,h.facts.checks);
    }
    @Test void exactReviewAndReservationReplayDoNotAdmitOrResolveFreshEvidence() {
        Harness r=new Harness();var c=r.review();var a=r.port.tx.data.approved().approval();
        r.port.tx.priorReview=new PlanReceipt(1,PlanOperation.REVIEW,c.identity(),a,null,0);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,r.service.review(r.context,c).status());
        assertEquals(List.of("enter-review","current-REVIEW","lookup-review"),r.port.events);assertEquals(0,r.facts.resolves);
        Harness s=new Harness();var d=s.reserve();var p=prepareReservation(d,s.port.tx.reservationBindings,s.port.tx.data.evidence());
        s.port.tx.priorReserve=new PlanReceipt(1,PlanOperation.RESERVE,d.identity(),p.approval(),d.domain(),3);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,s.service.reserve(s.context,d).status());
        assertEquals(List.of("enter-reserve","current-RESERVE","lookup-reserve"),s.port.events);assertEquals(0,s.facts.resolves);
    }
    @Test void historyPurposeOrDomainMismatchIsConflictWithoutFreshMutation() {
        Harness r=new Harness();var c=r.review();
        r.port.tx.priorReview=new PlanReceipt(1,PlanOperation.RESERVE,c.identity(),r.port.tx.data.approved().approval(),r.port.tx.data.domain(),3);
        stopped(Status.IDENTITY_CONFLICT,()->r.service.review(r.context,c));assertEquals(0,r.facts.resolves);assertNull(r.port.tx.recordedReview);
        Harness s=new Harness();var d=s.reserve();
        s.port.tx.priorReserve=new PlanReceipt(1,PlanOperation.RESERVE,d.identity(),s.port.tx.data.approved().approval(),s.port.tx.data.domain(id(999),1000,id(3),"synthetic-policy"),3);
        stopped(Status.IDENTITY_CONFLICT,()->s.service.reserve(s.context,d));assertEquals(0,s.facts.resolves);assertNull(s.port.tx.recordedReserve);
    }
    @Test void equalButDetachedEvidenceTicketCannotReachPrepareOrRecord() {
        Harness h=new Harness();h.facts.detached=true;stopped(Status.UNCONFIRMED_BEFORE_ADMISSION,()->h.service.review(h.context,h.review()));
        assertEquals(1,h.facts.resolves);assertEquals(1,h.facts.checks);assertNull(h.port.tx.recordedReview);
        assertFalse(h.port.events.contains("record-review"));
    }
    @Test void secondCurrentFenceRefusesBothPurposesBeforeRecord() {
        for(boolean reserve:List.of(false,true)){
            Harness h=new Harness();h.facts.second=Gate.REFUSED;
            stopped(Status.REFUSED_BEFORE_ADMISSION,()->{if(reserve)h.service.reserve(h.context,h.reserve());else h.service.review(h.context,h.review());});
            assertEquals(2,h.facts.checks);assertEquals(1,h.facts.resolves);assertNull(h.port.tx.recordedReview);assertNull(h.port.tx.recordedReserve);
        }
    }
    @Test void malformedExpectedReviewHashNeverReachesRecord() {
        Harness h=new Harness();var c=h.review();var wrong=new ReviewCommand(c.identity(),c.approvalId(),c.decision(),J,c.now(),c.expiresAt(),c.comment());
        stopped(Status.UNCONFIRMED_BEFORE_ADMISSION,()->h.service.review(h.context,wrong));
        assertEquals(1,h.facts.resolves);assertEquals(1,h.facts.checks);assertNull(h.port.tx.recordedReview);
    }
    @Test void absentReconciliationRemainsUnknownAndNeverAdmitsOrResolves() {
        Harness h=new Harness();var r=h.service.reconcileReview(h.context,h.review());
        assertEquals(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH,r.status());assertNull(r.receipt());assertEquals(PlanEffect.UNKNOWN,r.effectKnowledge());
        assertEquals(List.of("enter-review","current-REVIEW","lookup-review"),h.port.events);assertEquals(0,h.facts.resolves);
        Harness s=new Harness();var p=s.service.reconcileReservation(s.context,s.reserve());
        assertEquals(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH,p.status());assertEquals(PlanEffect.UNKNOWN,p.effectKnowledge());
        assertEquals(List.of("enter-reserve","current-RESERVE","lookup-reserve"),s.port.events);
    }
}
