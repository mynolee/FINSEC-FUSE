package com.finsec.fuse.reimplementation.grant;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBindingTest.*;

/** Protocol tests; no concrete journal atomicity or stored-marker proof. */
class SyntheticKycPreparationServiceTest {
    static final class Protocol implements OwnedKycPreparationPort, OwnedKycPreparationPort.OwnedPreparationTx {
        final List<String> events=new ArrayList<>();
        PreparationReceipt prior;
        FreshBindings bindings;
        int preparations,refusals;
        Protocol(PreparationCommand c) {
            bindings=binding(c,grant(c,GrantState.ISSUED,com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction.EVALUATE_KYC),new SourceCoordinate(c.source().documentId(),c.source().documentVersion()),c.terms());
        }
        public PreparationOutcome prepareKyc(PreparationCommand c,PreparationWork work) {
            try { return work.apply(this); }
            catch(OwnedGrantTransactionPort.Stop stop) { return new PreparationOutcome(stop.status,null,PreparationEffect.NO_NEW_PREPARATION_ATTEMPT_THIS_INVOCATION); }
        }
        public PreparationReceipt lookupPreparation(PreparationCommand c) { events.add("lookup"); return prior; }
        public void admitFreshPreparation(PreparationCommand c) { events.add("admit"); }
        public FreshBindings readPreparationBindings(PreparationCommand c) { events.add("bindings"); return bindings; }
        public PreparationReceipt recordPreparation(PreparationCommand c,ResolvedPreparation r) {
            events.add("prepare"); preparations++;
            assertSame(bindings,r.bindings());
            assertEquals(prepareRequested(c).canonicalInput(),r.input().canonicalInput());
            return receipt(c,Decision.PREPARED,Refusal.NONE,bindings.counters().kycCharged()?0:c.terms().kycPoints());
        }
        public PreparationReceipt recordRefusal(PreparationCommand c,FreshBindings b,Refusal reason) {
            events.add("refuse"); refusals++; assertSame(bindings,b);
            return receipt(c,Decision.ON_HOLD,reason,0);
        }
        public StageOutcome transact(StageCommand c,Work w) { throw new AssertionError("Unexpected stage transaction"); }
        public SyntheticRootProvisionBinding.RootOutcome provisionRoot(SyntheticRootProvisionBinding.RootCommand c,RootWork w) { throw new AssertionError("Unexpected root provision"); }
        public SyntheticMockPaymentPlanBinding.PlanOutcome review(SyntheticMockPaymentPlanBinding.ReviewCommand c,PlanWork w) { throw new AssertionError("Unexpected review"); }
        public SyntheticMockPaymentPlanBinding.PlanOutcome reserve(SyntheticMockPaymentPlanBinding.ReserveCommand c,PlanWork w) { throw new AssertionError("Unexpected reserve"); }
    }
    static PreparationReceipt receipt(PreparationCommand c,Decision decision,Refusal refusal,int charge) {
        return new PreparationReceipt(c.identity(),descriptor(c),prepareRequested(c).inputSnapshotHash(),decision,refusal,charge,1,charge);
    }
    static SyntheticKycPreparationService service(Protocol p,Gate... gates) {
        int[] index={0};
        return new SyntheticKycPreparationService(p,(ctx,c,tx)->{
            assertSame(p,tx); assertEquals(c.identity().actorId(),ctx.actorId());
            p.events.add("current"); assertTrue(index[0]<gates.length,"Unexpected extra current check");
            return gates[index[0]++];
        });
    }
    static ServerContext context(PreparationCommand c) { return ()->c.identity().actorId(); }
    @Test void freshPreparationChecksCurrentTwiceAndUsesExactOwnedBindings() {
        var c=command(); var p=new Protocol(c); var out=service(p,Gate.CLEAR,Gate.CLEAR).prepare(context(c),c);
        assertEquals(List.of("current","lookup","admit","current","bindings","prepare"),p.events);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status()); assertEquals(1,p.preparations); assertEquals(0,p.refusals);
        assertEquals(2,out.receipt().chargedPoints()); assertFalse(out.actualAuthority()); assertFalse(out.durable()); assertFalse(out.executionAuthorityGranted());
    }
    @Test void currentDenialPrecedesCachedReceiptAndActorMismatchPrecedesResolver() {
        var c=command(); var p=new Protocol(c); p.prior=receipt(c,Decision.PREPARED,Refusal.NONE,2);
        assertEquals(Status.REFUSED_BEFORE_ADMISSION,service(p,Gate.REFUSED).prepare(context(c),c).status());
        assertEquals(List.of("current"),p.events);
        p.events.clear(); assertEquals(Status.REFUSED_BEFORE_ADMISSION,service(p).prepare(()->"synthetic-other",c).status());
        assertTrue(p.events.isEmpty()); assertEquals(0,p.preparations);
    }
    @Test void secondCurrentFenceStopsBeforeBindingsOrRecord() {
        var c=command(); var p=new Protocol(c);
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,service(p,Gate.CLEAR,Gate.UNKNOWN).prepare(context(c),c).status());
        assertEquals(List.of("current","lookup","admit","current"),p.events); assertEquals(0,p.preparations+p.refusals);
    }
    @Test void exactReplayAndReconcileHaveNoFreshAdmissionOrCharge() {
        var c=command(); var p=new Protocol(c); p.prior=receipt(c,Decision.PREPARED,Refusal.NONE,2);
        var out=service(p,Gate.CLEAR).prepare(context(c),c);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,out.status()); assertSame(p.prior,out.receipt()); assertEquals(List.of("current","lookup"),p.events);
        p.events.clear(); assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,service(p,Gate.CLEAR).reconcile(context(c),c).status());
        assertEquals(List.of("current","lookup"),p.events); assertEquals(0,p.preparations+p.refusals);
    }
    @Test void descriptorMismatchCannotReusePriorReceipt() {
        var c=command(); var p=new Protocol(c);
        var other=new PreparationCommand(c.identity(),c.source(),c.facts(),c.terms(),NOW.plusNanos(1));
        p.prior=receipt(other,Decision.PREPARED,Refusal.NONE,2);
        var out=service(p,Gate.CLEAR).prepare(context(c),c);
        assertEquals(Status.IDENTITY_CONFLICT,out.status()); assertNull(out.receipt()); assertEquals(List.of("current","lookup"),p.events);
    }
    @Test void absentReconciliationIsUnknownAndNeverAdmitsOrCharges() {
        var c=command(); var p=new Protocol(c); var out=service(p,Gate.CLEAR).reconcile(context(c),c);
        assertEquals(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH,out.status()); assertEquals(PreparationEffect.UNKNOWN,out.effect()); assertNull(out.receipt());
        assertEquals(List.of("current","lookup"),p.events); assertEquals(0,p.preparations+p.refusals);
    }
    @Test void maxRunsAndCapacityRouteToZeroChargeRefusalAndExistingChargeIsNotRepeated() {
        var c=command();
        for(int mode=0;mode<3;mode++) {
            var p=new Protocol(c); var b=p.bindings;
            var counters=new VirtualGrantEvaluationAccounting.Counters(mode==1?20:0,0,mode==0?2:mode==1?0:1,mode!=1,false);
            p.bindings=new FreshBindings(b.grant(),b.workflowState(),counters,20,b.currentSource(),b.riskTerms(),false);
            var out=service(p,Gate.CLEAR,Gate.CLEAR).prepare(context(c),c);
            assertEquals(0,out.receipt().chargedPoints());
            if(mode<2) { assertEquals(Decision.ON_HOLD,out.receipt().decision()); assertEquals(mode==0?Refusal.KYC_PRECONDITION_FAILED:Refusal.RISK_LIMIT_EXCEEDED,out.receipt().refusal()); assertEquals(1,p.refusals); assertEquals(0,p.preparations); }
            else { assertEquals(Decision.PREPARED,out.receipt().decision()); assertEquals(1,p.preparations); assertEquals(0,p.refusals); }
        }
    }
    @Test void unsafeSourceFailsBeforeHistoryAndWrongActualCoordinateBeforeRecord() {
        var c=command(); var p=new Protocol(c); var unsafe=command(c.facts(),false);
        assertThrows(IllegalArgumentException.class,()->service(p,Gate.CLEAR).prepare(context(c),unsafe)); assertEquals(List.of("current"),p.events);
        p.events.clear(); var b=p.bindings;
        p.bindings=new FreshBindings(b.grant(),b.workflowState(),b.counters(),20,new SourceCoordinate(c.source().documentId(),2),b.riskTerms(),false);
        assertThrows(IllegalArgumentException.class,()->service(p,Gate.CLEAR,Gate.CLEAR).prepare(context(c),c));
        assertEquals(List.of("current","lookup","admit","current","bindings"),p.events); assertEquals(0,p.preparations+p.refusals);
    }
}
