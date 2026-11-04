package com.finsec.fuse.reimplementation.auth;

import org.junit.jupiter.api.Test;
import java.util.Set;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantKeyLifecycleAssessment.*;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.Fact.*;

/** Supplied-data regressions only: no key, clock, store or authoritative transition. */
class SyntheticGrantKeyLifecycleAssessmentTest {
    private static final KeyBinding KEY = new KeyBinding("synthetic-kid", "synthetic-issuer", "opaque-alg", "v-test");
    private static final SyntheticGrantTemporalAssessment.Fact C = CLEAR;
    private static KeySnapshot key(Lifecycle state) { return new KeySnapshot(KEY, state); }
    private static SyntheticGrantTemporalAssessment.TemporalFacts time(long now) {
        return new SyntheticGrantTemporalAssessment.TemporalFacts(now, 10, 20,
                SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null);
    }
    private static SyntheticGrantTemporalAssessment.RevocationFacts rev(SyntheticGrantTemporalAssessment.Fact key) {
        return new SyntheticGrantTemporalAssessment.RevocationFacts(C,C,key,C,C,C,C,C,C);
    }
    private static CurrentUseFacts clear() { return new CurrentUseFacts(C,C,C,C,C,C); }
    private static SyntheticGrantReplayAssessment.CurrentReadFacts reads() {
        return new SyntheticGrantReplayAssessment.CurrentReadFacts(C,C,C,C,C,C,C);
    }
    private static SyntheticGrantReplayAssessment.CommandIdentity identity(String actor) {
        return new SyntheticGrantReplayAssessment.CommandIdentity(actor,new UUID(0,1),"synthetic-operation",
                "synthetic-version","synthetic-digest",new UUID(0,2),new UUID(0,3),new UUID(0,4),new UUID(0,5),1,"synthetic-customer");
    }
    private static Assessment issue(KeySnapshot state, MaterialFact material) {
        return assessNewIssuance(KEY,state,C,material,time(15),rev(C),clear());
    }
    private static Assessment outstanding(KeySnapshot state, Ordering order, MaterialFact material, long now) {
        return assessOutstanding(KEY,state,SyntheticGrantReplayAssessment.GrantLifecycle.ISSUED,order,material,time(now),rev(C),clear());
    }
    private static Assessment history(KeySnapshot state, long now) {
        var id=identity("synthetic-actor");
        return assessHistoricalRead(KEY,state,id,new SyntheticGrantReplayAssessment.SuppliedReceipt(
                SyntheticGrantReplayAssessment.ReceiptState.COMMITTED,id,SyntheticGrantReplayAssessment.GrantLifecycle.CONSUMED),time(now),rev(C),reads());
    }
    private static void noProof(Assessment a) {
        assertFalse(a.authorizationEstablished()); assertFalse(a.keyBindingEstablished());
        assertFalse(a.keyTransitionEstablished()); assertFalse(a.materialRetentionEstablished());
        assertFalse(a.materialDestructionEstablished()); assertFalse(a.executionAuthorityGranted());
    }
    private static void noProof(TransitionAssessment a) {
        assertFalse(a.authorizationEstablished()); assertFalse(a.keyBindingEstablished());
        assertFalse(a.keyTransitionEstablished()); assertFalse(a.materialRetentionEstablished());
        assertFalse(a.materialDestructionEstablished()); assertFalse(a.executionAuthorityGranted());
    }
    private static void invalid(org.junit.jupiter.api.function.Executable call) {
        var e=assertThrows(IllegalArgumentException.class,call);
        assertEquals("INVALID_SYNTHETIC_GRANT_KEY_LIFECYCLE",e.getMessage()); assertNull(e.getCause());
    }

    @Test void lifecycleMatrixPreservesDistinctPurposesAndNeverEstablishesAuthority() {
        for (var state: Lifecycle.values()) {
            var issuance=issue(key(state),MaterialFact.AVAILABLE);
            var work=outstanding(key(state),Ordering.BEFORE_RETIREMENT,MaterialFact.AVAILABLE,15);
            var read=history(key(state),15);
            assertEquals(state==Lifecycle.ACTIVE,issuance.suppliedConditionsSatisfied());
            assertEquals(state==Lifecycle.ACTIVE||state==Lifecycle.RETIRED,work.suppliedConditionsSatisfied());
            assertEquals(state==Lifecycle.ACTIVE||state==Lifecycle.RETIRED,read.suppliedConditionsSatisfied());
            assertEquals(UseKind.NEW_ISSUANCE,issuance.purpose()); assertEquals(UseKind.OUTSTANDING_NEW_WORK,work.purpose());
            assertEquals(UseKind.EXACT_COMMITTED_RECEIPT_READ,read.purpose());
            noProof(issuance); noProof(work); noProof(read);
        }
        assertEquals(Set.of(Blocker.KEY_RETIRED_FOR_ISSUANCE),issue(key(Lifecycle.RETIRED),MaterialFact.AVAILABLE).blockers());
        assertEquals(Set.of(Blocker.KEY_REVOKED),issue(key(Lifecycle.REVOKED),MaterialFact.AVAILABLE).blockers());
    }
    @Test void retiredOutstandingRequiresStrictlyBeforeWithoutInventingAnActiveCutoff() {
        for(var order:Ordering.values()) {
            var a=outstanding(key(Lifecycle.RETIRED),order,MaterialFact.AVAILABLE,15);
            assertEquals(order==Ordering.BEFORE_RETIREMENT,a.suppliedConditionsSatisfied());
            if(order==Ordering.UNKNOWN) assertEquals(Set.of(Blocker.RETIREMENT_ORDER_UNKNOWN),a.blockers());
            if(order==Ordering.AT_RETIREMENT||order==Ordering.AFTER_RETIREMENT)
                assertEquals(Set.of(Blocker.RETIREMENT_ORDER_NOT_BEFORE),a.blockers());
            assertTrue(outstanding(key(Lifecycle.ACTIVE),order,MaterialFact.AVAILABLE,15).suppliedConditionsSatisfied());
        }
    }
    @Test void requiredMaterialAndCommitFenceAreSeparateFromRevocation() {
        for(var m:MaterialFact.values()) {
            assertEquals(m==MaterialFact.AVAILABLE,issue(key(Lifecycle.ACTIVE),m).suppliedConditionsSatisfied());
            var a=outstanding(key(Lifecycle.RETIRED),Ordering.BEFORE_RETIREMENT,m,15);
            assertEquals(m==MaterialFact.AVAILABLE,a.suppliedConditionsSatisfied());
            if(m!=MaterialFact.AVAILABLE) assertFalse(a.blockers().contains(Blocker.KEY_REVOKED));
        }
        for(var f: new SyntheticGrantTemporalAssessment.Fact[]{ACTIVE,UNKNOWN}) {
            var a=assessNewIssuance(KEY,key(Lifecycle.ACTIVE),f,MaterialFact.AVAILABLE,time(15),rev(C),clear());
            assertEquals(Set.of(f==ACTIVE?Blocker.ISSUANCE_BINDING_CHANGED_ACTIVE:Blocker.ISSUANCE_BINDING_CHANGED_UNKNOWN),a.blockers());
            noProof(a);
        }
    }
    @Test void outstandingDoesNotReuseConsumedRevokedExpiredOrUnknownGrants() {
        for(var g:SyntheticGrantReplayAssessment.GrantLifecycle.values()) {
            var a=assessOutstanding(KEY,key(Lifecycle.RETIRED),g,Ordering.BEFORE_RETIREMENT,MaterialFact.AVAILABLE,time(15),rev(C),clear());
            assertEquals(g==SyntheticGrantReplayAssessment.GrantLifecycle.ISSUED,a.suppliedConditionsSatisfied());
            if(g!=SyntheticGrantReplayAssessment.GrantLifecycle.ISSUED)
                assertEquals(Set.of(g==SyntheticGrantReplayAssessment.GrantLifecycle.UNKNOWN?Blocker.GRANT_LIFECYCLE_UNKNOWN:Blocker.GRANT_NOT_ISSUED),a.blockers());
        }
    }
    @Test void eachOpaqueBindingComponentMustMatchWithoutNormalization() {
        var foreign=new KeyBinding[]{new KeyBinding("other",KEY.issuer(),KEY.algorithm(),KEY.keyVersion()),
                new KeyBinding(KEY.kid(),"other",KEY.algorithm(),KEY.keyVersion()),
                new KeyBinding(KEY.kid(),KEY.issuer(),"other",KEY.keyVersion()),
                new KeyBinding(KEY.kid(),KEY.issuer(),KEY.algorithm(),"other")};
        for(var k:foreign) {
            assertTrue(issue(new KeySnapshot(k,Lifecycle.ACTIVE),MaterialFact.AVAILABLE).blockers().contains(Blocker.KEY_BINDING_MISMATCH));
            assertTrue(history(new KeySnapshot(k,Lifecycle.RETIRED),20).blockers().contains(Blocker.KEY_BINDING_MISMATCH));
            assertFalse(assessTransition(key(Lifecycle.ACTIVE),new KeySnapshot(k,Lifecycle.RETIRED)).suppliedTransitionConsistent());
        }
        assertEquals(" x ",new KeyBinding(" x ","i","a","v").kid());
        var unknown=issue(new KeySnapshot(null,Lifecycle.UNKNOWN),MaterialFact.AVAILABLE);
        assertEquals(Set.of(Blocker.KEY_BINDING_UNCONFIRMED,Blocker.KEY_STATE_UNKNOWN),unknown.blockers());
    }
    @Test void ownExpiryExceptionAppliesOnlyToExactCommittedHistoryAtEqualityAndAfter() {
        for(long now:new long[]{20,21,Long.MAX_VALUE}) {
            var read=history(key(Lifecycle.RETIRED),now);
            assertTrue(read.suppliedConditionsSatisfied()); assertTrue(read.ownExpiryExceptionApplied()); noProof(read);
            var work=outstanding(key(Lifecycle.RETIRED),Ordering.BEFORE_RETIREMENT,MaterialFact.AVAILABLE,now);
            assertFalse(work.suppliedConditionsSatisfied()); assertFalse(work.ownExpiryExceptionApplied());
            assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.EXPIRED),work.temporalBlockers());
        }
        assertFalse(history(key(Lifecycle.RETIRED),15).ownExpiryExceptionApplied());
        assertFalse(history(key(Lifecycle.RETIRED),9).suppliedConditionsSatisfied());
    }
    @Test void keyRevocationActiveAndUnknownSurviveAllThreePurposes() {
        for(var f:new SyntheticGrantTemporalAssessment.Fact[]{ACTIVE,UNKNOWN}) {
            var id=identity("synthetic-actor");
            var receipt=new SyntheticGrantReplayAssessment.SuppliedReceipt(SyntheticGrantReplayAssessment.ReceiptState.COMMITTED,id,SyntheticGrantReplayAssessment.GrantLifecycle.CONSUMED);
            var all=new Assessment[]{assessNewIssuance(KEY,key(Lifecycle.ACTIVE),C,MaterialFact.AVAILABLE,time(15),rev(f),clear()),
                    assessOutstanding(KEY,key(Lifecycle.RETIRED),SyntheticGrantReplayAssessment.GrantLifecycle.ISSUED,Ordering.BEFORE_RETIREMENT,MaterialFact.AVAILABLE,time(15),rev(f),clear()),
                    assessHistoricalRead(KEY,key(Lifecycle.RETIRED),id,receipt,time(20),rev(f),reads())};
            for(var a:all) { assertFalse(a.suppliedConditionsSatisfied()); assertTrue(a.temporalBlockers().contains(
                    f==ACTIVE?SyntheticGrantTemporalAssessment.Blocker.KEY_REVOKED_ACTIVE:SyntheticGrantTemporalAssessment.Blocker.KEY_REVOKED_UNKNOWN)); noProof(a); }
        }
    }
    @Test void everyCurrentUseGateActiveOrUnknownRemainsBlocking() {
        var active=new Blocker[]{Blocker.CREDENTIAL_INVALID_ACTIVE,Blocker.ACTOR_MISMATCH_ACTIVE,Blocker.OWNER_DENIED_ACTIVE,Blocker.OPERATION_DENIED_ACTIVE,Blocker.ANCESTOR_EXPIRY_BLOCKED_ACTIVE,Blocker.OTHER_APPLICABLE_GATE_BLOCKED_ACTIVE};
        var unknown=new Blocker[]{Blocker.CREDENTIAL_INVALID_UNKNOWN,Blocker.ACTOR_MISMATCH_UNKNOWN,Blocker.OWNER_DENIED_UNKNOWN,Blocker.OPERATION_DENIED_UNKNOWN,Blocker.ANCESTOR_EXPIRY_BLOCKED_UNKNOWN,Blocker.OTHER_APPLICABLE_GATE_BLOCKED_UNKNOWN};
        for(int i=0;i<6;i++) for(var f:new SyntheticGrantTemporalAssessment.Fact[]{ACTIVE,UNKNOWN}) {
            var facts=new SyntheticGrantTemporalAssessment.Fact[]{C,C,C,C,C,C}; facts[i]=f;
            var current=new CurrentUseFacts(facts[0],facts[1],facts[2],facts[3],facts[4],facts[5]);
            var a=assessNewIssuance(KEY,key(Lifecycle.ACTIVE),C,MaterialFact.AVAILABLE,time(15),rev(C),current);
            var b=assessOutstanding(KEY,key(Lifecycle.RETIRED),SyntheticGrantReplayAssessment.GrantLifecycle.ISSUED,Ordering.BEFORE_RETIREMENT,MaterialFact.AVAILABLE,time(15),rev(C),current);
            assertEquals(Set.of(f==ACTIVE?active[i]:unknown[i]),a.blockers()); assertEquals(a.blockers(),b.blockers());
            assertFalse(a.suppliedConditionsSatisfied()); assertFalse(b.suppliedConditionsSatisfied());
        }
    }
    @Test void historyKeepsCurrentDisclosureAndAncestorExpiryWithoutMaterialArgument() {
        var id=identity("synthetic-actor");
        var receipt=new SyntheticGrantReplayAssessment.SuppliedReceipt(SyntheticGrantReplayAssessment.ReceiptState.COMMITTED,id,SyntheticGrantReplayAssessment.GrantLifecycle.CONSUMED);
        for(var f:new SyntheticGrantTemporalAssessment.Fact[]{ACTIVE,UNKNOWN}) {
            var current=new SyntheticGrantReplayAssessment.CurrentReadFacts(f,C,C,C,f,f,f);
            var a=assessHistoricalRead(KEY,key(Lifecycle.RETIRED),id,receipt,time(20),rev(C),current);
            assertTrue(a.ownExpiryExceptionApplied()); assertFalse(a.suppliedConditionsSatisfied());
            assertTrue(a.historicalReadBlockers().contains(f==ACTIVE?SyntheticGrantReplayAssessment.Blocker.DISCLOSURE_DENIED_ACTIVE:SyntheticGrantReplayAssessment.Blocker.DISCLOSURE_DENIED_UNKNOWN));
            assertTrue(a.historicalReadBlockers().contains(f==ACTIVE?SyntheticGrantReplayAssessment.Blocker.CREDENTIAL_INVALID_ACTIVE:SyntheticGrantReplayAssessment.Blocker.CREDENTIAL_INVALID_UNKNOWN));
            var childTime=new SyntheticGrantTemporalAssessment.TemporalFacts(20,10,20,SyntheticGrantTemporalAssessment.ChainPosition.CHILD,19L);
            var child=assessHistoricalRead(KEY,key(Lifecycle.RETIRED),id,receipt,childTime,rev(C),reads());
            assertFalse(child.suppliedConditionsSatisfied());
            assertTrue(child.temporalBlockers().contains(SyntheticGrantTemporalAssessment.Blocker.PARENT_EXPIRED));
            assertTrue(child.temporalBlockers().contains(SyntheticGrantTemporalAssessment.Blocker.PARENT_EXPIRY_EXCEEDED));
        }
    }
    @Test void incompleteOrForeignHistoryNeverGetsFabricatedReceiptEligibility() {
        var id=identity("synthetic-actor");
        var foreign=new SyntheticGrantReplayAssessment.SuppliedReceipt(SyntheticGrantReplayAssessment.ReceiptState.COMMITTED,identity("other"),SyntheticGrantReplayAssessment.GrantLifecycle.CONSUMED);
        var absent=new SyntheticGrantReplayAssessment.SuppliedReceipt(SyntheticGrantReplayAssessment.ReceiptState.ABSENT,null,null);
        for(var receipt:new SyntheticGrantReplayAssessment.SuppliedReceipt[]{foreign,absent}) {
            var a=assessHistoricalRead(KEY,key(Lifecycle.RETIRED),id,receipt,time(20),rev(C),reads());
            assertFalse(a.suppliedConditionsSatisfied()); assertTrue(a.blockers().contains(Blocker.HISTORICAL_RECEIPT_UNCONFIRMED)); noProof(a);
        }
    }
    @Test void onlyThreeIrreversibleSameBindingEdgesAreConsistent() {
        for(var from:Lifecycle.values()) for(var to:Lifecycle.values()) {
            var a=assessTransition(key(from),key(to));
            boolean allowed=(from==Lifecycle.ACTIVE&&(to==Lifecycle.RETIRED||to==Lifecycle.REVOKED))||(from==Lifecycle.RETIRED&&to==Lifecycle.REVOKED);
            assertEquals(allowed,a.suppliedTransitionConsistent()); noProof(a);
            if(!allowed) assertTrue(a.blockers().contains(Blocker.TRANSITION_NOT_ALLOWED));
        }
        assertFalse(assessTransition(new KeySnapshot(null,Lifecycle.UNKNOWN),key(Lifecycle.RETIRED)).suppliedTransitionConsistent());
    }
    @Test void diagnosticSetsAreImmutableAndRenderingDoesNotExposeBindings() {
        var a=issue(key(Lifecycle.RETIRED),MaterialFact.UNKNOWN);
        assertThrows(UnsupportedOperationException.class,()->a.blockers().clear());
        assertThrows(UnsupportedOperationException.class,()->a.temporalBlockers().add(SyntheticGrantTemporalAssessment.Blocker.EXPIRED));
        assertThrows(UnsupportedOperationException.class,()->a.historicalReadBlockers().add(SyntheticGrantReplayAssessment.Blocker.IDENTITY_CONFLICT));
        var edge=assessTransition(key(Lifecycle.RETIRED),key(Lifecycle.ACTIVE));
        assertThrows(UnsupportedOperationException.class,()->edge.blockers().clear());
        assertFalse(a.toString().contains(KEY.kid())); assertFalse(edge.toString().contains(KEY.issuer()));
        assertFalse(KEY.toString().contains(KEY.algorithm())); assertFalse(key(Lifecycle.ACTIVE).toString().contains(KEY.keyVersion()));
        assertEquals(Set.of(Blocker.KEY_RETIRED_FOR_ISSUANCE,Blocker.MATERIAL_UNKNOWN),a.blockers());
    }
    @Test void malformedInputsHaveOneFixedCauseFreeError() {
        invalid(()->new KeyBinding(null,"i","a","v")); invalid(()->new KeyBinding("k","","a","v"));
        invalid(()->new KeyBinding("k","i",null,"v")); invalid(()->new KeyBinding("k","i","a",""));
        invalid(()->new KeySnapshot(null,Lifecycle.ACTIVE)); invalid(()->new KeySnapshot(KEY,null));
        invalid(()->new CurrentUseFacts(C,C,C,C,C,null));
        invalid(()->assessNewIssuance(KEY,key(Lifecycle.ACTIVE),null,MaterialFact.AVAILABLE,time(15),rev(C),clear()));
        invalid(()->assessNewIssuance(KEY,key(Lifecycle.ACTIVE),C,MaterialFact.AVAILABLE,null,rev(C),clear()));
        invalid(()->assessOutstanding(KEY,key(Lifecycle.RETIRED),SyntheticGrantReplayAssessment.GrantLifecycle.ISSUED,null,MaterialFact.AVAILABLE,time(15),rev(C),clear()));
        invalid(()->assessHistoricalRead(KEY,key(Lifecycle.RETIRED),identity("actor"),null,time(15),rev(C),reads()));
        invalid(()->assessTransition(null,key(Lifecycle.RETIRED)));
    }
}
