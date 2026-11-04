package com.finsec.fuse.reimplementation.persistence;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.persistence.LeaseStateModel.*;

/** Synthetic public-API regressions only; NOT_RUN. No service/journal/provider claim. */
final class LeaseStateModelTest {
    private State active() { return create("synthetic-a", 2, 4, 100); }
    private void unchanged(Code expected, State original, Transition result) {
        assertEquals(expected, result.code());
        assertSame(original, result.state());
    }

    @Test void equalityExpiryAndPostExpiryCannotRenewOrComplete() {
        State s = active();
        unchanged(Code.EXPIRED, s, renew(s,"synthetic-a",2,4,100,101));
        unchanged(Code.EXPIRED, s, renew(s,"synthetic-a",2,4,101,102));
        unchanged(Code.EXPIRED, s, complete(s,"synthetic-a",2,4,100));
        Transition before = complete(s,"synthetic-a",2,4,99);
        assertEquals(Code.APPLIED, before.code());
        assertEquals(Status.COMPLETED, before.state().status());
        assertEquals(5, before.state().version());
    }

    @Test void renewalStrictlyExtendsOnlyVersion() {
        State s = active();
        Transition t = renew(s,"synthetic-a",2,4,99,110);
        assertEquals(Code.APPLIED,t.code());
        assertEquals(new State("synthetic-a",2,5,110,Status.ACTIVE),t.state());
        assertEquals(new State("synthetic-a",2,4,100,Status.ACTIVE),s);
        assertThrows(IllegalArgumentException.class,()->renew(s,"synthetic-a",2,4,99,100));
        assertThrows(IllegalArgumentException.class,()->renew(s,"synthetic-a",2,4,99,99));
    }

    @Test void eachExpectedCasComponentRejectsStale() {
        State s = active();
        unchanged(Code.STALE,s,renew(s,"synthetic-b",2,4,99,110));
        unchanged(Code.STALE,s,renew(s,"synthetic-a",3,4,99,110));
        unchanged(Code.STALE,s,renew(s,"synthetic-a",2,5,99,110));
        unchanged(Code.STALE,s,complete(s,"synthetic-b",2,4,99));
        unchanged(Code.STALE,s,recover(s,"synthetic-a",2,5,100,"synthetic-b",110,true));
    }

    @Test void explicitRecoveryRequiresExpiryAndAdvancesFenceAndVersion() {
        State s=active();
        unchanged(Code.NOT_EXPIRED,s,recover(s,"synthetic-a",2,4,99,"synthetic-b",110,true));
        Transition t=recover(s,"synthetic-a",2,4,100,"synthetic-b",110,true);
        assertEquals(Code.APPLIED,t.code());
        assertEquals(new State("synthetic-b",3,5,110,Status.ACTIVE),t.state());
        unchanged(Code.STALE,t.state(),complete(t.state(),"synthetic-a",2,4,101));
    }

    @Test void uncertainEffectBlocksWithoutTakingOverOrClaimingDispatch() {
        State s=active();
        Transition t=recover(s,"synthetic-a",2,4,100,"synthetic-b",110,false);
        assertEquals(Code.UNCERTAIN_EFFECT,t.code());
        State blocked=new State("synthetic-a",2,5,100,Status.RECOVERY_BLOCKED);
        assertEquals(blocked,t.state());
        unchanged(Code.TERMINAL,t.state(),renew(t.state(),"synthetic-a",2,5,101,110));
        unchanged(Code.TERMINAL,t.state(),complete(t.state(),"synthetic-a",2,5,101));
        unchanged(Code.TERMINAL,t.state(),recover(t.state(),"synthetic-a",2,5,101,"synthetic-b",120,true));
        // Pure model has no dispatch port; no service side-effect claim inferred.
    }

    @Test void overflowNeverWrapsAndUncertaintyDoesNotNeedFenceIncrement() {
        State versionMax=create("synthetic-a",2,Long.MAX_VALUE,100);
        unchanged(Code.OVERFLOW,versionMax,renew(versionMax,"synthetic-a",2,Long.MAX_VALUE,99,110));
        unchanged(Code.OVERFLOW,versionMax,complete(versionMax,"synthetic-a",2,Long.MAX_VALUE,99));
        unchanged(Code.OVERFLOW,versionMax,recover(versionMax,"synthetic-a",2,Long.MAX_VALUE,100,"synthetic-b",110,false));
        State fenceMax=create("synthetic-a",Long.MAX_VALUE,4,100);
        unchanged(Code.OVERFLOW,fenceMax,recover(fenceMax,"synthetic-a",Long.MAX_VALUE,4,100,"synthetic-b",110,true));
        Transition blocked=recover(fenceMax,"synthetic-a",Long.MAX_VALUE,4,100,"synthetic-b",110,false);
        assertEquals(Code.UNCERTAIN_EFFECT,blocked.code());
        assertEquals(Long.MAX_VALUE,blocked.state().fence());
    }

    @Test void linearCompleteThenRecoveryAndRecoveryThenOldComplete() {
        State s=active();
        State completed=complete(s,"synthetic-a",2,4,99).state();
        unchanged(Code.TERMINAL,completed,recover(completed,"synthetic-a",2,5,100,"synthetic-b",110,true));
        State recovered=recover(s,"synthetic-a",2,4,100,"synthetic-b",110,true).state();
        unchanged(Code.STALE,recovered,complete(recovered,"synthetic-a",2,4,101));
        // Linear transition alternatives, not concurrent/global-CAS proof.
    }

    @Test void terminalAndStalePrecedencePreserveState() {
        State terminal=new State("synthetic-a",2,5,100,Status.COMPLETED);
        unchanged(Code.STALE,terminal,complete(terminal,"synthetic-a",2,4,101));
        unchanged(Code.TERMINAL,terminal,complete(terminal,"synthetic-a",2,5,101));
        unchanged(Code.TERMINAL,terminal,renew(terminal,"synthetic-a",2,5,101,110));
    }

    @Test void invalidShapeBeforeCasUsesFixedErrorWithoutRawCause() {
        State s=active();
        IllegalArgumentException e=assertThrows(IllegalArgumentException.class,
                ()->renew(s,"synthetic-mismatch",9,9,99,100));
        assertEquals("Invalid lease input",e.getMessage());
        assertNull(e.getCause());
        assertThrows(IllegalArgumentException.class,()->recover(s,"synthetic-a",2,4,100,"synthetic-b",100,true));
        assertThrows(IllegalArgumentException.class,()->create(null,0,0,0));
        assertThrows(IllegalArgumentException.class,()->create(" ",0,0,0));
        assertThrows(IllegalArgumentException.class,()->create("synthetic-a",-1,0,0));
        assertThrows(IllegalArgumentException.class,()->complete(s,"synthetic-a",2,4,-1));
    }

    @Test void renderingsDoNotRevealOwnerAndNoReceiptSemanticsAreInvented() {
        State s=active();
        assertEquals("LeaseState[REDACTED]",s.toString());
        assertEquals("LeaseTransition[REDACTED]",complete(s,"synthetic-a",2,4,99).toString());
        // Authorized committed receipt replay and pending journal disposition are
        // external service contracts; a TERMINAL result does not implement them.
    }
}
