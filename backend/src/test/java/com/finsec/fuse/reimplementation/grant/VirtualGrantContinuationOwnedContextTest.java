package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.simulation.VirtualGrantContinuationFixture;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.*;
import static com.finsec.fuse.reimplementation.grant.OwnedTypedContinuationPort.*;
import static com.finsec.fuse.reimplementation.simulation.VirtualGrantContinuationFixture.id;

/** Opaque callback ownership in synthetic source only; no authorization or race proof. */
class VirtualGrantContinuationOwnedContextTest {
    private static ContinuationOutcome readOnly() {
        return new ContinuationOutcome(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, null, ContinuationEffect.UNKNOWN);
    }
    private static void unavailable(org.junit.jupiter.api.function.Executable call) {
        var failure = assertThrows(IllegalStateException.class, call);
        assertEquals("OWNED_CONTINUATION_TRANSACTION_UNAVAILABLE", failure.getMessage());
    }

    @Test void escapedFacadeRejectsAllFiveMethodsAfterCallbackClosure() {
        var f = new VirtualGrantContinuationFixture(); var c = f.firstCommand();
        AtomicReference<OwnedContinuationTx> saved = new AtomicReference<>(); var before = f.store.snapshot();
        var observed = f.journal.continueWorkflow(c, tx -> { saved.set(tx); return readOnly(); });
        assertEquals(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, observed.status());
        var tx = saved.get(); assertNotNull(tx);
        unavailable(() -> tx.lookupExactContinuation(c)); unavailable(() -> tx.admitFreshContinuation(c));
        unavailable(() -> tx.readContinuationBindings(c)); unavailable(() -> tx.recordContinuation(c, null));
        unavailable(() -> tx.recordDeniedContinuation(c, null)); assertEquals(before, f.store.snapshot());
    }

    @Test void everyContinuationMethodRejectsASecondCommandInsideOwningCallback() {
        var f = new VirtualGrantContinuationFixture(); var c = f.firstCommand();
        var other = f.command(2, f.firstPrior(), 9970); var before = f.store.snapshot();
        f.journal.continueWorkflow(c, tx -> {
            org.junit.jupiter.api.function.Executable[] calls = {
                () -> tx.lookupExactContinuation(other), () -> tx.admitFreshContinuation(other),
                () -> tx.readContinuationBindings(other), () -> tx.recordContinuation(other, null),
                () -> tx.recordDeniedContinuation(other, null)
            };
            for (var call : calls) assertEquals(Status.IDENTITY_CONFLICT, assertThrows(Stop.class, call).status);
            return readOnly();
        });
        assertEquals(before, f.store.snapshot());
    }

    @Test void synchronousReentryDoesNotEnterAnotherContinuationCallbackOrPublish() {
        var f = new VirtualGrantContinuationFixture(); var c = f.firstCommand(); var before = f.store.snapshot();
        var outer = f.journal.continueWorkflow(c, tx -> {
            var nested = f.journal.continueWorkflow(c, ignored -> { fail("reentrant callback entered"); return null; });
            assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION, nested.status()); assertNull(nested.receipt());
            assertNull(tx.lookupExactContinuation(c)); return readOnly();
        });
        assertEquals(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, outer.status());
        assertEquals(before, f.store.snapshot());
    }

    @Test void foreignThreadIsRefusedBeforeOwnedFacadeCanReadWhileOwnerIsOpen() {
        var f = new VirtualGrantContinuationFixture(); var c = f.firstCommand(); var before = f.store.snapshot();
        f.journal.continueWorkflow(c, tx -> {
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread worker = new Thread(() -> { try { tx.lookupExactContinuation(c); } catch (Throwable e) { failure.set(e); } });
            worker.setDaemon(true);
            try {
                worker.start(); worker.join(1000); assertFalse(worker.isAlive(), "synthetic foreign callback did not stop");
                assertInstanceOf(IllegalStateException.class, failure.get());
                assertEquals("OWNED_CONTINUATION_TRANSACTION_UNAVAILABLE", failure.get().getMessage());
                assertNull(tx.lookupExactContinuation(c));
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt(); throw new AssertionError("synthetic owner interrupted", interrupted);
            } finally { if (worker.isAlive()) worker.interrupt(); }
            return readOnly();
        });
        assertEquals(before, f.store.snapshot());
    }

    @Test void repeatedOwnedReadReturnsSameActualTicketAndUnfinishedAdmissionCannotPublish() {
        var f = new VirtualGrantContinuationFixture(); f.blockAndRelease(); var c = f.firstCommand();
        var before = f.store.snapshot(); AtomicReference<CurrentBindings> captured = new AtomicReference<>();
        var result = f.journal.continueWorkflow(c, tx -> {
            assertNull(tx.lookupExactContinuation(c)); tx.admitFreshContinuation(c);
            var ticket = tx.readContinuationBindings(c); captured.set(ticket);
            assertSame(ticket, tx.readContinuationBindings(c));
            assertEquals(PendingDisposition.VERIFIED_EMPTY, ticket.pendingDisposition());
            assertEquals(ResumeReadiness.READY, ticket.resumeReadiness());
            assertEquals(f.scope(1), ticket.origin().scope());
            return readOnly();
        });
        assertNotNull(captured.get());
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION, result.status()); assertNull(result.receipt());
        assertEquals(before, f.store.snapshot());
    }

    @Test void missingOpaquePhaseNeverMakesSyntheticPendingAccountingAuthorized() {
        var f = new VirtualGrantContinuationFixture(); var before = f.store.snapshot();
        new ActionJournal(f.store).reservedTransaction(tx -> {
            assertFalse(VirtualGrantTransactionJournal.accountingConsumptionIsPending(tx, id(9980), id(9981), null));
            assertFalse(VirtualGrantTransactionJournal.accountingPreparationIsPending(tx, null, null));
            return null;
        });
        assertEquals(before, f.store.snapshot());
    }
}
