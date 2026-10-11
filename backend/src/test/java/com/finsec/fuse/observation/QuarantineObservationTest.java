package com.finsec.fuse.observation;

import static com.finsec.fuse.observation.QuarantineObservation.Attempt.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

class QuarantineObservationTest {
    private static QuarantineObservation.Execution execution() {
        return new QuarantineObservation.Execution(UUID.randomUUID(), 1, UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());
    }
    /** Synthetic synchronization only: real PostgreSQL commit/rollback is covered separately. */
    private static List<TransactionSynchronization> transaction(Runnable action) {
        TransactionSynchronizationManager.setActualTransactionActive(true);
        TransactionSynchronizationManager.initSynchronization();
        try {
            action.run();
            return TransactionSynchronizationManager.getSynchronizations();
        } finally {
            TransactionSynchronizationManager.clearSynchronization();
            TransactionSynchronizationManager.setActualTransactionActive(false);
        }
    }
    private static void commit(Runnable action) { transaction(action).forEach(TransactionSynchronization::afterCommit); }

    @Test void startUsesAfterCommitAndEndUsesActualGuardNotDenialCommit() {
        var clock = new AtomicLong(10);
        var session = QuarantineObservation.begin(clock::get);
        var execution = execution();var id = UUID.randomUUID();
        try (session) {
            var callbacks = transaction(() -> QuarantineObservation.quarantineWillCommit(id, Set.of(execution)));
            clock.set(1_000);
            commit(() -> QuarantineObservation.executionDenied(execution, PAYMENT_EXECUTION)); // Not committed yet.
            clock.set(2_000);
            callbacks.forEach(TransactionSynchronization::afterCommit);
            clock.set(2_250);
            var denial = transaction(() -> QuarantineObservation.executionDenied(execution, PAYMENT_EXECUTION));
            clock.set(99_000); // Audit/transaction completion is not the endpoint.
            denial.forEach(TransactionSynchronization::afterCommit);
        }
        assertEquals(0.00025, session.result().quarantineLatencyMs());
        var incident = session.result().incidents().getFirst();
        assertEquals(id, incident.quarantineId());assertEquals(2_000, incident.commitObservedNanos());
        assertEquals(2_250, incident.firstDenial().executionDeniedNanos());
        assertEquals(250, incident.firstDenial().elapsedNanos());
        assertEquals(execution.jobId(), incident.firstDenial().jobId());
        assertFalse(session.result().toString().contains(execution.leaseToken().toString()));
    }

    @Test void rolledBackQuarantineAndRolledBackDenialAreNotPublished() {
        var clock = new AtomicLong();var execution = execution();
        var session = QuarantineObservation.begin(clock::get);
        try (session) {
            transaction(() -> QuarantineObservation.quarantineWillCommit(UUID.randomUUID(), Set.of(execution)));
            commit(() -> QuarantineObservation.executionDenied(execution, KYC_RESULT_APPLY));
            assertEquals(0, clock.get());
            commit(() -> QuarantineObservation.quarantineWillCommit(UUID.randomUUID(), Set.of(execution)));
            clock.set(25);
            transaction(() -> QuarantineObservation.executionDenied(execution, KYC_RESULT_APPLY));
        }
        assertEquals(1, session.result().incidents().size());assertNull(session.result().quarantineLatencyMs());
        assertEquals(0, session.result().observedDenialCount());
    }

    @Test void exactContextAndFirstActualDenialAreRequired() {
        var clock = new AtomicLong(1_000);var execution = execution();
        var session = QuarantineObservation.begin(clock::get);
        try (session) {
            commit(() -> QuarantineObservation.quarantineWillCommit(UUID.randomUUID(), Set.of(execution)));
            for (var unrelated : List.of(execution(),
                    new QuarantineObservation.Execution(execution.workflowId(), 2, execution.jobId(), execution.runId(), execution.leaseToken()),
                    new QuarantineObservation.Execution(execution.workflowId(), 1, execution.jobId(), execution.runId(), UUID.randomUUID())))
                commit(() -> QuarantineObservation.executionDenied(unrelated, PAYMENT_EXECUTION));
            clock.set(1_100);commit(() -> QuarantineObservation.executionDenied(execution, KYC_RESULT_APPLY));
            clock.set(10_000);commit(() -> QuarantineObservation.executionDenied(execution, PAYMENT_EXECUTION));
        }
        assertEquals(100, session.result().incidents().getFirst().firstDenial().elapsedNanos());
        assertEquals(KYC_RESULT_APPLY, session.result().incidents().getFirst().firstDenial().attempt());
        assertEquals(1, session.result().observedDenialCount());
    }

    @Test void noDenialIsNullWhileObservedZeroIsZeroAndIncidentsRetainOwnOrigins() {
        var clock = new AtomicLong(500);var a = execution();var b = execution();
        var session = QuarantineObservation.begin(clock::get);
        try (session) {
            commit(() -> QuarantineObservation.quarantineWillCommit(UUID.randomUUID(), Set.of(a)));
            clock.set(600);commit(() -> QuarantineObservation.quarantineWillCommit(UUID.randomUUID(), Set.of(b)));
            commit(() -> QuarantineObservation.executionDenied(b, KYC_RESULT_APPLY));
            clock.set(900);commit(() -> QuarantineObservation.executionDenied(a, PAYMENT_EXECUTION));
        }
        assertEquals(0.0, session.result().quarantineLatencyMs());
        assertEquals(400, session.result().incidents().getFirst().firstDenial().elapsedNanos());
        assertEquals(0, session.result().incidents().getLast().firstDenial().elapsedNanos());
        assertThrows(UnsupportedOperationException.class, () -> session.result().incidents().clear());
    }

    @Test void disabledOrNonTransactionalObservationDoesNotReadClockOrRegisterCallbacks() {
        var execution = execution();
        assertTrue(transaction(() -> {
            QuarantineObservation.quarantineWillCommit(UUID.randomUUID(), Set.of(execution));
            QuarantineObservation.executionDenied(execution, PAYMENT_EXECUTION);
        }).isEmpty());
        var reads = new AtomicLong();var session = QuarantineObservation.begin(reads::incrementAndGet);
        try (session) {
            QuarantineObservation.quarantineWillCommit(UUID.randomUUID(), Set.of(execution));
            QuarantineObservation.executionDenied(execution, PAYMENT_EXECUTION);
        }
        assertEquals(0, reads.get());assertNull(session.result().quarantineLatencyMs());
    }

    @Test void closedSessionCallbacksAndEarlierIncidentsCannotContaminateNextCase() {
        var execution = execution();var clock = new AtomicLong();
        var first = QuarantineObservation.begin(clock::get);
        var callbacks = transaction(() -> QuarantineObservation.quarantineWillCommit(UUID.randomUUID(), Set.of(execution)));
        first.close();first.close();
        var next = QuarantineObservation.begin(clock::get);
        try (next) {
            callbacks.forEach(TransactionSynchronization::afterCommit);
            commit(() -> QuarantineObservation.executionDenied(execution, PAYMENT_EXECUTION));
        }
        assertTrue(first.result().incidents().isEmpty());assertTrue(next.result().incidents().isEmpty());
    }

    @Test void sessionIsNotInheritedAndForeignThreadCannotReadOrCloseIt() throws InterruptedException {
        var session = QuarantineObservation.begin();var failure = new AtomicReference<Throwable>();
        try (session) {
            assertThrows(IllegalStateException.class, QuarantineObservation::begin);
            assertThrows(IllegalStateException.class, session::result);
            var child = new Thread(() -> {
                try {
                    assertFalse(QuarantineObservation.enabled());
                    assertThrows(IllegalStateException.class, session::close);
                    assertThrows(IllegalStateException.class, session::result);
                    var own = QuarantineObservation.begin();own.close();assertNull(own.result().quarantineLatencyMs());
                } catch (Throwable error) { failure.set(error); }
            });
            child.start();child.join();assertTrue(QuarantineObservation.enabled());
        }
        assertNull(failure.get());assertFalse(QuarantineObservation.enabled());
    }
}
