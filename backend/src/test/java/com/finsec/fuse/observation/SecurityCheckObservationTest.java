package com.finsec.fuse.observation;

import static com.finsec.fuse.observation.SecurityCheckObservation.Check.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class SecurityCheckObservationTest {
    @Test void onlyExplicitCheckScopesCountNotModelOrReviewerWaits() {
        AtomicLong clock = new AtomicLong();
        var session = SecurityCheckObservation.begin(clock::get);
        try (session) {
            clock.addAndGet(8_000_000_000L); // Simulated model time, no external call.
            try (var check = SecurityCheckObservation.enter(VERIFIED_EVIDENCE)) {
                clock.addAndGet(125_000);
            }
            clock.addAndGet(600_000_000_000L); // Simulated human wait.
            try (var check = SecurityCheckObservation.enter(DELEGATION_VALIDATION)) {
                clock.addAndGet(375_000);
            }
        }
        assertEquals(500_000, session.result().elapsedNanos());
        assertEquals(0.5, session.result().securityCheckDurationMs());
        assertEquals(2, session.result().completedCheckCount());
    }

    @Test void nestedChecksAreNotDoubleCountedAndUseOnlyTheOutermostClock() {
        AtomicLong clock = new AtomicLong();
        AtomicLong clockReads = new AtomicLong();
        var session = SecurityCheckObservation.begin(() -> { clockReads.incrementAndGet(); return clock.get(); });
        try (session; var outer = SecurityCheckObservation.enter(DELEGATION_VALIDATION)) {
            clock.addAndGet(10);
            try (var evidence = SecurityCheckObservation.enter(VERIFIED_EVIDENCE)) {
                clock.addAndGet(20);
                try (var quarantine = SecurityCheckObservation.enter(QUARANTINE_MATCH)) {
                    clock.addAndGet(30);
                }
            }
            clock.addAndGet(40);
        }
        assertEquals(100, session.result().elapsedNanos());
        assertEquals(3, session.result().completedCheckCount());
        assertEquals(2, clockReads.get());
        assertEquals(1L, session.result().completedChecks().get(VERIFIED_EVIDENCE));
        assertThrows(UnsupportedOperationException.class,
                () -> session.result().completedChecks().put(VERIFIED_EVIDENCE, 20L));
    }

    @Test void exceptionsCompleteAllScopesAndDoNotLeakIntoTheNextSession() {
        AtomicLong clock = new AtomicLong();
        RuntimeException denial = new RuntimeException("local test denial");
        var session = SecurityCheckObservation.begin(clock::get);
        assertSame(denial, assertThrows(RuntimeException.class, () -> {
            try (session; var outer = SecurityCheckObservation.enter(DELEGATION_VALIDATION);
                    var inner = SecurityCheckObservation.enter(VERIFIED_EVIDENCE)) {
                clock.addAndGet(250);
                throw denial;
            }
        }));
        assertEquals(250, session.result().elapsedNanos());
        assertEquals(2, session.result().completedCheckCount());
        try (var ignored = SecurityCheckObservation.enter(VERIFIED_EVIDENCE)) { clock.addAndGet(999); }
        var next = SecurityCheckObservation.begin(clock::get);
        next.close();
        assertEquals(0, next.result().elapsedNanos());
        assertEquals(0, next.result().completedCheckCount());
    }

    @Test void disabledChecksAndInactiveRuntimeProduceNoRecordedCalls() {
        var inactive = SecurityCheckObservation.enter(VERIFIED_EVIDENCE);
        var otherInactive = SecurityCheckObservation.enter(QUARANTINE_MATCH);
        assertSame(inactive, otherInactive);
        inactive.close();
        AtomicLong reads = new AtomicLong();
        var session = SecurityCheckObservation.begin(reads::incrementAndGet);
        try (session; var shared = SecurityCheckObservation.enter(VERIFIED_EVIDENCE, false)) {}
        assertEquals(0, reads.get());
        assertEquals(0, session.result().securityCheckDurationMs());
        assertTrue(session.result().completedChecks().isEmpty());
    }

    @Test void childThreadDoesNotInheritTheParentSession() throws InterruptedException {
        AtomicLong clock = new AtomicLong();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        var session = SecurityCheckObservation.begin(clock::get);
        try (session) {
            Thread child = new Thread(() -> {
                try {
                    try (var ignored = SecurityCheckObservation.enter(VERIFIED_EVIDENCE)) {}
                    var independent = SecurityCheckObservation.begin(clock::get);
                    try (independent; var check = SecurityCheckObservation.enter(QUARANTINE_MATCH)) {
                        clock.addAndGet(50);
                    }
                    assertEquals(50, independent.result().elapsedNanos());
                    assertEquals(1, independent.result().completedCheckCount());
                } catch (Throwable error) { failure.set(error); }
            });
            child.start();
            child.join();
        }
        assertNull(failure.get());
        assertEquals(0, session.result().elapsedNanos());
        assertEquals(0, session.result().completedCheckCount());
    }

    @Test void nestedSessionsFailWithoutReplacingTheActiveMeasurement() {
        AtomicLong clock = new AtomicLong();
        var session = SecurityCheckObservation.begin(clock::get);
        try (session) {
            assertThrows(IllegalStateException.class, SecurityCheckObservation::begin);
            assertThrows(IllegalStateException.class, session::result);
            try (var check = SecurityCheckObservation.enter(VERIFIED_EVIDENCE)) { clock.addAndGet(8); }
        }
        assertEquals(8, session.result().elapsedNanos());
    }

    @Test void repeatedCloseIsIdempotentButOutOfOrderScopeCloseIsRejected() {
        AtomicLong clock = new AtomicLong();
        var session = SecurityCheckObservation.begin(clock::get);
        try (session) {
            var outer = SecurityCheckObservation.enter(DELEGATION_VALIDATION);
            var inner = SecurityCheckObservation.enter(VERIFIED_EVIDENCE);
            assertThrows(IllegalStateException.class, outer::close);
            clock.addAndGet(100);
            inner.close();
            inner.close();
            outer.close();
            outer.close();
        }
        session.close();
        assertEquals(100, session.result().elapsedNanos());
        assertEquals(2, session.result().completedCheckCount());
    }

    @Test void incompleteScopeClearsThreadStateAndCannotPublishPartialTime() {
        var session = SecurityCheckObservation.begin();
        SecurityCheckObservation.enter(VERIFIED_EVIDENCE);
        assertThrows(IllegalStateException.class, session::close);
        assertThrows(IllegalStateException.class, session::result);
        var next = SecurityCheckObservation.begin();
        next.close();
        assertEquals(0, next.result().completedCheckCount());
    }

    @Test void foreignThreadCannotCloseOrReadTheOwnerSession() throws InterruptedException {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        var session = SecurityCheckObservation.begin();
        try (session) {
            Thread child = new Thread(() -> {
                try {
                    assertThrows(IllegalStateException.class, session::close);
                    assertThrows(IllegalStateException.class, session::result);
                } catch (Throwable error) { failure.set(error); }
            });
            child.start();
            child.join();
            assertThrows(IllegalStateException.class, SecurityCheckObservation::begin);
        }
        assertNull(failure.get());
        assertEquals(0, session.result().completedCheckCount());
    }
}
