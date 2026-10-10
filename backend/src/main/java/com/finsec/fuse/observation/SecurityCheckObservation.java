package com.finsec.fuse.observation;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.LongSupplier;

/**
 * Optional, synchronous experiment observation. Normal serving paths never open a session.
 * Only monotonic elapsed time and fixed check names/counts are retained, never policy inputs.
 *
 * <p>The measured boundary is deliberately narrower than a workflow or transaction: additional
 * verified-evidence checks, delegation consumption validation, and quarantine matching. Shared
 * grant creation, common MAC/strict-JSON/body-hash verification, public authentication, exact
 * approval, non-VERIFIED proposal handling, model
 * calls, and reviewer waits are outside it. Database reads within a measured check are included.
 * This is measured check elapsed time, not a paired whole-workflow latency difference or a CPU
 * benchmark. Nested measured calls contribute to elapsed time once.
 */
public final class SecurityCheckObservation {
    public static final String BOUNDARY_VERSION = "FUSE-DEDICATED-POLICY-CHECKS-2";

    public enum Check { VERIFIED_EVIDENCE, DELEGATION_VALIDATION, QUARANTINE_MATCH }

    private static final ThreadLocal<Session> ACTIVE = new ThreadLocal<>();
    private static final Scope NOOP = () -> {};

    private SecurityCheckObservation() {}

    /** Call only around one isolated synchronous experiment scenario, never a request/worker. */
    public static Session begin() {
        return begin(System::nanoTime);
    }

    // A deterministic monotonic clock is injectable only by local package tests.
    static Session begin(LongSupplier nanoTime) {
        Objects.requireNonNull(nanoTime);
        if (ACTIVE.get() != null) throw new IllegalStateException("An observation session is already active");
        Session session = new Session(nanoTime);
        ACTIVE.set(session);
        return session;
    }

    /** No clock read, input capture, or span allocation occurs when observation is not enabled. */
    public static Scope enter(Check check) {
        Session session = ACTIVE.get();
        return session == null ? NOOP : session.enter(Objects.requireNonNull(check));
    }

    /** Allows shared baseline handling to remain outside the additional-check boundary. */
    public static Scope enter(Check check, boolean additionalCheck) {
        return additionalCheck ? enter(check) : NOOP;
    }

    public interface Scope extends AutoCloseable {
        @Override void close();
    }

    public record Result(long elapsedNanos, long completedCheckCount, Map<Check, Long> completedChecks) {
        public Result {
            completedChecks = Map.copyOf(completedChecks);
        }
        /** Fractional milliseconds preserve sub-millisecond checks without inventing a minimum. */
        public double securityCheckDurationMs() { return elapsedNanos / 1_000_000.0; }
    }

    /** Use try-with-resources, then read result() after close(), including when a check denies. */
    public static final class Session implements AutoCloseable {
        private final Thread owner = Thread.currentThread();
        private final LongSupplier nanoTime;
        private final EnumMap<Check, Long> completedChecks = new EnumMap<>(Check.class);
        private Span current;
        private long elapsedNanos;
        private long completedCheckCount;
        private boolean closed;
        private Result result;

        private Session(LongSupplier nanoTime) { this.nanoTime = nanoTime; }

        private Span enter(Check check) {
            requireOwner();
            Span span = new Span(this, current, check);
            current = span;
            if (span.parent == null) span.startedAt = nanoTime.getAsLong();
            return span;
        }

        private void complete(Span span) {
            requireOwner();
            if (span.closed) return;
            if (closed) throw new IllegalStateException("The observation session is closed");
            if (current != span) throw new IllegalStateException("Check spans must close in reverse order");
            // Read the end before bookkeeping, and only for the outermost timed boundary.
            if (span.parent == null) elapsedNanos += nanoTime.getAsLong() - span.startedAt;
            completedCheckCount++;
            completedChecks.merge(span.check, 1L, Long::sum);
            current = span.parent;
            span.closed = true;
        }

        @Override public void close() {
            requireOwner();
            if (closed) return;
            ACTIVE.remove();
            closed = true;
            // A malformed scope must neither leak into the next request nor publish partial time.
            if (current != null) throw new IllegalStateException("An observation check is still open");
            result = new Result(elapsedNanos, completedCheckCount, completedChecks);
        }

        public Result result() {
            requireOwner();
            if (result == null) throw new IllegalStateException("Close all checks and the observation session first");
            return result;
        }

        private void requireOwner() {
            if (Thread.currentThread() != owner) throw new IllegalStateException("Observation is thread-confined");
        }
    }

    private static final class Span implements Scope {
        private final Session session;
        private final Span parent;
        private final Check check;
        private long startedAt;
        private boolean closed;

        private Span(Session session, Span parent, Check check) {
            this.session = session;
            this.parent = parent;
            this.check = check;
        }

        @Override public void close() { session.complete(this); }
    }
}
