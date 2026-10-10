package com.finsec.fuse.observation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.LongSupplier;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Opt-in observation of committed quarantine invalidations and actual execution denials.
 * A session belongs to one synchronous experiment/test thread; no serving session is automatic.
 * Matcher results and UI reads cannot produce observations. This utility never makes decisions.
 */
public final class QuarantineObservation {
    public static final String BOUNDARY_VERSION = "QUARANTINE-COMMIT-TO-EXECUTION-DENIAL-1";
    public enum Attempt { KYC_RESULT_APPLY, PAYMENT_EXECUTION }

    /** Private correlation context only: lease tokens are never included in exported results. */
    public record Execution(UUID workflowId, int generation, UUID jobId, UUID runId, UUID leaseToken) {
        public Execution {
            Objects.requireNonNull(workflowId);
            Objects.requireNonNull(jobId);
            Objects.requireNonNull(runId);
            Objects.requireNonNull(leaseToken);
        }
    }

    public record Denial(UUID workflowId, int generation, UUID jobId, UUID runId, Attempt attempt,
                         long executionDeniedNanos, long elapsedNanos) {
        public double latencyMs() { return elapsedNanos / 1_000_000.0; }
    }
    public record Incident(UUID quarantineId, long commitObservedNanos, int affectedExecutionCount,
                           Denial firstDenial) {}
    public record Result(List<Incident> incidents, Double quarantineLatencyMs) {
        public Result { incidents = List.copyOf(incidents); }
        public long observedDenialCount() { return incidents.stream().filter(i -> i.firstDenial() != null).count(); }
    }

    private static final ThreadLocal<Session> ACTIVE = new ThreadLocal<>();
    private QuarantineObservation() {}

    public static Session begin() { return begin(System::nanoTime); }
    static Session begin(LongSupplier nanoTime) {
        Objects.requireNonNull(nanoTime);
        if (ACTIVE.get() != null) throw new IllegalStateException("A quarantine observation session is already active");
        var session = new Session(nanoTime);
        ACTIVE.set(session);
        return session;
    }
    public static boolean enabled() { return ACTIVE.get() != null; }

    /**
     * Called after the service has invalidated these exact active executions, inside its transaction.
     * Capture starts in afterCommit, never at service return or at a database created_at timestamp.
     */
    public static void quarantineWillCommit(UUID quarantineId, Set<Execution> invalidatedExecutions) {
        var session = ACTIVE.get();
        if (session == null || !transactionActive()) return;
        var executions = Set.copyOf(invalidatedExecutions);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override public void afterCommit() {
                if (session.isActive()) session.committed(quarantineId, executions);
            }
        });
    }

    /**
     * Call only from an actual execution guard after proving quarantine caused its rejection.
     * The guard timestamp is retained only if that denial's transaction commits. Rollbacks and
     * attempts preceding the quarantine commit cannot become measured policy outcomes.
     */
    public static void executionDenied(Execution execution, Attempt attempt) {
        var session = ACTIVE.get();
        if (session == null || !transactionActive()) return;
        var matching = session.committed.values().stream()
            .filter(i -> i.firstDenial == null && i.executions.contains(execution)).toList();
        if (matching.isEmpty()) return;
        long deniedAt = session.nanoTime.getAsLong();
        long sequence = session.nextDenialSequence++;
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override public void afterCommit() {
                if (!session.isActive()) return;
                for (var incident : matching) {
                    long elapsed = deniedAt - incident.committedAt;
                    if (elapsed < 0 || (incident.firstDenial != null && incident.denialSequence <= sequence)) continue;
                    incident.firstDenial = new Denial(execution.workflowId(), execution.generation(),
                        execution.jobId(), execution.runId(), attempt, deniedAt, elapsed);
                    incident.denialSequence = sequence;
                }
            }
        });
    }

    private static boolean transactionActive() {
        return TransactionSynchronizationManager.isSynchronizationActive()
            && TransactionSynchronizationManager.isActualTransactionActive();
    }

    public static final class Session implements AutoCloseable {
        private final Thread owner = Thread.currentThread();
        private final LongSupplier nanoTime;
        private final Map<UUID, PendingIncident> committed = new LinkedHashMap<>();
        private long nextDenialSequence;
        private boolean closed;
        private Result result;
        private Session(LongSupplier nanoTime) { this.nanoTime = nanoTime; }
        private boolean isActive() { return Thread.currentThread() == owner && !closed && ACTIVE.get() == this; }
        private void committed(UUID quarantineId, Set<Execution> executions) {
            if (!committed.containsKey(quarantineId))
                committed.put(quarantineId, new PendingIncident(quarantineId, nanoTime.getAsLong(), executions));
        }
        @Override public void close() {
            requireOwner();
            if (closed) return;
            ACTIVE.remove();
            closed = true;
            var incidents = new ArrayList<Incident>();
            PendingIncident first = null;
            for (var incident : committed.values()) {
                incidents.add(new Incident(incident.id, incident.committedAt, incident.executions.size(), incident.firstDenial));
                if (incident.firstDenial != null && (first == null || incident.denialSequence < first.denialSequence)) first = incident;
            }
            result = new Result(incidents, first == null ? null : first.firstDenial.latencyMs());
            committed.clear(); // In particular, discard all lease-token correlation context.
        }
        public Result result() {
            requireOwner();
            if (result == null) throw new IllegalStateException("Close the quarantine observation session first");
            return result;
        }
        private void requireOwner() {
            if (Thread.currentThread() != owner) throw new IllegalStateException("Quarantine observation is thread-confined");
        }
    }
    private static final class PendingIncident {
        final UUID id;
        final long committedAt;
        final Set<Execution> executions;
        Denial firstDenial;
        long denialSequence;
        PendingIncident(UUID id, long committedAt, Set<Execution> executions) {
            this.id = id;
            this.committedAt = committedAt;
            this.executions = executions;
        }
    }
}
