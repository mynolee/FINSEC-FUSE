package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Supplier;

/** Explicit finite virtual delivery. Supplied executor ownership, authority and bounds remain external. */
public final class VirtualDeliveryCoordinator {
    public interface Notifications {
        void kycCommitted(UUID workflowId, int generation);
        void paymentCommitted(UUID workflowId, int generation);
        void experimentCommitted(ActorRef owner, UUID experimentId);
    }
    public enum Submission { ACCEPTED, SKIPPED, UNAVAILABLE }
    public record DispatchStatus(int queued, int running, int unknown, long rejected) { }
    private enum State { QUEUED, RUNNING, UNKNOWN }
    private record Key(String kind, UUID id) { }
    private static final class Flight {
        State state = State.QUEUED;
        boolean inlineRefused, submissionReturned, completed;
    }
    private final Executor executor;
    private final ActorRef workflowActor;
    private final VirtualWorkflowService workflows;
    private final VirtualKycJobAdapter kyc;
    private final VirtualExperimentService experiments;
    private final Supplier<UUID> actions;
    private final int maximumInFlight;
    private final Map<Key, Flight> flights = new LinkedHashMap<>();
    private final ThreadLocal<Boolean> submitting = new ThreadLocal<>();
    private long rejected;
    /** Local diagnostic only; neither successful delivery nor permission is inferred. */
    public DispatchStatus status() {
        synchronized (flights) {
            int queued = 0, running = 0, unknown = 0;
            for (var flight : flights.values()) {
                switch (flight.state) { case QUEUED -> queued++; case RUNNING -> running++; case UNKNOWN -> unknown++; }
            }
            return new DispatchStatus(queued, running, unknown, rejected);
        }
    }
    private void rejected() { if (rejected != Long.MAX_VALUE) rejected++; }

    public VirtualDeliveryCoordinator(Executor executor, ActorRef workflowActor, VirtualWorkflowService workflows,
            VirtualKycJobAdapter kyc, VirtualExperimentService experiments, Supplier<UUID> actions, int maximumInFlight) {
        this.executor = Objects.requireNonNull(executor); this.workflowActor = Objects.requireNonNull(workflowActor);
        this.workflows = Objects.requireNonNull(workflows); this.kyc = Objects.requireNonNull(kyc);
        this.experiments = Objects.requireNonNull(experiments); this.actions = Objects.requireNonNull(actions);
        if (maximumInFlight < 1) throw new IllegalArgumentException("INVALID_DELIVERY_CAPACITY");
        this.maximumInFlight = maximumInFlight;
    }

    /** Original request receipts are not changed when an explicit dispatch cannot be accepted. */
    public Submission enqueueKyc(UUID workflowId, int generation) { return workflow(workflowId, generation, "KYC"); }
    public Submission enqueuePayment(UUID workflowId, int generation) { return workflow(workflowId, generation, "PAY"); }
    private Submission workflow(UUID workflowId, int generation, String phase) {
        try {
            var view = workflows.get(workflowActor, Objects.requireNonNull(workflowId));
            var job = eligibleJob(view, generation, phase);
            if (job == null) return Submission.SKIPPED;
            UUID jobId = uuid(job.get("jobId"));
            return submit(new Key(phase, jobId), () -> {
                var current = eligibleJob(workflows.get(workflowActor, workflowId), generation, phase);
                if (current == null || !jobId.equals(uuid(current.get("jobId")))) return;
                if ("KYC".equals(phase)) {
                    UUID prepare = nextAction(), observe = nextAction();
                    if (prepare.equals(observe)) throw SimulationFailure.unavailable();
                    kyc.run(workflowActor, new VirtualKycJobAdapter.Delivery(prepare, observe, workflowId, jobId, generation));
                } else {
                    UUID reserveAction = nextAction(), commitAction = nextAction();
                    if (reserveAction.equals(commitAction)) throw SimulationFailure.unavailable();
                    var reserved = workflows.reservePayment(workflowActor, reserveAction, workflowId, jobId, generation);
                    if (!"ALLOW".equals(reserved.get("decision")) || reserved.get("reservationId") == null) return;
                    if (!workflowId.toString().equals(reserved.get("workflowId"))
                            || !Integer.valueOf(generation).equals(reserved.get("generation"))) throw SimulationFailure.unavailable();
                    workflows.commitPayment(workflowActor, commitAction, workflowId, uuid(reserved.get("reservationId")));
                }
            });
        } catch (RuntimeException unavailable) { return Submission.UNAVAILABLE; }
    }

    /** Uses the actual creating owner; a configured worker is never substituted for experiment ownership. */
    public Submission enqueueExperiment(ActorRef owner, UUID experimentId) {
        try {
            Objects.requireNonNull(owner); Objects.requireNonNull(experimentId);
            var initial = experiments.get(owner, experimentId);
            if (terminal(initial)) return Submission.SKIPPED;
            int total = count(initial.get("totalPairs")), completed = count(initial.get("completedPairs"));
            if (total < 1 || total > Math.multiplyExact(100, 10) || completed > total) throw SimulationFailure.unavailable();
            int remaining = Math.subtractExact(total, completed);
            return submit(new Key("EXPERIMENT", experimentId), () -> {
                int prior = completed;
                for (int step = 0; step < remaining; step++) {
                    var current = experiments.get(owner, experimentId);
                    if (terminal(current)) return;
                    if (count(current.get("totalPairs")) != total || count(current.get("completedPairs")) != prior)
                        throw SimulationFailure.unavailable();
                    var receipt = experiments.advance(owner, nextAction(), experimentId);
                    if (!experimentId.toString().equals(receipt.get("experimentId"))) throw SimulationFailure.unavailable();
                    if ("CANCELLED".equals(receipt.get("status"))) return;
                    int now = count(receipt.get("completedPairs"));
                    if (now != Math.addExact(prior, 1)) throw SimulationFailure.unavailable();
                    prior = now;
                    if ("COMPLETED".equals(receipt.get("status"))) return;
                }
            });
        } catch (RuntimeException unavailable) { return Submission.UNAVAILABLE; }
    }

    private Submission submit(Key key, Runnable work) {
        final Flight flight;
        synchronized (flights) {
            if (flights.containsKey(key)) return Submission.SKIPPED;
            if (flights.size() >= maximumInFlight) { rejected(); return Submission.UNAVAILABLE; }
            flight = new Flight(); flights.put(key, flight);
        }
        try {
            submitting.set(Boolean.TRUE);
            executor.execute(() -> {
                synchronized (flights) {
                    if (flights.get(key) != flight || flight.state != State.QUEUED) return;
                    if (Boolean.TRUE.equals(submitting.get())) {
                        flight.inlineRefused = true; rejected(); flights.remove(key); return;
                    }
                    flight.state = State.RUNNING;
                }
                try {
                    work.run();
                    synchronized (flights) {
                        flight.completed = true;
                        if (flight.submissionReturned && flight.state == State.RUNNING && flights.get(key) == flight)
                            flights.remove(key);
                    }
                } catch (RuntimeException unknown) {
                    synchronized (flights) { flight.state = State.UNKNOWN; }
                } catch (Error fatal) {
                    synchronized (flights) { flight.state = State.UNKNOWN; }
                    throw fatal;
                }
            });
            synchronized (flights) {
                flight.submissionReturned = true;
                if (flight.completed && flight.state == State.RUNNING && flights.get(key) == flight) flights.remove(key);
                return flight.inlineRefused ? Submission.UNAVAILABLE : Submission.ACCEPTED;
            }
        } catch (RejectedExecutionException rejected) {
            synchronized (flights) {
                rejected();
                if (flight.state == State.QUEUED) flights.remove(key, flight);
                else flight.state = State.UNKNOWN;
            }
            return Submission.UNAVAILABLE;
        } catch (RuntimeException unknown) {
            synchronized (flights) { flight.state = State.UNKNOWN; }
            return Submission.UNAVAILABLE;
        } finally { submitting.remove(); }
    }
    private UUID nextAction() { return Objects.requireNonNull(actions.get()); }
    private static boolean terminal(Map<String, Object> row) {
        return "COMPLETED".equals(row.get("status")) || "CANCELLED".equals(row.get("status"));
    }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> eligibleJob(Map<String, Object> view, int generation, String phase) {
        if (generation < 1 || !Integer.valueOf(generation).equals(view.get("generation"))
                || !("KYC".equals(phase) ? "KYC_PENDING" : "APPROVED").equals(view.get("state"))
                || view.get("activeJob") == null) return null;
        if (!(view.get("activeJob") instanceof Map<?, ?> raw)) throw SimulationFailure.unavailable();
        var job = (Map<String, Object>) raw;
        if (!Integer.valueOf(generation).equals(job.get("generation")) || !phase.equals(job.get("phase"))
                || !"PENDING".equals(job.get("state"))) return null;
        return job;
    }
    private static int count(Object value) {
        if (!(value instanceof Integer n) || n < 0) throw SimulationFailure.unavailable(); return n;
    }
    private static UUID uuid(Object value) {
        if (!(value instanceof String text)) throw SimulationFailure.unavailable();
        UUID id = UUID.fromString(text); if (!id.toString().equals(text)) throw SimulationFailure.unavailable(); return id;
    }
    @Override public String toString() { return "VirtualDeliveryCoordinator[NON_AUTHORIZING]"; }
}
