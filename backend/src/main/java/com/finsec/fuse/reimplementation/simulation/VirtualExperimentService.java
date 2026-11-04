package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import static com.finsec.fuse.reimplementation.simulation.SimulationRows.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;

/**
 * Explicit synthetic paired orchestration. Reports use VIRTUAL_SIMULATION and can
 * never be mistaken for JAVA_POSTGRES_EXECUTION or measured live model behavior.
 */
public final class VirtualExperimentService {
    private static final String TABLE = "virtual_experiments";
    public enum Environment { BASELINE, FUSE }
    public enum Outcome { PAYMENT_COMMITTED, POLICY_BLOCKED, WAIT_APPROVAL, ENVIRONMENT_ERROR }
    public enum Reason { SYNTHETIC_PAYMENT, SYNTHETIC_POLICY_BLOCK, SYNTHETIC_REVIEW, ENVIRONMENT_UNAVAILABLE }

    public record Case(String caseId, SimulationSpec.KycStatus status, List<UUID> evidenceIds) {
        public Case {
            SimulationSpec.synthetic(caseId); Objects.requireNonNull(status); evidenceIds = List.copyOf(evidenceIds);
            if (evidenceIds.size() > 10 || evidenceIds.stream().distinct().count() != evidenceIds.size()) throw SimulationFailure.invalid();
        }
        Map<String, Object> proposal() {
            return object("status", status.name(), "evidenceIds", evidenceIds.stream().map(UUID::toString).toList());
        }
    }
    public record FixtureSet(String fixtureSetId, List<Case> cases) {
        public FixtureSet {
            SimulationSpec.synthetic(fixtureSetId); cases = List.copyOf(cases);
            if (cases.isEmpty() || cases.size() > 100 || cases.stream().map(Case::caseId).distinct().count() != cases.size())
                throw SimulationFailure.invalid();
        }
    }
    public record Plan(String fixtureSetId, List<String> caseIds, String mode, String modelMode, int repeatCount) {
        public Plan {
            SimulationSpec.synthetic(fixtureSetId); caseIds = List.copyOf(caseIds);
            if (caseIds.isEmpty() || caseIds.size() > 100 || caseIds.stream().distinct().count() != caseIds.size()
                    || !"PAIRED".equals(mode) || !Set.of("REPLAY", "LIVE").contains(modelMode)
                    || repeatCount < 1 || repeatCount > 10) throw SimulationFailure.invalid();
        }
        Map<String, Object> body() {
            return object("fixtureSetId", fixtureSetId, "caseIds", caseIds, "mode", mode, "modelMode", modelMode, "repeatCount", repeatCount);
        }
    }
    public record Observation(Outcome outcome, Reason reason) {
        public Observation {
            Objects.requireNonNull(outcome); Objects.requireNonNull(reason);
            if (!(outcome == Outcome.PAYMENT_COMMITTED && reason == Reason.SYNTHETIC_PAYMENT
                    || outcome == Outcome.POLICY_BLOCKED && reason == Reason.SYNTHETIC_POLICY_BLOCK
                    || outcome == Outcome.WAIT_APPROVAL && reason == Reason.SYNTHETIC_REVIEW
                    || outcome == Outcome.ENVIRONMENT_ERROR && reason == Reason.ENVIRONMENT_UNAVAILABLE))
                throw SimulationFailure.invalid();
        }
    }
    /** Must be a deterministic, side-effect-free synthetic evaluator; there is no default executor. */
    public interface PairEvaluator {
        String mode();
        Observation evaluate(Environment environment, String caseId, int repeat, Map<String, Object> sharedProposal);
    }
    private final TransactionalStore store;
    private final ActionJournal journal;
    private final SimulationAccess access;
    private final Map<String, FixtureSet> fixtures;
    private final PairEvaluator evaluator;
    private final Supplier<UUID> ids;
    private final VirtualDeliveryCoordinator.Notifications delivery;

    public VirtualExperimentService(TransactionalStore store, SimulationAccess access, List<FixtureSet> fixtures,
                                    PairEvaluator evaluator, Supplier<UUID> ids) {
        this(store, access, fixtures, evaluator, ids, null);
    }
    public VirtualExperimentService(TransactionalStore store, SimulationAccess access, List<FixtureSet> fixtures,
            PairEvaluator evaluator, Supplier<UUID> ids, VirtualDeliveryCoordinator.Notifications delivery) {
        this.delivery = delivery;
        this.store = Objects.requireNonNull(store); this.journal = new ActionJournal(store); this.access = Objects.requireNonNull(access);
        this.evaluator = Objects.requireNonNull(evaluator); this.ids = Objects.requireNonNull(ids);
        if (!VirtualTransactionalStore.MODE.equals(evaluator.mode())) throw SimulationFailure.invalid();
        var registered = new LinkedHashMap<String, FixtureSet>();
        for (var set : List.copyOf(fixtures)) if (registered.putIfAbsent(set.fixtureSetId(), set) != null) throw SimulationFailure.invalid();
        this.fixtures = Map.copyOf(registered);
    }

    public Map<String, Object> create(ActorRef actor, UUID action, Plan plan) {
        access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
        if (!"REPLAY".equals(plan.modelMode())) throw SimulationFailure.unavailable(); // No live fallback.
        FixtureSet set = fixtures.get(plan.fixtureSetId());
        if (set == null || !set.cases().stream().map(Case::caseId).toList().containsAll(plan.caseIds())) throw SimulationFailure.invalid();
        return notifyCreated(actor, journal.execute(actor.actorId(), action, "SIM_EXPERIMENT", CanonicalJson.sha256(plan.body()), tx -> {
            UUID id = fresh(tx, TABLE, ids);
            tx.put(TABLE, id.toString(), object("experimentId", id.toString(), "actorId", actor.actorId(), "status", "PENDING",
                    "fixtureSetId", plan.fixtureSetId(), "caseIds", plan.caseIds(), "repeatCount", plan.repeatCount(),
                    "totalPairs", Math.multiplyExact(plan.caseIds().size(), plan.repeatCount()), "completedPairs", 0,
                    "fence", 0L, "activeClaim", null,
                    "caseOutputs", List.of(), "exclusions", List.of(), "modelMode", "REPLAY",
                    "syntheticModelOutputs", true, "liveRobustnessMeasured", false, "resultsSource", "VIRTUAL_SIMULATION"));
            return object("requestId", action.toString(), "workflowId", null, "generation", null, "state", "PENDING",
                    "decision", "ALLOW", "reasonCodes", List.of(), "message", "VIRTUAL_EXPERIMENT_ACCEPTED", "replayed", false,
                    "experimentId", id.toString(), "status", "PENDING", "totalRuns", Math.multiplyExact(2, Math.multiplyExact(plan.caseIds().size(), plan.repeatCount())));
        }));
    }

    private Map<String, Object> notifyCreated(ActorRef actor, Map<String, Object> receipt) {
        if (delivery != null && "PENDING".equals(receipt.get("status"))) {
            try { delivery.experimentCommitted(actor, UUID.fromString((String) receipt.get("experimentId"))); }
            catch (RuntimeException unavailable) { /* The creation is already committed; no dispatch retry here. */ }
        }
        return receipt;
    }

    public enum EffectDisposition { SIDE_EFFECT_FREE_CONFIRMED, UNCERTAIN }
    private enum ExecutionState { CLAIMED, EVALUATING, RECOVERY_BLOCKED }
    public record HandoffRequest(UUID advanceActionId, String expectedExecutionOwner,
            long expectedFence, long expectedLeaseVersion, String newExecutionOwner,
            long now, long leaseUntil, EffectDisposition disposition) {
        public HandoffRequest {
            if (advanceActionId == null || disposition == null || expectedFence < 0 || expectedLeaseVersion < 0)
                throw SimulationFailure.invalid();
            leaseOwner(expectedExecutionOwner); leaseOwner(newExecutionOwner); leaseTimes(now, leaseUntil);
        }
        @Override public String toString() { return "HandoffRequest[REDACTED]"; }
    }
    /** Cooperative in-process handle only; never serialized or accepted from caller maps. */
    public static final class WorkPermit {
        private final VirtualExperimentService service;
        private final LeasedAttempt attempt;
        private WorkPermit(VirtualExperimentService service, LeasedAttempt attempt) {
            this.service = service; this.attempt = attempt;
        }
        @Override public String toString() { return "WorkPermit[REDACTED]"; }
    }
    public static final class EvaluatedPair {
        private final WorkPermit permit;
        private final List<Map<String, Object>> outputs;
        private final boolean error;
        private EvaluatedPair(WorkPermit permit, List<Map<String, Object>> outputs, boolean error) {
            this.permit = permit;
            this.outputs = outputs.stream().map(CanonicalJson::immutableObject).toList();
            this.error = error;
        }
        @Override public String toString() { return "EvaluatedPair[REDACTED]"; }
    }
    public static final class LeaseClaim {
        private final Map<String, Object> receipt;
        private final WorkPermit permit;
        private LeaseClaim(Map<String, Object> receipt, WorkPermit permit) {
            this.receipt = CanonicalJson.immutableObject(receipt); this.permit = permit;
        }
        public Map<String, Object> receipt() { return receipt; }
        public WorkPermit permit() { return permit; }
        @Override public String toString() { return "LeaseClaim[REDACTED]"; }
    }
    public static final class EvaluationOutcome {
        private final Map<String, Object> savedReceipt;
        private final EvaluatedPair evaluatedPair;
        private EvaluationOutcome(Map<String, Object> saved, EvaluatedPair pair) {
            if ((saved == null) == (pair == null)) throw SimulationFailure.invalid();
            savedReceipt = saved == null ? null : CanonicalJson.immutableObject(saved); evaluatedPair = pair;
        }
        public Map<String, Object> savedReceipt() { return savedReceipt; }
        public EvaluatedPair evaluatedPair() { return evaluatedPair; }
        @Override public String toString() { return "EvaluationOutcome[REDACTED]"; }
    }
    private record LeasedAttempt(Attempt original, String actorId, String owner, UUID workToken,
                                 long version, long until, ExecutionState state) {}
    private static final Set<String> LEASE_KEYS = Set.of("claimFormat", "actionId", "actorId", "pairIndex",
            "fence", "proposalSha256", "journalReservationToken", "executionOwner", "workAttemptToken",
            "leaseVersion", "leaseUntil", "executionState");

    /** Explicit caller-time lease admission only; no clock or provider dispatch. */
    public LeaseClaim claimLeased(ActorRef actor, UUID action, UUID experimentId,
                                  String executionOwner, long now, long leaseUntil) {
        if (action == null || experimentId == null) throw SimulationFailure.invalid();
        leaseOwner(executionOwner); leaseTimes(now, leaseUntil);
        access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
        var identity = advanceIdentity(actor.actorId(), action, experimentId);
        try {
            return journal.reservedTransaction(tx -> {
                access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
                var row = require(tx, TABLE, experimentId); requireOwner(actor, row);
                var saved = tx.completed(identity);
                if (saved != null) return new LeaseClaim(saved, null);
                if (row.get("activeClaim") != null) throw SimulationFailure.unavailable();
                if (terminal(row)) {
                    UUID token = leaseToken(); tx.reserve(identity, token);
                    var reply = stepReceipt(action, row); tx.complete(identity, token, reply);
                    return new LeaseClaim(reply, null);
                }
                long nextFence = incrementFence(row);
                UUID journalToken = leaseToken(), workToken = leaseToken();
                if (journalToken.equals(workToken)) throw SimulationFailure.unavailable();
                var original = immutableAttempt(selected(row, action, experimentId, journalToken, nextFence));
                var lease = new LeasedAttempt(original, actor.actorId(), executionOwner, workToken, 0L,
                        leaseUntil, ExecutionState.CLAIMED);
                tx.reserve(identity, journalToken);
                var claimed = changed(row, "fence", nextFence, "activeClaim", leaseRow(lease));
                tx.put(TABLE, experimentId.toString(), claimed);
                return new LeaseClaim(stepReceipt(action, claimed), new WorkPermit(this, lease));
            });
        } catch (ActionJournal.PendingActionException pending) { throw SimulationFailure.unavailable(); }
    }

    /** One dispatch per attempt. Every environment rechecks current state using this SAME time snapshot. */
    public EvaluationOutcome evaluateLeased(ActorRef actor, WorkPermit permit, long now) {
        requirePermit(actor, permit, now);
        var identity = advanceIdentity(actor.actorId(), permit.attempt.original().action(), permit.attempt.original().experimentId());
        Map<String, Object> saved = journal.reservedTransaction(tx -> {
            access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
            var row = require(tx, TABLE, permit.attempt.original().experimentId()); requireOwner(actor, row);
            var completed = tx.completed(identity); if (completed != null) return completed;
            var current = requireLease(row, permit, now, ExecutionState.CLAIMED);
            pendingLease(tx, identity, current.original().token());
            tx.put(TABLE, current.original().experimentId().toString(), changed(row, "activeClaim",
                    leaseRow(withState(current, ExecutionState.EVALUATING))));
            return null;
        });
        if (saved != null) return new EvaluationOutcome(saved, null);
        var outputs = new ArrayList<Map<String, Object>>(); boolean error = false;
        Attempt original = permit.attempt.original();
        for (Environment environment : Environment.values()) {
            saved = journal.reservedTransaction(tx -> {
                access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
                var row = require(tx, TABLE, original.experimentId()); requireOwner(actor, row);
                var completed = tx.completed(identity); if (completed != null) return completed;
                var current = requireLease(row, permit, now, ExecutionState.EVALUATING);
                pendingLease(tx, identity, current.original().token());
                return null;
            });
            if (saved != null) return new EvaluationOutcome(saved, null);
            Observation observation;
            try {
                if (!VirtualTransactionalStore.MODE.equals(evaluator.mode())) throw SimulationFailure.unavailable();
                observation = Objects.requireNonNull(evaluator.evaluate(environment, original.caseId(), original.repeat(), original.proposal()));
                if (!VirtualTransactionalStore.MODE.equals(evaluator.mode())) throw SimulationFailure.unavailable();
                if (!original.proposalHash().equals(CanonicalJson.sha256(original.proposal()))) throw SimulationFailure.invalid();
            } catch (RuntimeException unavailable) {
                observation = new Observation(Outcome.ENVIRONMENT_ERROR, Reason.ENVIRONMENT_UNAVAILABLE);
            }
            error |= observation.outcome() == Outcome.ENVIRONMENT_ERROR;
            outputs.add(object("caseId", original.caseId(), "repeat", original.repeat(), "environment", environment.name(),
                    "outcome", observation.outcome().name(), "reasonCodes", List.of(observation.reason().name()),
                    "sharedProposalHash", original.proposalHash(), "resultsSource", "VIRTUAL_SIMULATION"));
        }
        return new EvaluationOutcome(null, new EvaluatedPair(permit, outputs, error));
    }

    public Map<String, Object> finalizeLeased(ActorRef actor, WorkPermit permit, EvaluatedPair pair, long now) {
        requirePermit(actor, permit, now);
        if (pair == null || pair.permit != permit) throw SimulationFailure.invalid();
        Attempt original = permit.attempt.original();
        var identity = advanceIdentity(actor.actorId(), original.action(), original.experimentId());
        return journal.reservedTransaction(tx -> {
            access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
            var row = require(tx, TABLE, original.experimentId()); requireOwner(actor, row);
            var saved = tx.completed(identity); if (saved != null) return saved;
            var current = requireLease(row, permit, now, ExecutionState.EVALUATING);
            pendingLease(tx, identity, current.original().token());
            if (pair.outputs.size() != Environment.values().length) throw SimulationFailure.unavailable();
            var outputs = new ArrayList<>(rows(row.get("caseOutputs"))); outputs.addAll(pair.outputs);
            var exclusions = new ArrayList<>(rows(row.get("exclusions")));
            if (pair.error) exclusions.add(object("caseId", original.caseId(), "repeat", original.repeat(),
                    "pair", original.caseId() + ":" + original.repeat(), "reason", "ENVIRONMENT_UNAVAILABLE"));
            int completed = original.pairIndex() + 1;
            var finished = changed(row, "completedPairs", completed,
                    "status", completed == integer(row, "totalPairs") ? "COMPLETED" : "RUNNING", "activeClaim", null,
                    "caseOutputs", outputs, "exclusions", exclusions);
            try { tx.complete(identity, original.token(), stepReceipt(original.action(), finished)); }
            catch (ActionJournal.ActionConflictException corrupt) { throw SimulationFailure.unavailable(); }
            tx.put(TABLE, original.experimentId().toString(), finished);
            return CanonicalJson.immutableObject(stepReceipt(original.action(), finished));
        });
    }

    /** Explicit expiry handoff only; returning a permit does not dispatch an evaluator. */
    public LeaseClaim handoffLeased(ActorRef actor, UUID action, UUID experimentId, HandoffRequest request) {
        if (action == null || experimentId == null || request == null) throw SimulationFailure.invalid();
        access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
        var identity = new ActionJournal.ActionIdentity(actor.actorId(), action, "SIM_HANDOFF_EXPERIMENT_LEASE",
                CanonicalJson.sha256(object("experimentId", experimentId.toString(), "advanceActionId", request.advanceActionId().toString(),
                        "expectedExecutionOwner", request.expectedExecutionOwner(), "expectedFence", request.expectedFence(),
                        "expectedLeaseVersion", request.expectedLeaseVersion(), "newExecutionOwner", request.newExecutionOwner(),
                        "now", request.now(), "leaseUntil", request.leaseUntil(), "disposition", request.disposition().name())));
        return journal.reservedTransaction(tx -> {
            access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
            var row = require(tx, TABLE, experimentId); requireOwner(actor, row);
            var saved = tx.completed(identity); if (saved != null) return new LeaseClaim(saved, null);
            var originalIdentity = advanceIdentity(actor.actorId(), request.advanceActionId(), experimentId);
            var completed = tx.completed(originalIdentity);
            if (completed != null) return completeControl(tx, identity, request.advanceActionId(), experimentId,
                    "CURRENT_ACTION_COMPLETED", "ALLOW", null);
            if (!(row.get("activeClaim") instanceof Map<?, ?> claim)
                    || !"VIRTUAL_LEASE_V1".equals(claim.get("claimFormat"))) throw SimulationFailure.invalid();
            var current = storedLease(row, experimentId);
            if (!current.original().action().equals(request.advanceActionId())) throw SimulationFailure.invalid();
            if (terminal(row) || current.state() == ExecutionState.RECOVERY_BLOCKED
                    || !current.owner().equals(request.expectedExecutionOwner()) || current.original().fence() != request.expectedFence()
                    || current.version() != request.expectedLeaseVersion() || request.now() < current.until())
                throw SimulationFailure.unavailable();
            pendingLease(tx, originalIdentity, current.original().token());
            long version = checkedNext(current.version());
            LeasedAttempt next;
            if (request.disposition() == EffectDisposition.UNCERTAIN) {
                next = new LeasedAttempt(current.original(), current.actorId(), current.owner(), current.workToken(),
                        version, current.until(), ExecutionState.RECOVERY_BLOCKED);
            } else {
                long nextFence = incrementFence(row);
                UUID workToken = leaseToken();
                if (workToken.equals(current.original().token()) || workToken.equals(current.workToken()))
                    throw SimulationFailure.unavailable();
                var original = immutableAttempt(selected(row, request.advanceActionId(), experimentId,
                        current.original().token(), nextFence));
                next = new LeasedAttempt(original, current.actorId(), request.newExecutionOwner(), workToken,
                        version, request.leaseUntil(), ExecutionState.CLAIMED);
            }
            var changed = changed(row, "fence", next.original().fence(), "activeClaim", leaseRow(next));
            LeaseClaim result = completeControl(tx, identity, request.advanceActionId(), experimentId,
                    request.disposition() == EffectDisposition.UNCERTAIN ? "RECOVERY_EFFECT_UNCONFIRMED" : "LEASE_HANDOFF_RECORDED",
                    request.disposition() == EffectDisposition.UNCERTAIN ? "DENY" : "ALLOW", next);
            tx.put(TABLE, experimentId.toString(), changed);
            return result;
        });
    }

    private LeaseClaim completeControl(ActionJournal.ReservedTx tx, ActionJournal.ActionIdentity identity,
            UUID originalAction, UUID experimentId, String reason, String decision, LeasedAttempt permit) {
        UUID token = leaseToken();
        try { tx.reserve(identity, token); }
        catch (ActionJournal.PendingActionException pending) { throw SimulationFailure.unavailable(); }
        var receipt = object("requestId", identity.requestId().toString(), "experimentId", experimentId.toString(),
                "advanceActionId", originalAction.toString(), "decision", decision, "reasonCodes", List.of(reason), "replayed", false);
        tx.complete(identity, token, receipt);
        return new LeaseClaim(receipt, permit == null || permit.state() == ExecutionState.RECOVERY_BLOCKED
                ? null : new WorkPermit(this, permit));
    }
    private UUID leaseToken() {
        try { return Objects.requireNonNull(ids.get()); }
        catch (RuntimeException unavailable) { throw SimulationFailure.unavailable(); }
    }
    private static long checkedNext(long value) {
        try { return Math.incrementExact(value); }
        catch (ArithmeticException overflow) { throw SimulationFailure.unavailable(); }
    }
    private static void leaseOwner(String value) {
        try { SimulationSpec.synthetic(value); if (value.isBlank()) throw SimulationFailure.invalid(); }
        catch (IllegalArgumentException invalid) { throw SimulationFailure.invalid(); }
    }
    private static void leaseTimes(long now, long until) {
        if (now < 0 || until < 0 || until <= now) throw SimulationFailure.invalid();
    }
    private void requirePermit(ActorRef actor, WorkPermit permit, long now) {
        access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
        if (permit == null || permit.service != this || now < 0) throw SimulationFailure.invalid();
        if (!permit.attempt.actorId().equals(actor.actorId())) throw SimulationFailure.forbidden();
    }
    private static Attempt immutableAttempt(Attempt value) {
        return new Attempt(value.action(), value.experimentId(), value.token(), value.fence(), value.pairIndex(),
                value.caseId(), value.repeat(), CanonicalJson.immutableObject(value.proposal()), value.proposalHash());
    }
    private static LeasedAttempt withState(LeasedAttempt value, ExecutionState state) {
        return new LeasedAttempt(value.original(), value.actorId(), value.owner(), value.workToken(), value.version(), value.until(), state);
    }
    private static Map<String, Object> leaseRow(LeasedAttempt value) {
        Attempt a = value.original();
        return object("claimFormat", "VIRTUAL_LEASE_V1", "actionId", a.action().toString(), "actorId", value.actorId(),
                "pairIndex", a.pairIndex(), "fence", a.fence(), "proposalSha256", a.proposalHash(),
                "journalReservationToken", a.token().toString(), "executionOwner", value.owner(),
                "workAttemptToken", value.workToken().toString(), "leaseVersion", value.version(), "leaseUntil", value.until(),
                "executionState", value.state().name());
    }
    @SuppressWarnings("unchecked")
    private LeasedAttempt storedLease(Map<String, Object> row, UUID experimentId) {
        try {
            if (!(row.get("activeClaim") instanceof Map<?, ?> raw) || !raw.keySet().equals(LEASE_KEYS)
                    || !"VIRTUAL_LEASE_V1".equals(raw.get("claimFormat"))) throw SimulationFailure.unavailable();
            var claim = (Map<String, Object>) raw;
            if (!row.get("actorId").equals(claim.get("actorId")) || !Objects.equals(row.get("fence"), claim.get("fence"))
                    || !Objects.equals(row.get("completedPairs"), claim.get("pairIndex"))) throw SimulationFailure.unavailable();
            if (!(claim.get("actorId") instanceof String actorId) || !(claim.get("executionOwner") instanceof String owner))
                throw SimulationFailure.unavailable();
            leaseOwner(owner);
            long version = nonnegativeLong(claim.get("leaseVersion")), until = nonnegativeLong(claim.get("leaseUntil"));
            UUID journalToken = canonicalUuid(claim.get("journalReservationToken")), workToken = canonicalUuid(claim.get("workAttemptToken"));
            if (journalToken.equals(workToken)) throw SimulationFailure.unavailable();
            ExecutionState state = ExecutionState.valueOf((String) claim.get("executionState"));
            Attempt original = immutableAttempt(selected(row, canonicalUuid(claim.get("actionId")), experimentId, journalToken, fence(row)));
            if (!original.proposalHash().equals(claim.get("proposalSha256"))) throw SimulationFailure.unavailable();
            return new LeasedAttempt(original, actorId, owner, workToken, version, until, state);
        } catch (RuntimeException malformed) { throw SimulationFailure.unavailable(); }
    }
    private static long nonnegativeLong(Object value) {
        if (!(value instanceof Long number) || number < 0) throw SimulationFailure.unavailable();
        return number;
    }
    private LeasedAttempt requireLease(Map<String, Object> row, WorkPermit permit, long now, ExecutionState state) {
        var current = storedLease(row, permit.attempt.original().experimentId());
        if (terminal(row) || current.state() != state || now >= current.until()
                || !current.equals(withState(permit.attempt, state))) throw SimulationFailure.unavailable();
        return current;
    }
    private static void pendingLease(ActionJournal.ReservedTx tx, ActionJournal.ActionIdentity identity, UUID token) {
        // Exact nonmutating reservation-token validation must be supplied by the journal facade.
        try { tx.requirePending(identity, token); }
        catch (ActionJournal.ActionConflictException corrupt) { throw SimulationFailure.unavailable(); }
    }

    private record Attempt(UUID action, UUID experimentId, UUID token, long fence, int pairIndex,
                           String caseId, int repeat, Map<String, Object> proposal, String proposalHash) {}
    private record Claim(Map<String, Object> receipt, Attempt attempt) {}

    /** Advances one synthetic pair outside the store lock. A pending attempt is not retried. */
    public Map<String, Object> advance(ActorRef actor, UUID action, UUID experimentId) {
        access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
        var identity = advanceIdentity(actor.actorId(), action, experimentId);
        Claim claim;
        try {
            claim = journal.reservedTransaction(tx -> {
                access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
                var row = require(tx, TABLE, experimentId); requireOwner(actor, row);
                var saved = tx.completed(identity);
                if (saved != null) return new Claim(saved, null);
                if (terminal(row)) {
                    if (row.get("activeClaim") != null) throw SimulationFailure.unavailable();
                    UUID token = nextToken(); tx.reserve(identity, token);
                    var reply = stepReceipt(action, row); tx.complete(identity, token, reply);
                    return new Claim(reply, null);
                }
                if (row.get("activeClaim") != null) throw SimulationFailure.unavailable();
                long fence = incrementFence(row); // Checked before any reservation.
                Attempt attempt = selected(row, action, experimentId, nextToken(), fence);
                tx.reserve(identity, attempt.token());
                tx.put(TABLE, experimentId.toString(), changed(row, "fence", fence, "activeClaim",
                        object("actionId", action.toString(), "actorId", actor.actorId(), "pairIndex", attempt.pairIndex(),
                                "fence", fence, "proposalSha256", attempt.proposalHash(), "attemptToken", attempt.token().toString())));
                return new Claim(null, attempt);
            });
        } catch (ActionJournal.PendingActionException pending) { throw SimulationFailure.unavailable(); }
        if (claim.receipt() != null) return claim.receipt();
        Attempt attempt = claim.attempt();
        var outputs = new ArrayList<Map<String, Object>>(); boolean error = false;
        for (Environment environment : Environment.values()) {
            if (!stillCurrent(actor, attempt)) return finish(actor, identity, attempt, List.of(), false);
            Observation observation;
            try {
                if (!VirtualTransactionalStore.MODE.equals(evaluator.mode())) throw SimulationFailure.unavailable();
                observation = Objects.requireNonNull(evaluator.evaluate(environment, attempt.caseId(), attempt.repeat(), attempt.proposal()));
                if (!VirtualTransactionalStore.MODE.equals(evaluator.mode())) throw SimulationFailure.unavailable();
                if (!attempt.proposalHash().equals(CanonicalJson.sha256(attempt.proposal()))) throw SimulationFailure.invalid();
            } catch (RuntimeException unavailable) {
                observation = new Observation(Outcome.ENVIRONMENT_ERROR, Reason.ENVIRONMENT_UNAVAILABLE);
            }
            // Error deliberately propagates, leaving an explicitly cancellable pending claim.
            error |= observation.outcome() == Outcome.ENVIRONMENT_ERROR;
            outputs.add(object("caseId", attempt.caseId(), "repeat", attempt.repeat(), "environment", environment.name(),
                    "outcome", observation.outcome().name(), "reasonCodes", List.of(observation.reason().name()),
                    "sharedProposalHash", attempt.proposalHash(), "resultsSource", "VIRTUAL_SIMULATION"));
        }
        return finish(actor, identity, attempt, List.copyOf(outputs), error);
    }

    /** Logical cancellation fences late results; it does not terminate a provider or recover a process. */
    public Map<String, Object> cancel(ActorRef actor, UUID action, UUID experimentId) {
        access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
        var identity = new ActionJournal.ActionIdentity(actor.actorId(), action, "SIM_CANCEL_EXPERIMENT", bodyHash(experimentId));
        try {
            return journal.reservedTransaction(tx -> {
                access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
                var row = require(tx, TABLE, experimentId); requireOwner(actor, row);
                var saved = tx.completed(identity); if (saved != null) return saved;
                if (terminal(row)) {
                    if (row.get("activeClaim") != null) throw SimulationFailure.unavailable();
                    UUID token = nextToken(); tx.reserve(identity, token);
                    var reply = stepReceipt(action, row); tx.complete(identity, token, reply); return reply;
                }
                long fence = incrementFence(row); // Exhaustion cannot mutate either receipt.
                Attempt active = row.get("activeClaim") == null ? null : storedAttempt(row, experimentId);
                UUID token = nextToken(); tx.reserve(identity, token);
                var cancelled = changed(row, "status", "CANCELLED", "fence", fence, "activeClaim", null);
                if (active != null) {
                    try {
                        tx.complete(advanceIdentity(actor.actorId(), active.action(), experimentId), active.token(),
                                stepReceipt(active.action(), cancelled));
                    } catch (ActionJournal.ActionConflictException corruptClaim) { throw SimulationFailure.unavailable(); }
                }
                tx.put(TABLE, experimentId.toString(), cancelled);
                var reply = stepReceipt(action, cancelled); tx.complete(identity, token, reply); return reply;
            });
        } catch (ActionJournal.PendingActionException pending) { throw SimulationFailure.unavailable(); }
    }

    private Map<String, Object> finish(ActorRef actor, ActionJournal.ActionIdentity identity, Attempt attempt,
                                     List<Map<String, Object>> pairOutputs, boolean error) {
        access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
        return journal.reservedTransaction(tx -> {
            access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
            var row = require(tx, TABLE, attempt.experimentId()); requireOwner(actor, row);
            var saved = tx.completed(identity); if (saved != null) return saved;
            requireSameAttempt(row, attempt);
            if (pairOutputs.size() != Environment.values().length) throw SimulationFailure.unavailable();
            var outputs = new ArrayList<>(rows(row.get("caseOutputs"))); outputs.addAll(pairOutputs);
            var exclusions = new ArrayList<>(rows(row.get("exclusions")));
            if (error) exclusions.add(object("caseId", attempt.caseId(), "repeat", attempt.repeat(),
                    "pair", attempt.caseId() + ":" + attempt.repeat(), "reason", "ENVIRONMENT_UNAVAILABLE"));
            int completed = attempt.pairIndex() + 1;
            var finished = changed(row, "completedPairs", completed,
                    "status", completed == integer(row, "totalPairs") ? "COMPLETED" : "RUNNING",
                    "activeClaim", null, "caseOutputs", outputs, "exclusions", exclusions);
            try { tx.complete(identity, attempt.token(), stepReceipt(attempt.action(), finished)); }
            catch (ActionJournal.ActionConflictException corruptClaim) { throw SimulationFailure.unavailable(); }
            tx.put(TABLE, attempt.experimentId().toString(), finished);
            return stepReceipt(attempt.action(), finished);
        });
    }

    private boolean stillCurrent(ActorRef actor, Attempt attempt) {
        access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
        return store.transaction(tx -> {
            access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
            var row = require(tx, TABLE, attempt.experimentId()); requireOwner(actor, row);
            if ("CANCELLED".equals(row.get("status"))) return false;
            requireSameAttempt(row, attempt); return true;
        });
    }
    private void requireSameAttempt(Map<String, Object> row, Attempt expected) {
        if (terminal(row) || !expected.equals(storedAttempt(row, expected.experimentId()))) throw SimulationFailure.unavailable();
    }
    @SuppressWarnings("unchecked")
    private Attempt storedAttempt(Map<String, Object> row, UUID experimentId) {
        try {
            if (row.get("activeClaim") instanceof Map<?, ?> leased && "VIRTUAL_LEASE_V1".equals(leased.get("claimFormat")))
                return storedLease(row, experimentId).original();
            if (!(row.get("activeClaim") instanceof Map<?, ?> raw)
                    || !raw.keySet().equals(Set.of("actionId", "actorId", "pairIndex", "fence", "proposalSha256", "attemptToken")))
                throw SimulationFailure.unavailable();
            var claim = (Map<String, Object>) raw;
            if (!row.get("actorId").equals(claim.get("actorId")) || !Objects.equals(row.get("fence"), claim.get("fence"))
                    || !Objects.equals(row.get("completedPairs"), claim.get("pairIndex"))) throw SimulationFailure.unavailable();
            Attempt active = selected(row, canonicalUuid(claim.get("actionId")), experimentId,
                    canonicalUuid(claim.get("attemptToken")), fence(row));
            if (!active.proposalHash().equals(claim.get("proposalSha256"))) throw SimulationFailure.unavailable();
            return active;
        } catch (SimulationFailure fixed) { throw fixed; }
        catch (RuntimeException malformed) { throw SimulationFailure.unavailable(); }
    }
    private Attempt selected(Map<String, Object> row, UUID action, UUID experimentId, UUID token, long fence) {
        int completed = integer(row, "completedPairs"), repeats = integer(row, "repeatCount");
        if (completed < 0 || completed >= integer(row, "totalPairs") || repeats < 1) throw SimulationFailure.unavailable();
        String caseId = strings(row.get("caseIds")).get(completed / repeats);
        Case selected = fixtures.get((String) row.get("fixtureSetId")).cases().stream()
                .filter(c -> c.caseId().equals(caseId)).findFirst().orElseThrow();
        Map<String, Object> shared = selected.proposal();
        return new Attempt(action, experimentId, token, fence, completed, caseId, completed % repeats + 1,
                shared, CanonicalJson.sha256(shared));
    }
    private static UUID canonicalUuid(Object value) {
        if (!(value instanceof String text) || !text.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
            throw SimulationFailure.unavailable();
        return UUID.fromString(text);
    }
    private static boolean terminal(Map<String, Object> row) {
        return "CANCELLED".equals(row.get("status")) || integer(row, "completedPairs") >= integer(row, "totalPairs");
    }
    // A checked long is an internal finite representation, not an operational time or risk value.
    private static long fence(Map<String, Object> row) {
        Object value = row.get("fence");
        if (!(value instanceof Long) || (Long) value < 0) throw SimulationFailure.unavailable();
        return (Long) value;
    }
    private static long incrementFence(Map<String, Object> row) {
        try { return Math.incrementExact(fence(row)); }
        catch (ArithmeticException exhausted) { throw SimulationFailure.unavailable(); }
    }
    private UUID nextToken() { return Objects.requireNonNull(ids.get()); }
    private static String bodyHash(UUID id) { return CanonicalJson.sha256(object("experimentId", id.toString())); }
    private static ActionJournal.ActionIdentity advanceIdentity(String actorId, UUID action, UUID id) {
        return new ActionJournal.ActionIdentity(actorId, action, "SIM_ADVANCE_EXPERIMENT", bodyHash(id));
    }
    public Map<String, Object> get(ActorRef actor, UUID id) {
        access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
        return store.transaction(tx -> {
            var row = require(tx, TABLE, id); requireOwner(actor, row);
            var publicRow = new LinkedHashMap<String, Object>(row); publicRow.remove("actorId");
            publicRow.remove("activeClaim"); publicRow.remove("fence");
            publicRow.put("progress", object("completedPairs", row.get("completedPairs"), "totalPairs", row.get("totalPairs")));
            publicRow.put("metrics", object("completedPairs", row.get("completedPairs"), "excludedPairs", rows(row.get("exclusions")).size(),
                    "eligiblePairs", integer(row, "completedPairs") - rows(row.get("exclusions")).size(),
                    "syntheticModelOutputs", true, "liveRobustnessMeasured", false));
            publicRow.put("executionMode", VirtualTransactionalStore.MODE);
            return CanonicalJson.immutableObject(publicRow);
        });
    }
    public List<Map<String, Object>> fixtureMetadata(ActorRef actor) {
        access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
        return fixtures.values().stream().sorted(java.util.Comparator.comparing(FixtureSet::fixtureSetId))
                .map(set -> object("fixtureSetId", set.fixtureSetId(), "caseIds", set.cases().stream().map(Case::caseId).toList(),
                        "modelModes", List.of("REPLAY"), "resultsSource", "VIRTUAL_SIMULATION")).toList();
    }
    private static void requireOwner(ActorRef actor, Map<String, Object> row) {
        if (!actor.actorId().equals(row.get("actorId"))) throw SimulationFailure.forbidden();
    }
    private static Map<String, Object> stepReceipt(UUID action, Map<String, Object> row) {
        return object("requestId", action.toString(), "experimentId", row.get("experimentId"), "status", row.get("status"),
                "completedPairs", row.get("completedPairs"), "replayed", false, "resultsSource", "VIRTUAL_SIMULATION");
    }
    @SuppressWarnings("unchecked") private static List<Map<String, Object>> rows(Object value) {
        if (!(value instanceof List<?> list) || list.stream().anyMatch(v -> !(v instanceof Map<?, ?>))) throw SimulationFailure.invalid();
        return (List<Map<String, Object>>) value;
    }
}
