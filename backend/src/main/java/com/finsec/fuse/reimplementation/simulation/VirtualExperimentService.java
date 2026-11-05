package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.time.Instant;
import com.finsec.fuse.reimplementation.auth.LocalVirtualAdmissionContext;
import com.finsec.fuse.reimplementation.auth.LocalVirtualTargetRegistry;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import com.finsec.fuse.reimplementation.simulation.VirtualExperimentMetricsProjection.ExpectedCase;
import com.finsec.fuse.reimplementation.simulation.VirtualExperimentMetricsProjection.MeasuredArm;
import com.finsec.fuse.reimplementation.simulation.VirtualExperimentMetricsProjection.ConfigBinding;
import com.finsec.fuse.reimplementation.simulation.VirtualExperimentMetricsProjection.ArmBinding;
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
    /** Explicit opt-in precommitted measurements; no old Outcome is converted into an expected result. */
    public record MeasuredFixture(String fixtureSetId, List<ExpectedCase> cases, ConfigBinding configuration,
            Map<String, String> expectedPairedInputHashes, int maximumPairs) {
        public MeasuredFixture {
            SimulationSpec.synthetic(fixtureSetId); Objects.requireNonNull(configuration);
            cases = List.copyOf(cases); expectedPairedInputHashes = Map.copyOf(expectedPairedInputHashes);
            var ids = new java.util.LinkedHashSet<String>();
            for (var c : cases) if (!ids.add(c.caseId())) throw SimulationFailure.invalid();
            if (maximumPairs < 1 || !ids.equals(expectedPairedInputHashes.keySet())
                    || expectedPairedInputHashes.values().stream().anyMatch(h -> !SimulationSpec.hash(h))) throw SimulationFailure.invalid();
        }
        @Override public String toString() { return "MeasuredFixture[REDACTED]"; }
    }
    /** A null arm explicitly means unavailable measurement, never a zero or guessed expectation. */
    public record MeasuredObservation(Observation observation, MeasuredArm arm, String sharedProposalHash) {
        public MeasuredObservation {
            Objects.requireNonNull(observation); if (!SimulationSpec.hash(sharedProposalHash)) throw SimulationFailure.invalid();
        }
        @Override public String toString() { return "MeasuredObservation[REDACTED]"; }
    }
    public interface MeasuredPairEvaluator extends PairEvaluator {
        List<MeasuredFixture> measuredFixtures();
        MeasuredObservation evaluateMeasured(Environment environment, String caseId, int repeat,
                Map<String, Object> immutableProposal, String sharedProposalHash);
    }
    private record MeasurementContext(Map<String, Object> plan) { }
    private record EvaluatedArm(Observation observation, Map<String, Object> measurement) { }
    private final TransactionalStore store;
    private final ActionJournal journal;
    private final SimulationAccess access;
    private final Map<String, FixtureSet> fixtures;
    private final PairEvaluator evaluator;
    private final Map<String, MeasuredFixture> measuredProfiles;
    private final Supplier<UUID> ids;
    private final VirtualDeliveryCoordinator.Notifications delivery;
    private final LocalVirtualAdmissionContext creationContext;

    public VirtualExperimentService(TransactionalStore store, SimulationAccess access, List<FixtureSet> fixtures,
                                    PairEvaluator evaluator, Supplier<UUID> ids) {
        this(store, access, fixtures, evaluator, ids, null);
    }
    public VirtualExperimentService(TransactionalStore store, SimulationAccess access, List<FixtureSet> fixtures,
            PairEvaluator evaluator, Supplier<UUID> ids, VirtualDeliveryCoordinator.Notifications delivery) {
        this(store, access, fixtures, evaluator, ids, delivery, null);
    }
    public VirtualExperimentService(TransactionalStore store, SimulationAccess access, List<FixtureSet> fixtures,
            PairEvaluator evaluator, Supplier<UUID> ids, VirtualDeliveryCoordinator.Notifications delivery,
            LocalVirtualAdmissionContext creationContext) {
        this.creationContext = creationContext;
        this.delivery = delivery;
        this.store = Objects.requireNonNull(store); this.journal = new ActionJournal(store); this.access = Objects.requireNonNull(access);
        this.evaluator = Objects.requireNonNull(evaluator); this.ids = Objects.requireNonNull(ids);
        if (!VirtualTransactionalStore.MODE.equals(evaluator.mode())) throw SimulationFailure.invalid();
        var registered = new LinkedHashMap<String, FixtureSet>();
        for (var set : List.copyOf(fixtures)) if (registered.putIfAbsent(set.fixtureSetId(), set) != null) throw SimulationFailure.invalid();
        this.fixtures = Map.copyOf(registered);
        var profiles = new LinkedHashMap<String, MeasuredFixture>();
        if (evaluator instanceof MeasuredPairEvaluator measured) {
            for (var profile : List.copyOf(measured.measuredFixtures())) {
                var fixture = registered.get(profile.fixtureSetId());
                if (fixture == null || profiles.putIfAbsent(profile.fixtureSetId(), profile) != null
                        || !new java.util.HashSet<>(fixture.cases().stream().map(Case::caseId).toList())
                            .equals(new java.util.HashSet<>(profile.cases().stream().map(ExpectedCase::caseId).toList())))
                    throw SimulationFailure.invalid();
            }
        }
        measuredProfiles = Map.copyOf(profiles);
    }

    public Map<String, Object> create(ActorRef actor, UUID action, Plan plan) {
        access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
        return notifyCreated(actor, createCommitted(actor, action, plan, null));
    }

    private Map<String, Object> createCommitted(ActorRef actor, UUID action, Plan plan, CreationReference owner) {
        if (!"REPLAY".equals(plan.modelMode())) throw SimulationFailure.unavailable(); // No live fallback.
        FixtureSet set = fixtures.get(plan.fixtureSetId());
        if (set == null || !set.cases().stream().map(Case::caseId).toList().containsAll(plan.caseIds())) throw SimulationFailure.invalid();
        var measurement = measurementPlan(plan);
        return journal.execute(actor.actorId(), action, "SIM_EXPERIMENT", CanonicalJson.sha256(creationPayload(plan.body(), measurement)), tx -> {
            UUID id = fresh(tx, TABLE, ids);
            tx.put(TABLE, id.toString(), object("experimentId", id.toString(), "actorId", actor.actorId(), "status", "PENDING",
                    "fixtureSetId", plan.fixtureSetId(), "caseIds", plan.caseIds(), "repeatCount", plan.repeatCount(),
                    "totalPairs", Math.multiplyExact(plan.caseIds().size(), plan.repeatCount()), "completedPairs", 0,
                    "fence", 0L, "activeClaim", null,
                    "caseOutputs", List.of(), "exclusions", List.of(), "modelMode", "REPLAY",
                    "syntheticModelOutputs", true, "liveRobustnessMeasured", false, "resultsSource", "VIRTUAL_SIMULATION"));
            if (owner != null) {
                var row = require(tx, TABLE, id);
                tx.put(TABLE, id.toString(), changed(row, "creationOwner", ownerMetadata(owner)));
            }
            if (measurement != null) {
                var row = require(tx, TABLE, id);
                tx.put(TABLE, id.toString(), changed(row, "measurementPlan", measurement,
                        "measurementCreateRequestId", action.toString(), "measuredArms", List.of()));
            }
            return object("requestId", action.toString(), "workflowId", null, "generation", null, "state", "PENDING",
                    "decision", "ALLOW", "reasonCodes", List.of(), "message", "VIRTUAL_EXPERIMENT_ACCEPTED", "replayed", false,
                    "experimentId", id.toString(), "status", "PENDING", "totalRuns", Math.multiplyExact(2, Math.multiplyExact(plan.caseIds().size(), plan.repeatCount())));
        });
    }

    /** Explicit collection admission; does not dispatch while the request admission is live. */
    public CreationResult createForDelegation(ActorRef actor, UUID action, Plan plan,
            LocalVirtualTargetRegistry.CollectionAdmission collection, Instant now) {
        if (creationContext == null || collection == null || now == null) throw SimulationFailure.unavailable();
        var admission = creationContext.current();
        if (admission == null || actor == null || !admission.actor().equals(actor)) throw SimulationFailure.unavailable();
        collection.requireOwner(creationContext);
        collection.requireCreation(actor, plan.fixtureSetId(), now);
        var identity = new ActionJournal.ActionIdentity(actor.actorId(), action, "SIM_EXPERIMENT",
                CanonicalJson.sha256(creationPayload(plan.body(), measurementPlan(plan))));
        var original = new CreationReference(this, null, identity, admission.credential(), actor.actorId());
        var receipt = createCommitted(actor, action, plan, original);
        CreationProof proof = null;
        // Replays retain their known reply but never mint a new owner delegation.
        if (Boolean.FALSE.equals(receipt.get("replayed"))) {
            try {
                collection.requireOwner(creationContext);
                collection.requireCreation(actor, plan.fixtureSetId(), now);
                if (creationContext.current() != admission) throw SimulationFailure.unavailable();
                var reference = new CreationReference(this, UUID.fromString((String) receipt.get("experimentId")),
                        identity, admission.credential(), actor.actorId());
                requireCurrentCreation(reference);
                proof = new CreationProof(reference, admission);
            } catch (RuntimeException unavailable) { /* Creation remains committed; no automatic retry. */ }
        }
        return new CreationResult(receipt, proof);
    }

    public static final class CreationResult {
        private final Map<String, Object> receipt;
        private final CreationProof proof;
        private CreationResult(Map<String, Object> receipt, CreationProof proof) {
            this.receipt = CanonicalJson.immutableObject(receipt); this.proof = proof;
        }
        public Map<String, Object> receipt() { return receipt; }
        public CreationProof proof() { return proof; }
        @Override public String toString() { return "CreationResult[REDACTED]"; }
    }
    public static final class CreationProof {
        private final CreationReference reference;
        private final LocalVirtualAdmissionContext.Admission owner;
        private CreationProof(CreationReference reference, LocalVirtualAdmissionContext.Admission owner) {
            this.reference = reference; this.owner = owner;
        }
        public CreationReference reference() { return reference; }
        public boolean createdBy(LocalVirtualAdmissionContext.Admission expected) { return owner == expected; }
        @Override public String toString() { return "CreationProof[REDACTED]"; }
    }
    public static final class CreationReference {
        private final VirtualExperimentService issuer;
        private final UUID experimentId;
        private final ActionJournal.ActionIdentity identity;
        private final LocalVirtualAdmissionContext.CredentialReference credential;
        private final String alias;
        private CreationReference(VirtualExperimentService issuer, UUID experimentId, ActionJournal.ActionIdentity identity,
                LocalVirtualAdmissionContext.CredentialReference credential, String alias) {
            this.issuer = issuer; this.experimentId = experimentId; this.identity = identity; this.credential = credential; this.alias = alias;
        }
        public UUID experimentId() { return experimentId; }
        public ActionJournal.ActionIdentity creationIdentity() { return identity; }
        public LocalVirtualAdmissionContext.CredentialReference ownerCredential() { return credential; }
        public String creationActorAlias() { return alias; }
        public boolean issuedBy(Object expected) { return issuer == expected; }
        @Override public String toString() { return "CreationReference[REDACTED]"; }
    }
    private static Map<String, Object> ownerMetadata(CreationReference ref) {
        var c = ref.credential;
        return object("tokenId", c.tokenId().toString(), "principalId", c.principalId().toString(),
                "tokenRevision", c.tokenRevision(), "bindingRevision", c.bindingRevision(),
                "issuedAt", c.issuedAt().toString(), "expiresAt", c.expiresAt().toString(),
                "actorId", ref.alias, "requestId", ref.identity.requestId().toString(),
                "operation", ref.identity.operation(), "canonicalBodyHash", ref.identity.canonicalBodyHash());
    }
    /** Rejoins one immutable committed snapshot; never publishes a read-only transaction. */
    public void requireCurrentCreation(CreationReference reference) {
        try {
            if (reference == null || !reference.issuedBy(this) || reference.experimentId == null) throw SimulationFailure.unavailable();
            var snapshot = store.snapshot();
            var row = snapshot.getOrDefault(TABLE, Map.of()).get(reference.experimentId.toString());
            var id = reference.identity;
            var global = snapshot.getOrDefault(ActionJournal.TABLE, Map.of()).get(id.requestId().toString());
            if (row == null || global == null || !reference.alias.equals(row.get("actorId"))
                    || !reference.experimentId.toString().equals(row.get("experimentId"))
                    || !ownerMetadata(reference).equals(row.get("creationOwner"))
                    || !global.keySet().equals(Set.of("actorId", "requestId", "operation", "canonicalBodyHash", "reply", "persistenceMode", "durable"))
                    || !id.actorId().equals(global.get("actorId")) || !id.requestId().toString().equals(global.get("requestId"))
                    || !id.operation().equals(global.get("operation")) || !id.canonicalBodyHash().equals(global.get("canonicalBodyHash"))
                    || !VirtualTransactionalStore.MODE.equals(global.get("persistenceMode")) || !Boolean.FALSE.equals(global.get("durable")))
                throw SimulationFailure.unavailable();
            if (!(global.get("reply") instanceof Map<?, ?> reply)
                    || !reference.experimentId.toString().equals(reply.get("experimentId"))
                    || !id.requestId().toString().equals(reply.get("requestId"))
                    || !"PENDING".equals(reply.get("status")) || !"ALLOW".equals(reply.get("decision"))) throw SimulationFailure.unavailable();
            var plan = storedPlan(row);
            if (!Objects.equals(reply.get("totalRuns"), Math.multiplyExact(2, Math.multiplyExact(plan.caseIds().size(), plan.repeatCount())))
                    || !"PENDING".equals(reply.get("state"))) throw SimulationFailure.unavailable();
            if (!id.canonicalBodyHash().equals(CanonicalJson.sha256(creationPayload(plan.body(),
                    row.get("measurementPlan") instanceof Map<?, ?> ? castMeasurementPlan(row.get("measurementPlan")) : null))))
                throw SimulationFailure.unavailable();
        } catch (RuntimeException unavailable) { throw SimulationFailure.unavailable(); }
    }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMeasurementPlan(Object value) { return (Map<String, Object>) value; }

    private Map<String, Object> notifyCreated(ActorRef actor, Map<String, Object> receipt) {
        if (delivery != null && "PENDING".equals(receipt.get("status"))) {
            try { delivery.experimentCommitted(actor, UUID.fromString((String) receipt.get("experimentId"))); }
            catch (RuntimeException unavailable) { /* The creation is already committed; no dispatch retry here. */ }
        }
        return receipt;
    }

    private Map<String, Object> measurementPlan(Plan request) {
        var profile = measuredProfiles.get(request.fixtureSetId());
        if (profile == null) return null;
        if (request.caseIds().size() > profile.maximumPairs() / request.repeatCount()) throw SimulationFailure.invalid();
        var kinds = new LinkedHashMap<String, ExpectedCase>();
        for (var c : profile.cases()) kinds.put(c.caseId(), c);
        var selected = new ArrayList<Map<String, Object>>();
        var expected = new LinkedHashMap<String, Object>(); var shared = new LinkedHashMap<String, Object>();
        for (String id : request.caseIds()) {
            var c = kinds.get(id); if (c == null) throw SimulationFailure.invalid();
            selected.add(object("caseId", id, "kind", c.kind().name()));
            expected.put(id, profile.expectedPairedInputHashes().get(id));
            var actual = fixtures.get(request.fixtureSetId()).cases().stream().filter(value -> id.equals(value.caseId())).findFirst().orElseThrow();
            shared.put(id, CanonicalJson.sha256(actual.proposal()));
        }
        return object("version", 1, "fixtureSetId", request.fixtureSetId(), "cases", selected,
                "configuration", configMap(profile.configuration()), "expectedPairedInputHashes", expected,
                "sharedProposalHashes", shared, "maximumPairs", profile.maximumPairs());
    }
    private static Map<String, Object> creationPayload(Map<String, Object> original, Map<String, Object> measurement) {
        return measurement == null ? original : changed(original, "measurementPlan", measurement);
    }
    private static Map<String, Object> configMap(ConfigBinding c) {
        return object("fixtureHash", c.fixtureHash(), "mockReviewerVersion", c.mockReviewerVersion(),
                "promptVersion", c.promptVersion(), "model", c.model(), "policyVersion", c.policyVersion());
    }
    private static ConfigBinding config(Object value) {
        var c = metricMap(value);
        if (!c.keySet().equals(Set.of("fixtureHash", "mockReviewerVersion", "promptVersion", "model", "policyVersion"))) throw SimulationFailure.unavailable();
        return new ConfigBinding(metricText(c,"fixtureHash"),metricText(c,"mockReviewerVersion"),metricText(c,"promptVersion"),metricText(c,"model"),metricText(c,"policyVersion"));
    }
    private static Plan storedPlan(Map<String, Object> row) {
        return new Plan(metricText(row,"fixtureSetId"), strings(row.get("caseIds")), "PAIRED", metricText(row,"modelMode"), metricInt(row.get("repeatCount")));
    }
    private static List<ExpectedCase> expectedCases(Map<String, Object> plan) {
        var out = new ArrayList<ExpectedCase>();
        for (var c : rows(plan.get("cases"))) {
            if (!c.keySet().equals(Set.of("caseId","kind"))) throw SimulationFailure.unavailable();
            out.add(new ExpectedCase(metricText(c,"caseId"),VirtualExperimentMetricsProjection.Kind.valueOf(metricText(c,"kind"))));
        }
        return List.copyOf(out);
    }
    private static Map<String, Object> verifiedMeasurementPlan(TransactionalStore.Tx tx, Map<String, Object> row) {
        var plan = metricMap(row.get("measurementPlan"));
        if (!plan.keySet().equals(Set.of("version","fixtureSetId","cases","configuration","expectedPairedInputHashes","sharedProposalHashes","maximumPairs"))
                || !Integer.valueOf(1).equals(plan.get("version")) || !row.get("fixtureSetId").equals(plan.get("fixtureSetId"))) throw SimulationFailure.unavailable();
        var expected = expectedCases(plan); var ids = expected.stream().map(ExpectedCase::caseId).toList();
        if (!ids.equals(strings(row.get("caseIds"))) || new java.util.HashSet<>(ids).size() != ids.size()) throw SimulationFailure.unavailable();
        config(plan.get("configuration"));
        for (String key : List.of("expectedPairedInputHashes","sharedProposalHashes")) {
            var hashes = metricMap(plan.get(key));
            if (!hashes.keySet().equals(new java.util.HashSet<>(ids))
                    || hashes.values().stream().anyMatch(h -> !(h instanceof String text) || !SimulationSpec.hash(text))) throw SimulationFailure.unavailable();
        }
        int cap = metricInt(plan.get("maximumPairs")), repeats = metricInt(row.get("repeatCount"));
        if (cap < 1 || repeats < 1 || repeats > 10 || expected.size() > cap / repeats) throw SimulationFailure.unavailable();
        UUID request = canonicalUuid(row.get("measurementCreateRequestId"));
        var identity = new ActionJournal.ActionIdentity(metricText(row,"actorId"),request,"SIM_EXPERIMENT",
                CanonicalJson.sha256(creationPayload(storedPlan(row).body(),plan)));
        var global = tx.get(ActionJournal.TABLE,request.toString());
        if (global == null || !global.keySet().equals(Set.of("actorId","requestId","operation","canonicalBodyHash","persistenceMode","durable","reply"))
                || !identity.actorId().equals(global.get("actorId")) || !request.toString().equals(global.get("requestId"))
                || !identity.operation().equals(global.get("operation")) || !identity.canonicalBodyHash().equals(global.get("canonicalBodyHash"))
                || !VirtualTransactionalStore.MODE.equals(global.get("persistenceMode")) || !Boolean.FALSE.equals(global.get("durable"))) throw SimulationFailure.unavailable();
        var reply = metricMap(global.get("reply"));
        if (!request.toString().equals(reply.get("requestId")) || !row.get("experimentId").equals(reply.get("experimentId"))
                || !"PENDING".equals(reply.get("status")) || !"ALLOW".equals(reply.get("decision"))
                || !Integer.valueOf(Math.multiplyExact(2, Math.multiplyExact(ids.size(),repeats))).equals(reply.get("totalRuns"))) throw SimulationFailure.unavailable();
        return CanonicalJson.immutableObject(plan);
    }
    private MeasurementContext measurementContext(ActorRef actor, Attempt attempt) {
        return store.transaction(tx -> {
            access.require(actor,SimulationAccess.Operation.EXPERIMENT,null,null);
            var row = require(tx,TABLE,attempt.experimentId()); requireOwner(actor,row);
            if (!row.containsKey("measurementPlan")) return null;
            var plan = verifiedMeasurementPlan(tx,row);
            if (!(evaluator instanceof MeasuredPairEvaluator) || !plan.equals(measurementPlan(storedPlan(row)))) throw SimulationFailure.unavailable();
            if (!attempt.proposalHash().equals(metricMap(plan.get("sharedProposalHashes")).get(attempt.caseId()))) throw SimulationFailure.unavailable();
            return new MeasurementContext(plan);
        });
    }
    private EvaluatedArm evaluateArm(Attempt attempt, Environment environment, MeasurementContext context) {
        if (!VirtualTransactionalStore.MODE.equals(evaluator.mode())) throw SimulationFailure.unavailable();
        Observation observation; Map<String,Object> stored = null;
        if (context == null) observation = Objects.requireNonNull(evaluator.evaluate(environment,attempt.caseId(),attempt.repeat(),attempt.proposal()));
        else {
            var measured = Objects.requireNonNull(((MeasuredPairEvaluator)evaluator).evaluateMeasured(environment,attempt.caseId(),attempt.repeat(),attempt.proposal(),attempt.proposalHash()));
            if (!attempt.proposalHash().equals(measured.sharedProposalHash())) throw SimulationFailure.invalid();
            observation = measured.observation(); var arm = measured.arm();
            if (arm != null) {
                validateArm(arm,context.plan(),attempt.caseId(),attempt.repeat(),environment,attempt.proposalHash());
                if (observation.outcome() == Outcome.ENVIRONMENT_ERROR && arm.status() != VirtualExperimentMetricsProjection.Status.ERROR)
                    throw SimulationFailure.invalid();
                stored = armMap(arm,attempt.proposalHash());
            }
        }
        if (!VirtualTransactionalStore.MODE.equals(evaluator.mode()) || !attempt.proposalHash().equals(CanonicalJson.sha256(attempt.proposal()))) throw SimulationFailure.unavailable();
        return new EvaluatedArm(observation,stored);
    }
    private static void validateArm(MeasuredArm arm, Map<String,Object> plan, String caseId, int repeat,
            Environment environment, String sharedHash) {
        String expected = (String)metricMap(plan.get("expectedPairedInputHashes")).get(caseId);
        if (!caseId.equals(arm.caseId()) || arm.repeat() != repeat || !environment.name().equals(arm.environment().name())
                || !config(plan.get("configuration")).equals(arm.configuration())
                || !sharedHash.equals(metricMap(plan.get("sharedProposalHashes")).get(caseId))
                || expected == null || !expected.equals(arm.binding().expectedPairedInputHash())
                || !expected.equals(arm.binding().pairedInputHash())) throw SimulationFailure.invalid();
    }
    private static Map<String,Object> armMap(MeasuredArm a,String sharedHash) {
        var b=a.binding();
        return object("caseId",a.caseId(),"repeat",a.repeat(),"environment",a.environment().name(),"status",a.status().name(),"decision",a.decision().name(),
                "attackInduced",a.attackInduced(),"policyBlocked",a.policyBlocked(),"forbiddenPaymentCount",a.forbiddenPaymentCount(),
                "forbiddenPaidAmountKrw",a.forbiddenPaidAmountKrw(),"actualDownstreamDepth",a.actualDownstreamDepth(),"normalExpectedReached",a.normalExpectedReached(),
                "unrelatedNormalExpected",a.unrelatedNormalExpected(),"unrelatedNormalCompleted",a.unrelatedNormalCompleted(),
                "securityCheckDurationMs",a.securityCheckDurationMs(),"quarantineLatencyMs",a.quarantineLatencyMs(),
                "exclusionReason",a.exclusionReason()==null?null:a.exclusionReason().name(),"configuration",configMap(a.configuration()),"modelOutputHash",a.modelOutputHash(),
                "binding",object("pairedInputVersion",b.pairedInputVersion(),"pairedInputHash",b.pairedInputHash(),"inputSnapshotHash",b.inputSnapshotHash(),
                        "responseByteHash",b.responseByteHash(),"expectedPairedInputHash",b.expectedPairedInputHash()),"sharedProposalHash",sharedHash);
    }
    private static MeasuredArm arm(Map<String,Object> a) {
        if (!a.keySet().equals(Set.of("caseId","repeat","environment","status","decision","attackInduced","policyBlocked","forbiddenPaymentCount",
                "forbiddenPaidAmountKrw","actualDownstreamDepth","normalExpectedReached","unrelatedNormalExpected","unrelatedNormalCompleted","securityCheckDurationMs",
                "quarantineLatencyMs","exclusionReason","configuration","modelOutputHash","binding","sharedProposalHash"))) throw SimulationFailure.unavailable();
        var b=metricMap(a.get("binding"));
        if(!b.keySet().equals(Set.of("pairedInputVersion","pairedInputHash","inputSnapshotHash","responseByteHash","expectedPairedInputHash")))throw SimulationFailure.unavailable();
        var binding=new ArmBinding(nullableText(b.get("pairedInputVersion")),nullableText(b.get("pairedInputHash")),nullableText(b.get("inputSnapshotHash")),
                nullableText(b.get("responseByteHash")),nullableText(b.get("expectedPairedInputHash")));
        return new MeasuredArm(metricText(a,"caseId"),metricInt(a.get("repeat")),VirtualExperimentMetricsProjection.Environment.valueOf(metricText(a,"environment")),
                VirtualExperimentMetricsProjection.Status.valueOf(metricText(a,"status")),VirtualExperimentMetricsProjection.Decision.valueOf(metricText(a,"decision")),
                (Boolean)a.get("attackInduced"),(Boolean)a.get("policyBlocked"),metricInt(a.get("forbiddenPaymentCount")),metricLong(a.get("forbiddenPaidAmountKrw")),
                metricInt(a.get("actualDownstreamDepth")),(Boolean)a.get("normalExpectedReached"),metricInt(a.get("unrelatedNormalExpected")),metricInt(a.get("unrelatedNormalCompleted")),
                nullableTiming(a.get("securityCheckDurationMs")),nullableTiming(a.get("quarantineLatencyMs")),
                a.get("exclusionReason")==null?null:VirtualExperimentMetricsProjection.Exclusion.valueOf(metricText(a,"exclusionReason")),
                config(a.get("configuration")),metricText(a,"modelOutputHash"),binding);
    }
    private static Map<String,Object> appendMeasurements(Map<String,Object> row,Map<String,Object> finished,List<Map<String,Object>> added, UUID action) {
        if (!row.containsKey("measurementPlan")) {
            if (!added.isEmpty()) throw SimulationFailure.unavailable(); return finished;
        }
        var all=new ArrayList<>(rows(row.get("measuredArms")));
        for(var value:added) all.add(changed(value,"producerActionId",action.toString()));
        return changed(finished,"measuredArms",all);
    }
    private static Map<String,Object> measurementCompletion(UUID action,Map<String,Object> finished,List<Map<String,Object>> added,int pairIndex) {
        var receipt=stepReceipt(action,finished);
        return !finished.containsKey("measurementPlan") ? receipt : changed(receipt,"measurementPairHash",CanonicalJson.sha256(added),"measurementPairIndex",pairIndex);
    }
    private static Map<String,Object> publicAdvanceReceipt(Map<String,Object> value) {
        var copy=new LinkedHashMap<String,Object>(value);copy.remove("measurementPairHash");copy.remove("measurementPairIndex");
        return CanonicalJson.immutableObject(copy);
    }
    private static Map<String,Object> measuredMetrics(TransactionalStore.Tx tx,Map<String,Object> row) {
        var plan=verifiedMeasurementPlan(tx,row);var observed=new ArrayList<MeasuredArm>();
        var groups=new LinkedHashMap<UUID,List<Map<String,Object>>>();var indices=new LinkedHashMap<UUID,Integer>();
        var cases=strings(row.get("caseIds"));int repeats=metricInt(row.get("repeatCount"));
        for(var stored:rows(row.get("measuredArms"))) {
            UUID producer=canonicalUuid(stored.get("producerActionId"));
            var projected=new LinkedHashMap<String,Object>(stored);projected.remove("producerActionId");
            var value=arm(projected);var env=Environment.valueOf(value.environment().name());
            validateArm(value,plan,value.caseId(),value.repeat(),env,metricText(projected,"sharedProposalHash"));
            int index=cases.indexOf(value.caseId());
            if(index<0 || value.repeat()>repeats)throw SimulationFailure.unavailable();
            int pair=Math.addExact(Math.multiplyExact(index,repeats),value.repeat()-1);
            var previous=indices.putIfAbsent(producer,pair);if(previous!=null && previous!=pair)throw SimulationFailure.unavailable();
            groups.computeIfAbsent(producer,key->new ArrayList<>()).add(CanonicalJson.immutableObject(projected));observed.add(value);
        }
        for(var group:groups.entrySet()) {
            var action=advanceIdentity(metricText(row,"actorId"),group.getKey(),canonicalUuid(row.get("experimentId")));
            var global=tx.get(ActionJournal.TABLE,action.requestId().toString());
            if(global==null || !global.keySet().equals(Set.of("actorId","requestId","operation","canonicalBodyHash","persistenceMode","durable","reply"))
                    || !action.actorId().equals(global.get("actorId")) || !action.requestId().toString().equals(global.get("requestId"))
                    || !action.operation().equals(global.get("operation")) || !action.canonicalBodyHash().equals(global.get("canonicalBodyHash"))
                    || !VirtualTransactionalStore.MODE.equals(global.get("persistenceMode")) || !Boolean.FALSE.equals(global.get("durable")))throw SimulationFailure.unavailable();
            var receipt=metricMap(global.get("reply"));int pair=indices.get(group.getKey());
            if(!receipt.keySet().equals(Set.of("requestId","experimentId","status","completedPairs","replayed","resultsSource","measurementPairHash","measurementPairIndex"))
                    || !action.requestId().toString().equals(receipt.get("requestId")) || !row.get("experimentId").equals(receipt.get("experimentId"))
                    || !Set.of("RUNNING","COMPLETED").contains(receipt.get("status")) || !Boolean.FALSE.equals(receipt.get("replayed"))
                    || !"VIRTUAL_SIMULATION".equals(receipt.get("resultsSource")) || !Integer.valueOf(pair).equals(receipt.get("measurementPairIndex"))
                    || !Integer.valueOf(Math.addExact(pair,1)).equals(receipt.get("completedPairs")) || pair>=metricInt(row.get("completedPairs"))
                    || !CanonicalJson.sha256(group.getValue()).equals(receipt.get("measurementPairHash")))throw SimulationFailure.unavailable();
        }
        return VirtualExperimentMetricsProjection.project(expectedCases(plan),observed,repeats,metricInt(plan.get("maximumPairs")));
    }
    @SuppressWarnings("unchecked") private static Map<String,Object> metricMap(Object value) {
        if (!(value instanceof Map<?,?> raw) || raw.keySet().stream().anyMatch(k -> !(k instanceof String))) throw SimulationFailure.unavailable();
        return (Map<String,Object>)raw;
    }
    private static String metricText(Map<String,Object> row,String key) { var value=row.get(key);if(!(value instanceof String text)||text.isBlank())throw SimulationFailure.unavailable();return text; }
    private static String nullableText(Object value) { if(value==null)return null;if(!(value instanceof String text))throw SimulationFailure.unavailable();return text; }
    private static int metricInt(Object value) { if(!(value instanceof Integer n))throw SimulationFailure.unavailable();return n; }
    private static long metricLong(Object value) { if(value instanceof Long n)return n;if(value instanceof Integer n)return n.longValue();throw SimulationFailure.unavailable(); }
    private static Double nullableTiming(Object value) { if(value==null)return null;if(!(value instanceof Number n))throw SimulationFailure.unavailable();return n.doubleValue(); }

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
        private final List<Map<String, Object>> measurements;
        private EvaluatedPair(WorkPermit permit, List<Map<String, Object>> outputs, boolean error, List<Map<String,Object>> measurements) {
            this.permit = permit;
            this.outputs = outputs.stream().map(CanonicalJson::immutableObject).toList();
            this.error = error;
            this.measurements = measurements.stream().map(CanonicalJson::immutableObject).toList();
        }
        @Override public String toString() { return "EvaluatedPair[REDACTED]"; }
    }
    public static final class LeaseClaim {
        private final Map<String, Object> receipt;
        private final WorkPermit permit;
        private LeaseClaim(Map<String, Object> receipt, WorkPermit permit) {
            this.receipt = CanonicalJson.immutableObject(publicAdvanceReceipt(receipt)); this.permit = permit;
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
            savedReceipt = saved == null ? null : CanonicalJson.immutableObject(publicAdvanceReceipt(saved)); evaluatedPair = pair;
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
        var measurement = measurementContext(actor,original);
        var measurements = new ArrayList<Map<String,Object>>();
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
                var evaluated = evaluateArm(original,environment,measurement);
                observation = evaluated.observation();
                if (evaluated.measurement() != null) measurements.add(evaluated.measurement());
            } catch (RuntimeException unavailable) {
                observation = new Observation(Outcome.ENVIRONMENT_ERROR, Reason.ENVIRONMENT_UNAVAILABLE);
            }
            error |= observation.outcome() == Outcome.ENVIRONMENT_ERROR;
            outputs.add(object("caseId", original.caseId(), "repeat", original.repeat(), "environment", environment.name(),
                    "outcome", observation.outcome().name(), "reasonCodes", List.of(observation.reason().name()),
                    "sharedProposalHash", original.proposalHash(), "resultsSource", "VIRTUAL_SIMULATION"));
        }
        return new EvaluationOutcome(null, new EvaluatedPair(permit, outputs, error, measurements));
    }

    public Map<String, Object> finalizeLeased(ActorRef actor, WorkPermit permit, EvaluatedPair pair, long now) {
        requirePermit(actor, permit, now);
        if (pair == null || pair.permit != permit) throw SimulationFailure.invalid();
        Attempt original = permit.attempt.original();
        var identity = advanceIdentity(actor.actorId(), original.action(), original.experimentId());
        return journal.reservedTransaction(tx -> {
            access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
            var row = require(tx, TABLE, original.experimentId()); requireOwner(actor, row);
            var saved = tx.completed(identity); if (saved != null) return publicAdvanceReceipt(saved);
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
            finished = appendMeasurements(row,finished,pair.measurements,original.action());
            try { tx.complete(identity, original.token(), measurementCompletion(original.action(),finished,pair.measurements,original.pairIndex())); }
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
        if (claim.receipt() != null) return publicAdvanceReceipt(claim.receipt());
        Attempt attempt = claim.attempt();
        var measurement = measurementContext(actor,attempt);
        var measurements = new ArrayList<Map<String,Object>>();
        var outputs = new ArrayList<Map<String, Object>>(); boolean error = false;
        for (Environment environment : Environment.values()) {
            if (!stillCurrent(actor, attempt)) return finish(actor, identity, attempt, List.of(), false, List.of());
            Observation observation;
            try {
                var evaluated = evaluateArm(attempt,environment,measurement);
                observation = evaluated.observation();
                if (evaluated.measurement() != null) measurements.add(evaluated.measurement());
            } catch (RuntimeException unavailable) {
                observation = new Observation(Outcome.ENVIRONMENT_ERROR, Reason.ENVIRONMENT_UNAVAILABLE);
            }
            // Error deliberately propagates, leaving an explicitly cancellable pending claim.
            error |= observation.outcome() == Outcome.ENVIRONMENT_ERROR;
            outputs.add(object("caseId", attempt.caseId(), "repeat", attempt.repeat(), "environment", environment.name(),
                    "outcome", observation.outcome().name(), "reasonCodes", List.of(observation.reason().name()),
                    "sharedProposalHash", attempt.proposalHash(), "resultsSource", "VIRTUAL_SIMULATION"));
        }
        return finish(actor, identity, attempt, List.copyOf(outputs), error, measurements);
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
                                     List<Map<String, Object>> pairOutputs, boolean error, List<Map<String,Object>> measurements) {
        access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
        return journal.reservedTransaction(tx -> {
            access.require(actor, SimulationAccess.Operation.EXPERIMENT, null, null);
            var row = require(tx, TABLE, attempt.experimentId()); requireOwner(actor, row);
            var saved = tx.completed(identity); if (saved != null) return publicAdvanceReceipt(saved);
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
            finished = appendMeasurements(row,finished,measurements,attempt.action());
            try { tx.complete(identity, attempt.token(), measurementCompletion(attempt.action(),finished,measurements,attempt.pairIndex())); }
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
            var publicRow = new LinkedHashMap<String, Object>(row); publicRow.remove("actorId"); publicRow.remove("creationOwner");
            publicRow.remove("activeClaim"); publicRow.remove("fence");
            publicRow.put("progress", object("completedPairs", row.get("completedPairs"), "totalPairs", row.get("totalPairs")));
            publicRow.put("metrics", object("completedPairs", row.get("completedPairs"), "excludedPairs", rows(row.get("exclusions")).size(),
                    "eligiblePairs", integer(row, "completedPairs") - rows(row.get("exclusions")).size(),
                    "syntheticModelOutputs", true, "liveRobustnessMeasured", false));
            if (row.containsKey("measurementPlan")) {
                try {
                    var metrics = new LinkedHashMap<>(metricMap(publicRow.get("metrics")));
                    metrics.putAll(measuredMetrics(tx,row)); publicRow.put("metrics",CanonicalJson.immutableObject(metrics));
                } catch (RuntimeException invalidMeasurement) { throw SimulationFailure.unavailable(); }
            }
            publicRow.remove("measurementPlan");publicRow.remove("measurementCreateRequestId");publicRow.remove("measuredArms");
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
