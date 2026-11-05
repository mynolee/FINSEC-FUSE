package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.time.Clock;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

/** Explicit prepared synthetic FUSE preapproval scenarios; no provider or baseline inference. */
public final class SyntheticFull60WorkflowScenarioRunner {
    private final SyntheticFull60FixtureAdapter.Fixture fixture;
    private final SimulationSpec.RiskTerms terms;
    private final SimulationAccess access;
    private final ActorRef actor;
    private final Clock clock;
    private final Supplier<UUID> ids;

    public enum Reached { STARTED, PREPARED, OBSERVED }

    public record Capability(List<String> caseIds, String executionMode,
            String supportedArm, String phase, boolean baselineAvailable,
            boolean providerInvoked, boolean productionAuthority) {
        public Capability { caseIds = List.copyOf(caseIds); }
    }

    /** Public GET projection and counts originate from the actual isolated workflow store. */
    public record Execution(String caseId, UUID workflowId, Reached reached,
            Map<String, Object> workflow, Map<String, Integer> committedRowCounts) {
        public Execution {
            Objects.requireNonNull(caseId); Objects.requireNonNull(workflowId);
            Objects.requireNonNull(reached);
            workflow = CanonicalJson.immutableObject(workflow);
            committedRowCounts = Map.copyOf(committedRowCounts);
        }
        public String executionMode() { return "VIRTUAL_SIMULATION"; }
        public String supportedArm() { return "FUSE"; }
        public String pairStatus() { return "INCOMPLETE_PAIR"; }
        public boolean baselineAvailable() { return false; }
        public boolean productionAuthority() { return false; }
        public boolean measuredMetricsAvailable() { return false; }
    }

    public SyntheticFull60WorkflowScenarioRunner(SyntheticFull60FixtureAdapter.Fixture fixture,
            SimulationSpec.RiskTerms terms, SimulationAccess access, ActorRef actor,
            Clock clock, Supplier<UUID> ids) {
        this.fixture = Objects.requireNonNull(fixture);
        this.terms = Objects.requireNonNull(terms);
        this.access = Objects.requireNonNull(access);
        this.actor = Objects.requireNonNull(actor);
        this.clock = Objects.requireNonNull(clock);
        this.ids = Objects.requireNonNull(ids);
    }

    /** This is a prepared registry seam, not experiment pairing/provider capability. */
    public Capability capability() {
        return new Capability(fixture.cases().stream().map(SyntheticFull60FixtureAdapter.Scenario::caseId)
                .sorted().toList(), "VIRTUAL_SIMULATION", "FUSE", "PREAPPROVAL_ONLY",
                false, false, false);
    }

    /**
     * Executes only existing public workflow operations against a fresh in-memory store.
     * Authority, risk terms, exact scenario clock and all UUIDs are explicit caller inputs.
     * No expected field is read to select a business outcome.
     */
    public synchronized Execution runCase(String caseId) {
        var scenario = Objects.requireNonNull(fixture.byId(Objects.requireNonNull(caseId)));
        var catalog = SyntheticFull60FixtureAdapter.catalog(scenario, clock);
        if (catalog.applications().size() != 1) throw unconfirmed();
        var application = catalog.applications().get(0);
        var seenIds = new HashSet<UUID>();
        Supplier<UUID> executionIds = () -> {
            UUID value = Objects.requireNonNull(ids.get());
            if (!seenIds.add(value)) throw unconfirmed();
            return value;
        };
        var store = new VirtualTransactionalStore();
        // No delivery notifications: observation is already prepared synthetic product data.
        var workflows = new VirtualWorkflowService(store, catalog, terms, access, clock, executionIds);
        var started = workflows.start(new WorkflowStartBoundary.Command(actor, executionIds.get(),
                application.request()));
        UUID workflowId = started.workflowId();
        Map<String, Object> current = workflows.get(actor, workflowId);
        Reached reached = Reached.STARTED;
        Object active = current.get("activeJob");
        if ("KYC_PENDING".equals(current.get("state")) && active instanceof Map<?, ?> job) {
            UUID jobId = uuid(job.get("jobId"));
            Object generation = current.get("generation");
            if (!(generation instanceof Integer nativeGeneration) || nativeGeneration < 1)
                throw unconfirmed();
            var prepared = workflows.prepareKyc(actor, executionIds.get(), workflowId,
                    jobId, nativeGeneration);
            reached = Reached.PREPARED;
            Object value = prepared.get("input");
            if (value instanceof Map<?, ?> input) {
                var actualInput = new LinkedHashMap<String, Object>();
                for (var entry : input.entrySet()) {
                    if (!(entry.getKey() instanceof String key)) throw unconfirmed();
                    actualInput.put(key, entry.getValue());
                }
                // Adapter verifies actual prepared request/workflow/run/hash and seed evidence.
                var observation = SyntheticFull60FixtureAdapter.observation(scenario,
                        CanonicalJson.immutableObject(actualInput));
                workflows.observeKyc(actor, executionIds.get(), observation);
                reached = Reached.OBSERVED;
            }
            current = workflows.get(actor, workflowId);
        }
        // A real committed-store snapshot, never an expected-table-derived response.
        var snapshot = store.snapshot();
        var row = snapshot.getOrDefault(VirtualWorkflowService.WORKFLOWS, Map.of())
                .get(workflowId.toString());
        if (row == null || !Objects.equals(row.get("state"), current.get("state"))
                || !Objects.equals(row.get("generation"), current.get("generation")))
            throw unconfirmed();
        var counts = new LinkedHashMap<String, Integer>();
        for (String table : List.of(VirtualWorkflowService.WORKFLOWS, VirtualWorkflowService.JOBS,
                VirtualWorkflowService.RUNS, VirtualWorkflowService.RESULTS,
                VirtualWorkflowService.RISK, VirtualWorkflowService.APPROVALS,
                VirtualWorkflowService.RESERVATIONS, VirtualWorkflowService.PAYMENTS)) {
            counts.put(table, snapshot.getOrDefault(table, Map.of()).size());
        }
        return new Execution(scenario.caseId(), workflowId, reached, current, counts);
    }

    private static UUID uuid(Object value) {
        if (!(value instanceof String text)) throw unconfirmed();
        try { return UUID.fromString(text); }
        catch (IllegalArgumentException invalid) { throw unconfirmed(); }
    }
    private static IllegalStateException unconfirmed() {
        return new IllegalStateException("SYNTHETIC_SCENARIO_GRAPH_UNCONFIRMED");
    }
}
