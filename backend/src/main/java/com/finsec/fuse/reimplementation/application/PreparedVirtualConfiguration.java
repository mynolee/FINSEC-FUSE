package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualExperimentService;
import java.time.Clock;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

/** Already prepared data only; no path, environment, credential or provider acquisition. */
public record PreparedVirtualConfiguration(VirtualLoopbackListener.Settings listener,
        SimulationSpec.Catalog catalog, SimulationSpec.RiskTerms riskTerms,
        List<VirtualExperimentService.FixtureSet> fixtureSets, int maximumFixtureSets,
        Clock clock, Supplier<UUID> actionIds, ActorRef deliveryActor, int maximumInFlight) {
    public PreparedVirtualConfiguration {
        Objects.requireNonNull(listener); Objects.requireNonNull(catalog); Objects.requireNonNull(riskTerms);
        Objects.requireNonNull(clock); Objects.requireNonNull(actionIds); Objects.requireNonNull(deliveryActor);
        if (fixtureSets == null || maximumFixtureSets < 1 || maximumInFlight < 1) throw invalid();
        fixtureSets = List.copyOf(fixtureSets);
        if (fixtureSets.size() > maximumFixtureSets) throw invalid();
        var ids = new HashSet<String>();
        for (var fixture : fixtureSets) if (!ids.add(fixture.fixtureSetId())) throw invalid();
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_PREPARED_CONFIGURATION"); }
    @Override public String toString() { return "PreparedVirtualConfiguration[REDACTED]"; }
}
