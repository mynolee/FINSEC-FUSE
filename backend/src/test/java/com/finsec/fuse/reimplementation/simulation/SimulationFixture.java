package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.WorkflowResumeBoundary;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;

/** Newly invented, explicitly synthetic cases; no original seed or private fixture data. */
final class SimulationFixture {
    static final WorkflowStartBoundary.ActorRef ACTOR = new WorkflowStartBoundary.ActorRef("synthetic-operator");
    static final UUID DOCUMENT = new UUID(1, 1), ACCOUNT = new UUID(1, 2),
            ID_FACT = new UUID(1, 3), FACE_FACT = new UUID(1, 4), FOREIGN_FACT = new UUID(1, 5);
    final AtomicLong sequence = new AtomicLong(100);
    final AtomicBoolean permitted = new AtomicBoolean(true);
    final AtomicBoolean remediationVerified = new AtomicBoolean(true);
    final MutableClock clock = new MutableClock(Instant.parse("2026-10-21T00:00:00Z"));
    final VirtualTransactionalStore store = new VirtualTransactionalStore();
    final SimulationSpec.Source source = new SimulationSpec.Source(DOCUMENT, 1, "synthetic source 한글",
            SimulationSpec.rawHash("synthetic source 한글"), true);
    final SimulationSpec.Source replacement = new SimulationSpec.Source(DOCUMENT, 2, "synthetic safe revision",
            SimulationSpec.rawHash("synthetic safe revision"), true);
    final SimulationSpec.Application app = new SimulationSpec.Application("synthetic-normal", "synthetic-reference-1",
            "synthetic-customer-1", 1000L, ACCOUNT, 5000L, 10000L, true, source);
    final SimulationSpec.Application second = new SimulationSpec.Application("synthetic-second", "synthetic-reference-2",
            "synthetic-customer-1", 2000L, ACCOUNT, 5000L, 10000L, true, replacement);
    final SimulationSpec.Catalog catalog = new SimulationSpec.Catalog(List.of(app, second), List.of(
            new SimulationSpec.Fact(ID_FACT, app.customerId(), SimulationSpec.Kind.ID_DOC, SimulationSpec.Outcome.PASS,
                    true, clock.instant().minusSeconds(60), clock.instant().plusSeconds(3600)),
            new SimulationSpec.Fact(FACE_FACT, app.customerId(), SimulationSpec.Kind.FACE_MATCH, SimulationSpec.Outcome.PASS,
                    true, clock.instant().minusSeconds(60), clock.instant().plusSeconds(3600)),
            new SimulationSpec.Fact(FOREIGN_FACT, "synthetic-other-customer", SimulationSpec.Kind.FACE_MATCH, SimulationSpec.Outcome.PASS,
                    true, clock.instant().minusSeconds(60), clock.instant().plusSeconds(3600))));
    final SimulationAccess access;
    final VirtualWorkflowService workflows;
    final VirtualQuarantineService quarantines;

    SimulationFixture() { this(20, null); }
    SimulationFixture(int limit, SimulationAccess.Authority extra) {
        this(new SimulationSpec.RiskTerms("SYNTHETIC-POLICY-1", 1, 2, 3, limit, 5, 2,
                Duration.ofMinutes(5)), extra);
    }
    SimulationFixture(SimulationSpec.RiskTerms terms, SimulationAccess.Authority extra) {
        access = new SimulationAccess((actor, operation, workflow, customer) ->
                permitted.get() && (extra == null || extra.allows(actor, operation, workflow, customer)));
        workflows = new VirtualWorkflowService(store, catalog, terms, access, clock, this::id);
        quarantines = new VirtualQuarantineService(store, catalog, access, workflows,
                (actor, target, remediation) -> remediationVerified.get(), clock, this::id);
    }
    UUID id() { return new UUID(0, sequence.incrementAndGet()); }
    UUID start() { return workflows.start(new WorkflowStartBoundary.Command(ACTOR, id(), app.request())).workflowId(); }
    @SuppressWarnings("unchecked") Map<String, Object> input(UUID workflow) {
        return (Map<String, Object>) workflows.prepareKyc(ACTOR, id(), workflow).get("input");
    }
    SimulationSpec.Observation observation(Map<String, Object> input, List<UUID> evidence) {
        return new SimulationSpec.Observation(UUID.fromString((String) input.get("requestId")),
                UUID.fromString((String) input.get("workflowId")), (Integer) input.get("generation"),
                UUID.fromString((String) input.get("runId")), (String) input.get("inputSnapshotHash"),
                SimulationSpec.KycStatus.VERIFIED, evidence);
    }
    UUID ready() {
        UUID workflow = start();
        workflows.observeKyc(ACTOR, id(), observation(input(workflow), List.of(ID_FACT, FACE_FACT)));
        return workflow;
    }
    Map<String, Object> approve(UUID workflow) {
        return workflows.approve(ACTOR, id(), workflow, true,
                (String) workflows.approvalPreview(ACTOR, workflow).get("reviewSnapshotHash"), "synthetic review");
    }
    UUID reserve(UUID workflow) {
        return UUID.fromString((String) workflows.reservePayment(ACTOR, id(), workflow).get("reservationId"));
    }
    Map<String, Object> quarantine(UUID workflow) {
        return quarantines.create(ACTOR, id(), new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.WORKFLOW,
                object("workflowId", workflow.toString())), "SYNTHETIC_CONTAINMENT", "");
    }
    Map<String, Object> release(UUID quarantine) {
        return quarantines.release(ACTOR, id(), quarantine, new VirtualQuarantineService.Remediation(DOCUMENT, 2,
                List.of(ID_FACT), "synthetic checked remediation", null, null));
    }
    int rows(String table) { return store.snapshot().getOrDefault(table, Map.of()).size(); }
    static final class MutableClock extends Clock {
        private Instant instant;
        MutableClock(Instant instant) { this.instant = instant; }
        void advance(Duration duration) { instant = instant.plus(duration); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { if (!ZoneOffset.UTC.equals(zone)) throw new IllegalArgumentException(); return this; }
        @Override public Instant instant() { return instant; }
    }
}
