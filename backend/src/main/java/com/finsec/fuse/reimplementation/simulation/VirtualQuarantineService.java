package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import static com.finsec.fuse.reimplementation.simulation.SimulationRows.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;
import static com.finsec.fuse.reimplementation.simulation.VirtualWorkflowService.*;

/** Synthetic containment only; never changes real permissions or reverses a payment. */
public final class VirtualQuarantineService {
    public enum Scope { RUN, RESULT, WORKFLOW, SOURCE_VERSION, AGENT_VERSION }
    public record Target(Scope scope, Map<String, Object> fields) {
        public Target {
            Objects.requireNonNull(scope); fields = CanonicalJson.immutableObject(fields);
            Set<String> expected = switch (scope) {
                case RUN -> Set.of("runId"); case RESULT -> Set.of("resultId");
                case WORKFLOW -> Set.of("workflowId"); case SOURCE_VERSION -> Set.of("documentId", "documentVersion");
                case AGENT_VERSION -> Set.of("agentId", "agentVersion");
            };
            if (!fields.keySet().equals(expected)) throw SimulationFailure.invalid();
            for (String key : fields.keySet()) {
                Object value = fields.get(key);
                if (key.endsWith("Version")) {
                    if (!(value instanceof Integer number) || number < 1) throw SimulationFailure.invalid();
                } else if (key.equals("agentId")) {
                    if (!(value instanceof String text) || !Set.of("synthetic-kyc", "synthetic-loan", "synthetic-payment").contains(text))
                        throw SimulationFailure.invalid();
                } else canonicalUuid(value);
            }
        }
    }
    public record Remediation(UUID safeDocumentId, int safeDocumentVersion, List<UUID> checkEvidenceIds,
                              String note, String safeAgentId, Integer safeAgentVersion) {
        public Remediation {
            Objects.requireNonNull(safeDocumentId); checkEvidenceIds = List.copyOf(Objects.requireNonNull(checkEvidenceIds));
            if (safeDocumentVersion < 1 || note == null || note.length() > 1000 || checkEvidenceIds.size() > 100
                    || checkEvidenceIds.stream().distinct().count() != checkEvidenceIds.size()) throw SimulationFailure.invalid();
            if ((safeAgentId == null) != (safeAgentVersion == null)) throw SimulationFailure.invalid();
            if (safeAgentId != null && (!Set.of("synthetic-kyc", "synthetic-loan", "synthetic-payment").contains(safeAgentId)
                    || safeAgentVersion < 1)) throw SimulationFailure.invalid();
        }
        @Override public String toString() { return "Remediation[REDACTED]"; }
        Map<String, Object> body() {
            return object("safeDocumentId", safeDocumentId.toString(), "safeDocumentVersion", safeDocumentVersion,
                    "checkEvidenceIds", checkEvidenceIds.stream().map(UUID::toString).toList(), "note", note,
                    "safeAgentId", safeAgentId, "safeAgentVersion", safeAgentVersion);
        }
    }
    @FunctionalInterface public interface RemediationVerifier {
        boolean verifies(ActorRef actor, Target target, Remediation remediation);
    }
    private final TransactionalStore store;
    private final ActionJournal journal;
    private final SimulationSpec.Catalog catalog;
    private final SimulationAccess access;
    private final VirtualWorkflowService workflows;
    private final RemediationVerifier verifier;
    private final Clock clock;
    private final Supplier<UUID> ids;

    public VirtualQuarantineService(TransactionalStore store, SimulationSpec.Catalog catalog,
            SimulationAccess access, VirtualWorkflowService workflows, RemediationVerifier verifier, Clock clock, Supplier<UUID> ids) {
        this.store = Objects.requireNonNull(store); this.journal = new ActionJournal(store); this.catalog = Objects.requireNonNull(catalog);
        this.access = Objects.requireNonNull(access); this.workflows = Objects.requireNonNull(workflows);
        this.verifier = Objects.requireNonNull(verifier); this.clock = Objects.requireNonNull(clock); this.ids = Objects.requireNonNull(ids);
    }

    public Map<String, Object> create(ActorRef actor, UUID action, Target target, String reasonCode, String note) {
        access.require(actor, SimulationAccess.Operation.QUARANTINE, null, null);
        if (reasonCode == null || !reasonCode.matches("[A-Z][A-Z0-9_]{0,63}") || note == null || note.length() > 1000)
            throw SimulationFailure.invalid();
        authorizeTarget(actor, SimulationAccess.Operation.QUARANTINE, target);
        return journal.execute(actor.actorId(), action, "SIM_QUARANTINE",
                CanonicalJson.sha256(object("scope", target.scope().name(), "target", target.fields(), "reasonCode", reasonCode, "note", note)), tx -> {
            access.require(actor, SimulationAccess.Operation.QUARANTINE, null, null);
            validateTarget(tx, target);
            if (tx.rows(QUARANTINES).values().stream().anyMatch(q -> "ACTIVE".equals(q.get("status"))
                    && target.scope().name().equals(q.get("scope")) && target.fields().equals(q.get("target")))) throw SimulationFailure.invalid();
            UUID id = fresh(tx, QUARANTINES, ids);
            // Note and caller-provided reason are bound to idempotency but never echoed as trace text.
            var q = object("quarantineId", id.toString(), "scope", target.scope().name(), "target", target.fields(),
                    "status", "ACTIVE", "createdAt", clock.instant().toString(), "reasonCodeHash", CanonicalJson.sha256(reasonCode),
                    "paidBeforeQuarantinePaymentIds", historicalPaymentIds(tx, target));
            var affected = tx.rows(WORKFLOWS).values().stream().filter(w -> matches(tx, w, q)).toList();
            for (var workflow : affected)
                access.require(actor, SimulationAccess.Operation.QUARANTINE, id(workflow, "workflowId"), (String) workflow.get("customerId"));
            tx.put(QUARANTINES, id.toString(), q);
            for (var workflow : affected) {
                if (!paid(tx, workflow)) {
                    if (VirtualGrantWorkflowControl.typed(tx, workflow)) {
                        VirtualGrantWorkflowControl.block(tx, workflow, id);
                        workflows.event(tx, id(workflow, "workflowId"), action, "QUARANTINE_ACTIVE");
                    } else workflows.block(tx, workflow, action, "QUARANTINE_ACTIVE", "BLOCKED");
                }
            }
            return receipt(action, q, "ACTIVE");
        });
    }

    public Map<String, Object> release(ActorRef actor, UUID action, UUID quarantineId, Remediation remediation) {
        access.require(actor, SimulationAccess.Operation.RELEASE, null, null);
        Target currentTarget = store.transaction(tx -> target(require(tx, QUARANTINES, quarantineId)));
        authorizeTarget(actor, SimulationAccess.Operation.RELEASE, currentTarget);
        return journal.execute(actor.actorId(), action, "SIM_RELEASE_QUARANTINE", CanonicalJson.sha256(object(
                "quarantineId", quarantineId.toString(), "remediation", remediation.body())), tx -> {
            access.require(actor, SimulationAccess.Operation.RELEASE, null, null);
            var q = require(tx, QUARANTINES, quarantineId);
            if (!"ACTIVE".equals(q.get("status"))) throw SimulationFailure.invalid();
            Target target = target(q);
            var safeSource = catalog.source(remediation.safeDocumentId(), remediation.safeDocumentVersion());
            if (safeSource == null || !safeSource.reviewedSafe()) throw SimulationFailure.invalid();
            if (target.scope() == Scope.SOURCE_VERSION
                    && target.fields().get("documentId").equals(remediation.safeDocumentId().toString())
                    && integer(target.fields(), "documentVersion") == remediation.safeDocumentVersion()) throw SimulationFailure.invalid();
            // A new safe agent implementation/registry is deliberately not invented.
            if (target.scope() == Scope.AGENT_VERSION) throw SimulationFailure.unavailable();
            if (remediation.safeAgentId() != null) throw SimulationFailure.invalid();
            var affected = tx.rows(WORKFLOWS).values().stream().filter(w -> matches(tx, w, q)).toList();
            boolean unpaid = affected.stream().anyMatch(w -> !paid(tx, w));
            if (unpaid && remediation.checkEvidenceIds().isEmpty()) throw SimulationFailure.invalid();
            for (var workflow : affected) {
                access.require(actor, SimulationAccess.Operation.RELEASE, id(workflow, "workflowId"), (String) workflow.get("customerId"));
                if (!paid(tx, workflow)) {
                    var candidate = changed(workflow, "documentId", remediation.safeDocumentId().toString(), "documentVersion", remediation.safeDocumentVersion());
                    if (tx.rows(QUARANTINES).values().stream().anyMatch(other -> !quarantineId.toString().equals(other.get("quarantineId"))
                            && "ACTIVE".equals(other.get("status")) && matches(tx, candidate, other))) throw SimulationFailure.invalid();
                }
            }
            boolean verified;
            try { verified = verifier.verifies(actor, target, remediation); }
            catch (RuntimeException unavailable) { throw SimulationFailure.unavailable(); }
            if (!verified) throw SimulationFailure.invalid();
            tx.put(QUARANTINES, quarantineId.toString(), changed(q, "status", "RELEASED", "releasedAt", clock.instant().toString(),
                    "remediationHash", CanonicalJson.sha256(remediation.body())));
            for (var workflow : affected) {
                if (!paid(tx, workflow)) {
                    tx.put(WORKFLOWS, id(workflow, "workflowId").toString(), changed(workflow,
                            "documentId", remediation.safeDocumentId().toString(), "documentVersion", remediation.safeDocumentVersion()));
                    workflows.event(tx, id(workflow, "workflowId"), action, "REMEDIATION_RECORDED");
                    // State, generation, results, jobs, consumed risk and invalidated approvals remain unchanged.
                }
            }
            return receipt(action, q, "RELEASED");
        });
    }

    public Map<String, Object> impact(ActorRef actor, UUID quarantineId) {
        access.require(actor, SimulationAccess.Operation.READ, null, null);
        return store.transaction(tx -> {
            var q = require(tx, QUARANTINES, quarantineId);
            Set<String> runIds = historicalRunIds(tx, target(q));
            var runs = tx.rows(RUNS).values().stream().filter(r -> runIds.contains(r.get("runId"))).toList();
            Set<String> historicalWorkflows = new LinkedHashSet<>(VirtualGrantWorkflowControl.historicalWorkflowIds(tx, runIds));
            runs.stream().map(r -> (String) r.get("workflowId")).forEach(historicalWorkflows::add);
            var affected = tx.rows(WORKFLOWS).values().stream()
                    .filter(w -> historicalWorkflows.contains(w.get("workflowId")) || matches(tx, w, q)).toList();
            for (var w : affected) access.require(actor, SimulationAccess.Operation.READ, id(w, "workflowId"), (String) w.get("customerId"));
            Set<String> paymentIds = Set.copyOf(historicalPaymentIds(tx, target(q)));
            var payments = tx.rows(PAYMENTS).values().stream().filter(p -> paymentIds.contains(p.get("paymentId"))).toList();
            var typedPaid = VirtualGrantWorkflowControl.paidAmounts(tx, paymentIds);
            if (payments.stream().anyMatch(p -> typedPaid.containsKey(p.get("paymentId")))) throw SimulationFailure.unavailable();
            long paid = Math.addExact(payments.stream().mapToLong(p -> number(p, "amountKrw")).reduce(0L, Math::addExact),
                    typedPaid.values().stream().mapToLong(Long::longValue).reduce(0L, Math::addExact));
            var currentRows = affected.stream().filter(w -> "ACTIVE".equals(q.get("status"))
                    && !paid(tx, w) && matches(tx, w, q)).toList();
            long pending = currentRows.stream().mapToLong(w -> number(w, "amountKrw")).reduce(0L, Math::addExact);
            var current = currentRows.stream().map(w -> w.get("workflowId")).toList();
            var policyHeld = currentRows.stream().filter(w -> forWorkflow(tx, RUNS, id(w, "workflowId")).stream()
                    .noneMatch(r -> integer(r, "generation") == integer(w, "generation")))
                    .map(w -> w.get("workflowId")).toList();
            return object("incidentId", quarantineId.toString(), "scope", q.get("scope"), "target", q.get("target"),
                    "historicalRunIds", runIds.stream().sorted().toList(), "currentAffectedWorkflowIds", current,
                    "policyHeldWorkflowIds", policyHeld, "paidBeforeQuarantine", !strings(q.get("paidBeforeQuarantinePaymentIds")).isEmpty(),
                    "actual", object("runCount", runs.size(), "roleCount", runs.stream().map(r -> r.get("role")).distinct().count(),
                            "workflowCount", affected.size(), "customerCount", affected.stream().map(w -> w.get("customerId")).distinct().count(),
                            "paymentCount", Math.addExact(payments.size(), typedPaid.size()), "paidAmountKrw", paid, "atRiskPendingAmountKrw", pending),
                    "potential", object("applicationCount", null, "totalAmountKrw", null, "currency", null, "roles", List.of(),
                            "maxDownstreamDepth", null, "registeredCustomerCount", null, "perApplicationLimitKrw", null,
                            "missingPolicyFields", List.of("productionPolicy", "reachableApplicationScope")),
                    "calculationRefs", object("basis", "VIRTUAL_OBSERVED_ROWS", "quarantineId", quarantineId.toString(),
                            "workflowIds", affected.stream().map(w -> w.get("workflowId")).toList()),
                    "executionMode", VirtualTransactionalStore.MODE);
        });
    }

    private boolean matches(TransactionalStore.Tx tx, Map<String, Object> workflow, Map<String, Object> quarantine) {
        return VirtualGrantWorkflowControl.typed(tx, workflow)
                ? VirtualGrantWorkflowControl.matches(tx, workflow, quarantine) : workflows.matches(tx, workflow, quarantine);
    }
    private boolean paid(TransactionalStore.Tx tx, Map<String, Object> workflow) {
        return VirtualGrantWorkflowControl.typed(tx, workflow)
                ? VirtualGrantWorkflowControl.paid(tx, workflow) : "PAID".equals(workflow.get("state"));
    }

    private void authorizeTarget(ActorRef actor, SimulationAccess.Operation op, Target target) {
        store.transaction(tx -> {
            Set<String> historicalRuns = historicalRunIds(tx, target);
            Set<String> historicalWorkflows = tx.rows(RUNS).values().stream()
                    .filter(r -> historicalRuns.contains(r.get("runId"))).map(r -> (String) r.get("workflowId"))
                    .collect(java.util.stream.Collectors.toSet());
            historicalWorkflows.addAll(VirtualGrantWorkflowControl.historicalWorkflowIds(tx, historicalRuns));
            var probe = object("scope", target.scope().name(), "target", target.fields());
            for (var workflow : tx.rows(WORKFLOWS).values()) {
                if (historicalWorkflows.contains(workflow.get("workflowId")) || matches(tx, workflow, probe))
                    access.require(actor, op, id(workflow, "workflowId"), (String) workflow.get("customerId"));
            }
            return null;
        });
    }
    private List<String> historicalPaymentIds(TransactionalStore.Tx tx, Target target) {
        Set<String> runIds = historicalRunIds(tx, target);
        var result = new LinkedHashSet<>(VirtualGrantWorkflowControl.historicalPaymentIds(tx, target));
        tx.rows(PAYMENTS).values().stream().filter(payment -> runIds.contains(payment.get("runId"))
                || target.scope() == Scope.WORKFLOW && target.fields().get("workflowId").equals(payment.get("workflowId")))
                .map(p -> (String) p.get("paymentId")).forEach(id -> {
                    if (!result.add(id)) throw SimulationFailure.unavailable();
                });
        return result.stream().sorted().toList();
    }
    private void validateTarget(TransactionalStore.Tx tx, Target target) {
        switch (target.scope()) {
            case RUN -> VirtualGrantWorkflowControl.validateRunTarget(tx, id(target.fields(), "runId"));
            case RESULT -> VirtualGrantWorkflowControl.validateResultTarget(tx, id(target.fields(), "resultId"));
            case WORKFLOW -> require(tx, WORKFLOWS, id(target.fields(), "workflowId"));
            case SOURCE_VERSION -> {
                if (catalog.source(id(target.fields(), "documentId"), integer(target.fields(), "documentVersion")) == null) throw SimulationFailure.invalid();
            }
            case AGENT_VERSION -> { if (integer(target.fields(), "agentVersion") != 1) throw SimulationFailure.invalid(); }
        }
    }
    Set<String> historicalRunIds(TransactionalStore.Tx tx, Target target) {
        Set<String> direct = new LinkedHashSet<>(VirtualGrantWorkflowControl.historicalRunIds(tx, target));
        for (var run : tx.rows(RUNS).values()) {
            boolean matches = switch (target.scope()) {
                case RUN -> run.get("runId").equals(target.fields().get("runId"));
                case RESULT -> {
                    var result = tx.get(RESULTS, (String) target.fields().get("resultId"));
                    yield result != null && run.get("runId").equals(result.get("runId"));
                }
                case WORKFLOW -> run.get("workflowId").equals(target.fields().get("workflowId"));
                case SOURCE_VERSION -> target.fields().get("documentId").equals(run.get("documentId"))
                        && target.fields().get("documentVersion").equals(run.get("documentVersion"));
                case AGENT_VERSION -> target.fields().get("agentId").equals(run.get("agentId"))
                        && target.fields().get("agentVersion").equals(run.get("agentVersion"));
            };
            if (matches) direct.add((String) run.get("runId"));
        }
        boolean added;
        do {
            added = false;
            for (var edge : tx.rows(LINKS).values()) {
                if (direct.contains(edge.get("parentRunId"))) added |= direct.add((String) edge.get("childRunId"));
            }
        } while (added);
        return Set.copyOf(direct);
    }
    @SuppressWarnings("unchecked") private static Target target(Map<String, Object> q) {
        return new Target(Scope.valueOf((String) q.get("scope")), (Map<String, Object>) q.get("target"));
    }
    private static Map<String, Object> receipt(UUID action, Map<String, Object> q, String state) {
        String workflow = "WORKFLOW".equals(q.get("scope")) ? (String) target(q).fields().get("workflowId") : null;
        return object("requestId", action.toString(), "workflowId", workflow, "generation", null, "state", state,
                "decision", "ALLOW", "reasonCodes", List.of(), "message", "VIRTUAL_CONTAINMENT_RECORDED", "replayed", false,
                "quarantineId", q.get("quarantineId"), "scope", q.get("scope"), "target", q.get("target"));
    }
    private static UUID canonicalUuid(Object value) {
        if (!(value instanceof String text) || !text.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
            throw SimulationFailure.invalid();
        return UUID.fromString(text);
    }
}
