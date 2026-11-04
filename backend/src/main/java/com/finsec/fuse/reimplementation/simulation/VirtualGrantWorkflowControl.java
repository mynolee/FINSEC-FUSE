package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.grant.VirtualGrantTransactionJournal;
import com.finsec.fuse.reimplementation.grant.VirtualGrantGenerationHistory;
import com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.ApprovalSnapshot;
import com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.ApprovalPlanState;
import com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.ReviewDecision;
import com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.ReviewMaterial;
import com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding;
import java.time.Instant;
import com.finsec.fuse.reimplementation.grant.VirtualGrantTransactionJournal.TypedReference;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import static com.finsec.fuse.reimplementation.simulation.SimulationRows.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;

/** Same-transaction supplied-reference containment; never actual authority or payment reversal. */
public final class VirtualGrantWorkflowControl {
    private static final String WORKFLOWS = "virtual_workflows", LANES = "virtual_workflow_lanes";
    private static final String HOLDS = "virtual_quarantines", PLANS = "virtual_grant_profile_payment_plans";
    private static final String INVALIDATIONS = "virtual_grant_profile_payment_invalidations";
    private static final String APPROVALS = "virtual_grant_profile_review_approvals";
    private static final String APPROVAL_INVALIDATIONS = "virtual_grant_profile_approval_invalidations";
    private static final Set<String> APPROVAL_KEYS = Set.of("approvalId", "reviewRequestId", "reviewerActorId", "decision", "material",
            "reviewSnapshotHash", "createdAt", "expiresAt", "extraRiskLimit", "riskLimit", "state");
    private static final Set<String> PLAN_KEYS = Set.of("grantId", "actionId", "paymentId", "targetRunId", "approvalId",
            "reservationId", "workflowId", "generation", "customerId", "applicationId", "amountKrw", "payoutAccountId",
            "securityPolicyVersion", "reservationState", "approvalState");
    private VirtualGrantWorkflowControl() { }

    public static void requireCurrent(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope) {
        VirtualWorkflowLane.requireTyped(tx, scope);
        var workflow = tx.get(WORKFLOWS, scope.workflowId().toString());
        var currentReferences = references(tx).stream().filter(r -> r.workflowId().equals(scope.workflowId())
                && r.generation() == scope.generation() && r.customerId().equals(scope.customerId())).toList();
        if (currentReferences.isEmpty()) throw SimulationFailure.unavailable();
        for (var hold : tx.rows(HOLDS).values()) {
            if ("ACTIVE".equals(hold.get("status")) && matches(tx, workflow, hold)) throw SimulationFailure.invalid();
        }
    }

    /** Same-transaction continuation predicate; old business RUN/RESULT edges do not become new-generation holds. */
    public static void requireContinuationClear(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope oldScope,
            UUID newDocumentId, int newDocumentVersion,
            Map<com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction,
                    com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.AgentReference> stageAgents) {
        VirtualWorkflowLane.requireTyped(tx, oldScope);
        if (newDocumentId == null || newDocumentVersion < 1 || stageAgents == null || stageAgents.isEmpty())
            throw SimulationFailure.unavailable();
        var agents = Map.copyOf(stageAgents);
        if (!agents.containsKey(com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction.EVALUATE_KYC))
            throw SimulationFailure.unavailable();
        for (var hold : tx.rows(HOLDS).values()) {
            if (!"ACTIVE".equals(hold.get("status"))) continue;
            if (!(hold.get("scope") instanceof String kind) || !(hold.get("target") instanceof Map<?,?> target))
                throw SimulationFailure.unavailable();
            final VirtualQuarantineService.Target admitted;
            try {
                var fields = new java.util.LinkedHashMap<String,Object>();
                for (var e : target.entrySet()) {
                    if (!(e.getKey() instanceof String k)) throw SimulationFailure.unavailable();
                    fields.put(k,e.getValue());
                }
                admitted = new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.valueOf(kind),fields);
            } catch (RuntimeException malformed) { throw SimulationFailure.unavailable(); }
            boolean blocked = switch (admitted.scope()) {
                case WORKFLOW -> oldScope.workflowId().toString().equals(admitted.fields().get("workflowId"));
                case SOURCE_VERSION -> newDocumentId.toString().equals(admitted.fields().get("documentId"))
                        && Integer.valueOf(newDocumentVersion).equals(admitted.fields().get("documentVersion"));
                case AGENT_VERSION -> agents.values().stream().anyMatch(a -> a.agentId().equals(admitted.fields().get("agentId"))
                        && Integer.valueOf(a.version()).equals(admitted.fields().get("agentVersion")));
                case RUN, RESULT -> false;
            };
            if (blocked) throw SimulationFailure.invalid();
        }
    }

    /** Own-artifact historical disclosure; callers separately enforce current access and purpose time rules. */
    public static void requireHistoricalDisclosure(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope historicalScope,
            UUID requestedTargetRunId, UUID requestedResultId) {
        if (tx == null || historicalScope == null || requestedTargetRunId == null) throw SimulationFailure.unavailable();
        VirtualGrantGenerationHistory.validate(tx, historicalScope);
        var refs = references(tx, true);
        var requested = refs.stream().filter(r -> r.workflowId().equals(historicalScope.workflowId())
                && r.generation() == historicalScope.generation() && r.customerId().equals(historicalScope.customerId())
                && r.targetRunId().equals(requestedTargetRunId)
                && (requestedResultId == null || requestedResultId.equals(r.resultId()))).toList();
        if (requested.size() != 1) throw SimulationFailure.unavailable();
        for (var hold : tx.rows(HOLDS).values()) {
            if (!"ACTIVE".equals(hold.get("status"))) continue;
            var target = historicalHoldTarget(hold);
            if (target.scope() == VirtualQuarantineService.Scope.RESULT && requestedResultId == null
                    && requested.get(0).resultId() != null
                    && requested.get(0).resultId().toString().equals(target.fields().get("resultId")))
                continue; // A later result is not silently added to a result-free receipt projection.
            if (target.scope() == VirtualQuarantineService.Scope.WORKFLOW) {
                if (historicalScope.workflowId().toString().equals(target.fields().get("workflowId")))
                    throw SimulationFailure.invalid();
            } else if (historicalRunIds(refs, target).contains(requestedTargetRunId.toString()))
                throw SimulationFailure.invalid();
        }
    }

    private static VirtualQuarantineService.Target historicalHoldTarget(Map<String,Object> hold) {
        if (!(hold.get("scope") instanceof String kind) || !(hold.get("target") instanceof Map<?,?> raw))
            throw SimulationFailure.unavailable();
        try {
            var fields = new java.util.LinkedHashMap<String,Object>();
            for (var e : raw.entrySet()) {
                if (!(e.getKey() instanceof String k)) throw SimulationFailure.unavailable();
                fields.put(k,e.getValue());
            }
            return new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.valueOf(kind),fields);
        } catch (RuntimeException malformed) { throw SimulationFailure.unavailable(); }
    }

    public static void requireFreshBusiness(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope) {
        requireCurrent(tx, scope);
        var workflow = tx.get(WORKFLOWS, scope.workflowId().toString());
        if ("BLOCKED".equals(workflow.get("state")) || "ON_HOLD".equals(workflow.get("state")))
            throw SimulationFailure.invalid();
    }

    /** Pending-use guard only; immutable committed receipt reconstruction does not call this. */
    public static void requirePaymentPlanUsable(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope, UUID reservationId) {
        requireFreshBusiness(tx, scope);
        if (reservationId == null) throw SimulationFailure.invalid();
        var row = tx.get(PLANS, reservationId.toString());
        checkPlan(row, reservationId.toString());
        if (!scope.workflowId().toString().equals(row.get("workflowId"))
                || !Integer.valueOf(scope.generation()).equals(row.get("generation"))
                || !scope.customerId().equals(row.get("customerId"))) throw SimulationFailure.unavailable();
        if (!"RESERVED".equals(row.get("reservationState")) || !"RESERVED".equals(row.get("approvalState")))
            throw SimulationFailure.invalid();
        var invalidation = tx.get(INVALIDATIONS, reservationId.toString());
        if (invalidation != null) {
            checkInvalidation(invalidation, row);
            throw SimulationFailure.invalid();
        }
    }

    /** Fresh reservation only; never a guard for immutable review receipt/history reconstruction. */
    public static void requireApprovalUsable(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope, UUID approvalId) {
        requireFreshBusiness(tx, scope);
        if (approvalId == null) throw SimulationFailure.invalid();
        var matching = reviewApprovals(tx).stream().filter(a -> a.approvalId().equals(approvalId)).toList();
        if (matching.size() != 1) throw SimulationFailure.unavailable();
        var approval = matching.get(0);
        requireApprovalScope(approval, scope);
        if (approval.decision() != ReviewDecision.APPROVE || approval.state() != ApprovalPlanState.AVAILABLE)
            throw SimulationFailure.invalid();
        var row = approvalRow(tx, approval);
        var invalidation = tx.get(APPROVAL_INVALIDATIONS, approvalId.toString());
        if (invalidation != null) {
            checkApprovalInvalidation(invalidation, row);
            throw SimulationFailure.invalid();
        }
    }

    /** Strict stored-shape read only; actual review receipt/finality remains the owned plan port's check. */
    private static List<ApprovalSnapshot> reviewApprovals(TransactionalStore.Tx tx) {
        var result = new java.util.ArrayList<ApprovalSnapshot>();
        try {
            for (var entry : tx.rows(APPROVALS).entrySet()) {
                var row = entry.getValue();
                if (!row.keySet().equals(APPROVAL_KEYS)) throw SimulationFailure.unavailable();
                var material = nativeMap(row.get("material"));
                if (!material.keySet().equals(Set.of("scope", "applicationId", "amountKrw", "payoutAccountId", "kycResultId", "loanResultId",
                        "evidenceBundleHash", "loanResultHash", "documentId", "documentVersion", "sourceContentHash", "policyVersion",
                        "usedRisk", "reservedRisk", "riskLimitAfterApproval"))) throw SimulationFailure.unavailable();
                var scope = nativeMap(material.get("scope"));
                if (!scope.keySet().equals(Set.of("workflowId", "generation", "customerId"))) throw SimulationFailure.unavailable();
                var typedScope = new VirtualWorkflowLane.Scope(nativeUuid(scope, "workflowId"), nativeInt(scope, "generation"), nativeString(scope, "customerId"));
                var typedMaterial = new ReviewMaterial(typedScope, nativeUuid(material, "applicationId"), nativeLong(material, "amountKrw"),
                        nativeUuid(material, "payoutAccountId"), nativeUuid(material, "kycResultId"), nativeUuid(material, "loanResultId"),
                        nativeString(material, "evidenceBundleHash"), nativeString(material, "loanResultHash"), nativeUuid(material, "documentId"),
                        nativeInt(material, "documentVersion"), nativeString(material, "sourceContentHash"), nativeString(material, "policyVersion"),
                        nativeInt(material, "usedRisk"), nativeInt(material, "reservedRisk"), nativeInt(material, "riskLimitAfterApproval"));
                var approval = new ApprovalSnapshot(nativeUuid(row, "approvalId"), nativeUuid(row, "reviewRequestId"), nativeString(row, "reviewerActorId"),
                        ReviewDecision.valueOf(nativeString(row, "decision")), typedMaterial, nativeString(row, "reviewSnapshotHash"),
                        nativeInstant(row, "createdAt"), nativeInstant(row, "expiresAt"), nativeInt(row, "extraRiskLimit"), nativeInt(row, "riskLimit"),
                        ApprovalPlanState.valueOf(nativeString(row, "state")));
                if (!entry.getKey().equals(approval.approvalId().toString())
                        || approval.decision() == ReviewDecision.APPROVE && approval.riskLimit() != typedMaterial.riskLimitAfterApproval()
                        || approval.decision() == ReviewDecision.REJECT && (approval.extraRiskLimit() != 0 || approval.riskLimit() > typedMaterial.riskLimitAfterApproval())
                        || !SyntheticMockPaymentPlanBinding.reviewHash(typedMaterial).equals(approval.reviewSnapshotHash())) throw SimulationFailure.unavailable();
                result.add(approval);
            }
        } catch (RuntimeException malformed) { throw SimulationFailure.unavailable(); }
        return List.copyOf(result);
    }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> nativeMap(Object value) {
        if (!(value instanceof Map<?, ?> map)) throw SimulationFailure.unavailable();
        return (Map<String, Object>) map;
    }
    private static String nativeString(Map<String, Object> row, String key) {
        if (!(row.get(key) instanceof String value)) throw SimulationFailure.unavailable(); return value;
    }
    private static int nativeInt(Map<String, Object> row, String key) {
        if (!(row.get(key) instanceof Integer value)) throw SimulationFailure.unavailable(); return value;
    }
    private static long nativeLong(Map<String, Object> row, String key) {
        if (!(row.get(key) instanceof Long value)) throw SimulationFailure.unavailable(); return value;
    }
    private static UUID nativeUuid(Map<String, Object> row, String key) {
        String value = nativeString(row, key); UUID id = UUID.fromString(value);
        if (!id.toString().equals(value)) throw SimulationFailure.unavailable(); return id;
    }
    private static Instant nativeInstant(Map<String, Object> row, String key) {
        String value = nativeString(row, key); Instant instant = Instant.parse(value);
        if (!instant.toString().equals(value)) throw SimulationFailure.unavailable(); return instant;
    }
    private static void requireApprovalScope(ApprovalSnapshot approval, VirtualWorkflowLane.Scope scope) {
        var actual = approval.material().scope();
        if (!actual.workflowId().equals(scope.workflowId()) || actual.generation() != scope.generation()
                || !actual.customerId().equals(scope.customerId())) throw SimulationFailure.unavailable();
    }
    private static Map<String, Object> approvalRow(TransactionalStore.Tx tx, ApprovalSnapshot approval) {
        var row = tx.get(APPROVALS, approval.approvalId().toString());
        if (row == null || !row.keySet().equals(APPROVAL_KEYS)
                || !approval.approvalId().toString().equals(row.get("approvalId"))) throw SimulationFailure.unavailable();
        return row;
    }
    private static void invalidateApprovals(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope, UUID quarantineId) {
        for (var approval : reviewApprovals(tx)) {
            if (!approval.material().scope().workflowId().equals(scope.workflowId())) continue;
            if (!approval.material().scope().customerId().equals(scope.customerId())) throw SimulationFailure.unavailable();
            if (approval.material().scope().generation() != scope.generation()) {
                VirtualGrantGenerationHistory.validate(tx, approval.material().scope());
                continue;
            }
            requireApprovalScope(approval, scope);
            if (approval.state() == ApprovalPlanState.REJECTED) continue;
            if (approval.decision() != ReviewDecision.APPROVE) throw SimulationFailure.unavailable();
            if (approval.state() != ApprovalPlanState.AVAILABLE && approval.state() != ApprovalPlanState.RESERVED)
                throw SimulationFailure.unavailable();
            var row = approvalRow(tx, approval);
            var old = tx.get(APPROVAL_INVALIDATIONS, approval.approvalId().toString());
            if (old == null) tx.put(APPROVAL_INVALIDATIONS, approval.approvalId().toString(),
                    object("approval", row, "quarantineId", quarantineId.toString()));
            else checkApprovalInvalidation(old, row);
        }
    }
    private static void checkApprovalInvalidation(Map<String, Object> invalidation, Map<String, Object> approval) {
        if (!invalidation.keySet().equals(Set.of("approval", "quarantineId"))
                || !approval.equals(invalidation.get("approval")) || !(invalidation.get("quarantineId") instanceof String value))
            throw SimulationFailure.unavailable();
        try { if (!UUID.fromString(value).toString().equals(value)) throw SimulationFailure.unavailable(); }
        catch (IllegalArgumentException malformed) { throw SimulationFailure.unavailable(); }
    }

    static boolean typed(TransactionalStore.Tx tx, Map<String, Object> workflow) {
        var scope = scope(workflow);
        var lane = tx.get(LANES, scope.workflowId().toString());
        if (lane == null || "LEGACY".equals(lane.get("lane"))) {
            VirtualWorkflowLane.requireLegacy(tx, scope); return false;
        }
        VirtualWorkflowLane.requireTyped(tx, scope); return true;
    }

    static void validateRunTarget(TransactionalStore.Tx tx, UUID id) {
        var typed = references(tx).stream().filter(r -> r.targetRunId().equals(id)).toList();
        var legacy = tx.get("virtual_runs", id.toString());
        if (legacy == null && typed.isEmpty()) throw SimulationFailure.invalid();
        if (legacy != null && !typed.isEmpty()) requireSameScope(legacy, typed.get(0));
    }
    static void validateResultTarget(TransactionalStore.Tx tx, UUID id) {
        var typed = references(tx).stream().filter(r -> id.equals(r.resultId())).toList();
        var legacy = tx.get("virtual_results", id.toString());
        if (legacy == null && typed.isEmpty()) throw SimulationFailure.invalid();
        if (legacy != null && !typed.isEmpty()) requireSameScope(legacy, typed.get(0));
    }
    private static void requireSameScope(Map<String, Object> legacy, TypedReference typed) {
        if (!typed.workflowId().toString().equals(legacy.get("workflowId"))
                || !Integer.valueOf(typed.generation()).equals(legacy.get("generation")))
            throw SimulationFailure.unavailable();
    }
    static Set<String> historicalRunIds(TransactionalStore.Tx tx, VirtualQuarantineService.Target target) {
        return historicalRunIds(references(tx), target);
    }
    private static Set<String> historicalRunIds(List<TypedReference> refs, VirtualQuarantineService.Target target) {
        var result = new LinkedHashSet<String>();
        for (var r : refs) {
            boolean match = switch (target.scope()) {
                case RUN -> r.targetRunId().toString().equals(target.fields().get("runId"));
                case RESULT -> r.resultId() != null && r.resultId().toString().equals(target.fields().get("resultId"));
                case WORKFLOW -> r.workflowId().toString().equals(target.fields().get("workflowId"));
                case SOURCE_VERSION -> r.documentId().toString().equals(target.fields().get("documentId"))
                        && Integer.valueOf(r.documentVersion()).equals(target.fields().get("documentVersion"));
                case AGENT_VERSION -> r.agentId().equals(target.fields().get("agentId"))
                        && Integer.valueOf(r.agentVersion()).equals(target.fields().get("agentVersion"));
            };
            if (match) result.add(r.targetRunId().toString());
        }
        boolean added;
        do {
            added = false;
            for (var r : refs) if (r.sourceRunId() != null && result.contains(r.sourceRunId().toString()))
                added |= result.add(r.targetRunId().toString());
        } while (added);
        return Set.copyOf(result);
    }

    @SuppressWarnings("unchecked")
    static boolean matches(TransactionalStore.Tx tx, Map<String, Object> workflow, Map<String, Object> quarantine) {
        if (!typed(tx, workflow)) throw SimulationFailure.unavailable();
        if (!(quarantine.get("scope") instanceof String text) || !(quarantine.get("target") instanceof Map<?, ?> raw))
            throw SimulationFailure.unavailable();
        final VirtualQuarantineService.Target target;
        try { target = new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.valueOf(text), (Map<String, Object>) raw); }
        catch (RuntimeException malformed) { throw SimulationFailure.unavailable(); }
        var scope = scope(workflow);
        var refs = references(tx).stream().filter(r -> r.workflowId().equals(scope.workflowId())
                && r.generation() == scope.generation()).toList();
        if (refs.isEmpty()) throw SimulationFailure.unavailable();
        return switch (target.scope()) {
            case WORKFLOW -> workflow.get("workflowId").equals(target.fields().get("workflowId"));
            case SOURCE_VERSION -> workflow.get("documentId").equals(target.fields().get("documentId"))
                    && workflow.get("documentVersion").equals(target.fields().get("documentVersion"))
                    || refs.stream().anyMatch(r -> r.documentId().toString().equals(target.fields().get("documentId"))
                        && Integer.valueOf(r.documentVersion()).equals(target.fields().get("documentVersion")));
            case AGENT_VERSION -> stageAgentMatches(workflow, target) || refs.stream().anyMatch(r ->
                    r.agentId().equals(target.fields().get("agentId"))
                    && Integer.valueOf(r.agentVersion()).equals(target.fields().get("agentVersion")));
            case RUN, RESULT -> {
                var runs = historicalRunIds(tx, target);
                yield refs.stream().anyMatch(r -> runs.contains(r.targetRunId().toString()));
            }
        };
    }

    static Set<String> historicalWorkflowIds(TransactionalStore.Tx tx, Set<String> runIds) {
        return references(tx).stream().filter(r -> runIds.contains(r.targetRunId().toString()))
                .map(r -> r.workflowId().toString()).collect(java.util.stream.Collectors.toUnmodifiableSet());
    }
    static Map<String, Long> paidAmounts(TransactionalStore.Tx tx, Set<String> paymentIds) {
        try {
            var result = new java.util.LinkedHashMap<String, Long>();
            for (var p : VirtualGrantTransactionJournal.committedPaymentDomains(tx))
                if (paymentIds.contains(p.paymentId().toString()) && result.put(p.paymentId().toString(), p.amountKrw()) != null)
                    throw SimulationFailure.unavailable();
            return Map.copyOf(result);
        } catch (RuntimeException malformed) { throw SimulationFailure.unavailable(); }
    }

    static boolean paid(TransactionalStore.Tx tx, Map<String, Object> workflow) {
        var s = scope(workflow);
        try {
            boolean paid = VirtualGrantTransactionJournal.committedPaymentDomains(tx).stream().anyMatch(p ->
                    p.workflowId().equals(s.workflowId()) && p.generation() == s.generation()
                    && p.customerId().equals(s.customerId()));
            if (paid) for (var entry : tx.rows(PLANS).entrySet()) {
                var row = entry.getValue(); checkPlan(row, entry.getKey());
                if (s.workflowId().toString().equals(row.get("workflowId"))
                        && "RESERVED".equals(row.get("reservationState"))) throw SimulationFailure.unavailable();
            }
            return paid;
        } catch (RuntimeException malformed) { throw SimulationFailure.unavailable(); }
    }
    static List<String> historicalPaymentIds(TransactionalStore.Tx tx, VirtualQuarantineService.Target target) {
        var runs = historicalRunIds(tx, target);
        try {
            return VirtualGrantTransactionJournal.committedPaymentDomains(tx).stream()
                    .filter(p -> runs.contains(p.targetRunId().toString()) || target.scope() == VirtualQuarantineService.Scope.WORKFLOW
                            && p.workflowId().toString().equals(target.fields().get("workflowId")))
                    .map(p -> p.paymentId().toString()).sorted().toList();
        } catch (RuntimeException malformed) { throw SimulationFailure.unavailable(); }
    }

    static void block(TransactionalStore.Tx tx, Map<String, Object> workflow, UUID quarantineId) {
        if (!typed(tx, workflow)) throw SimulationFailure.unavailable();
        references(tx);
        if (paid(tx, workflow)) return;
        if (workflow.get("activeJobId") != null) throw SimulationFailure.unavailable();
        var s = scope(workflow);
        invalidateApprovals(tx, s, quarantineId);
        for (var entry : tx.rows(PLANS).entrySet()) {
            var row = entry.getValue(); checkPlan(row, entry.getKey());
            if (!s.workflowId().toString().equals(row.get("workflowId"))) continue;
            if (!s.customerId().equals(row.get("customerId"))) throw SimulationFailure.unavailable();
            if (!Integer.valueOf(s.generation()).equals(row.get("generation"))) {
                VirtualGrantGenerationHistory.validate(tx, new VirtualWorkflowLane.Scope(s.workflowId(),
                        (Integer) row.get("generation"), s.customerId()));
                continue;
            }
            if (!"RESERVED".equals(row.get("reservationState")) || !"RESERVED".equals(row.get("approvalState")))
                throw SimulationFailure.unavailable();
            var joins = references(tx).stream().filter(r -> r.targetRunId().toString().equals(row.get("targetRunId"))
                    && r.grantId().toString().equals(row.get("grantId")) && r.actionId().toString().equals(row.get("actionId"))
                    && r.workflowId().equals(s.workflowId()) && r.generation() == s.generation()
                    && r.customerId().equals(s.customerId())).toList();
            if (joins.size() != 1) throw SimulationFailure.unavailable();
            var old = tx.get(INVALIDATIONS, entry.getKey());
            if (old == null) tx.put(INVALIDATIONS, entry.getKey(), object("plan", row, "quarantineId", quarantineId.toString()));
            else checkInvalidation(old, row);
        }
        tx.put(WORKFLOWS, s.workflowId().toString(), changed(workflow, "state", "BLOCKED", "lastDecision", "DENY",
                "reasonCodes", List.of("QUARANTINE_ACTIVE")));
    }

    private static List<TypedReference> references(TransactionalStore.Tx tx) {
        return references(tx, false);
    }
    private static List<TypedReference> references(TransactionalStore.Tx tx, boolean historicalRead) {
        final List<TypedReference> refs;
        try { refs = VirtualGrantTransactionJournal.typedReferences(tx); }
        catch (RuntimeException malformed) { throw SimulationFailure.unavailable(); }
        var runs = new LinkedHashSet<UUID>(); var results = new LinkedHashSet<UUID>();
        for (var r : refs) {
            var referenceScope = new VirtualWorkflowLane.Scope(r.workflowId(), r.generation(), r.customerId());
            var workflow = tx.get(WORKFLOWS, r.workflowId().toString());
            if (workflow == null) throw SimulationFailure.unavailable();
            if (!historicalRead && Integer.valueOf(r.generation()).equals(workflow.get("generation")))
                VirtualWorkflowLane.requireTyped(tx, referenceScope);
            else VirtualGrantGenerationHistory.validate(tx, referenceScope);
            if (!(workflow.get("documentId") instanceof String document)
                    || !(workflow.get("documentVersion") instanceof Integer version) || version < 1
                    || !(workflow.get("state") instanceof String state) || state.isBlank()) throw SimulationFailure.unavailable();
            try { if (!UUID.fromString(document).toString().equals(document)) throw SimulationFailure.unavailable(); }
            catch (IllegalArgumentException malformed) { throw SimulationFailure.unavailable(); }
            var grant = tx.get("virtual_grant_profile_grants", r.grantId().toString());
            if (grant == null || !r.grantId().toString().equals(grant.get("grantId"))
                    || !r.actionId().toString().equals(grant.get("actionId"))
                    || !r.targetRunId().toString().equals(grant.get("targetRunId"))
                    || !r.workflowId().toString().equals(grant.get("workflowId"))
                    || !Integer.valueOf(r.generation()).equals(grant.get("generation"))
                    || !r.customerId().equals(grant.get("customerId"))) throw SimulationFailure.unavailable();
            if (r.resultId() != null) {
                var result = tx.get("virtual_grant_profile_results", r.resultId().toString());
                if (!"CONSUMED".equals(grant.get("state")) || result == null
                        || !r.resultId().toString().equals(result.get("resultId"))) throw SimulationFailure.unavailable();
            } else if (!"ISSUED".equals(grant.get("state"))) throw SimulationFailure.unavailable();
            if (!runs.add(r.targetRunId()) || r.resultId() != null && !results.add(r.resultId())) throw SimulationFailure.unavailable();
        }
        for (var r : refs) if (r.sourceRunId() != null) {
            var parents = refs.stream().filter(p -> p.targetRunId().equals(r.sourceRunId())
                    && r.sourceResultId().equals(p.resultId()) && p.workflowId().equals(r.workflowId())
                    && p.generation() == r.generation() && p.customerId().equals(r.customerId())).toList();
            if (parents.size() != 1) throw SimulationFailure.unavailable();
        }
        for (var r : refs) {
            var visited = new LinkedHashSet<UUID>();
            var cursor = r;
            while (cursor.sourceRunId() != null) {
                if (!visited.add(cursor.targetRunId())) throw SimulationFailure.unavailable();
                UUID parent = cursor.sourceRunId();
                cursor = refs.stream().filter(p -> p.targetRunId().equals(parent)).findFirst()
                        .orElseThrow(SimulationFailure::unavailable);
            }
        }
        return refs;
    }
    @SuppressWarnings("unchecked")
    private static boolean stageAgentMatches(Map<String, Object> workflow, VirtualQuarantineService.Target target) {
        if (!(workflow.get("typedStageAgents") instanceof Map<?, ?> agents)) throw SimulationFailure.unavailable();
        boolean match = false;
        for (var value : agents.values()) {
            if (!(value instanceof Map<?, ?> agent) || !agent.keySet().equals(Set.of("agentId", "agentVersion"))
                    || !(agent.get("agentId") instanceof String) || !(agent.get("agentVersion") instanceof Integer version) || version < 1)
                throw SimulationFailure.unavailable();
            match |= agent.get("agentId").equals(target.fields().get("agentId"))
                    && agent.get("agentVersion").equals(target.fields().get("agentVersion"));
        }
        return match;
    }
    private static VirtualWorkflowLane.Scope scope(Map<String, Object> workflow) {
        try { return new VirtualWorkflowLane.Scope(id(workflow, "workflowId"), integer(workflow, "generation"), (String) workflow.get("customerId")); }
        catch (RuntimeException malformed) { throw SimulationFailure.unavailable(); }
    }
    private static void checkPlan(Map<String, Object> row, String key) {
        if (row == null || !row.keySet().equals(PLAN_KEYS)) throw SimulationFailure.unavailable();
        for (var name : List.of("grantId", "actionId", "paymentId", "targetRunId", "approvalId", "reservationId", "workflowId", "applicationId", "payoutAccountId")) {
            if (!(row.get(name) instanceof String value)) throw SimulationFailure.unavailable();
            try { if (!UUID.fromString(value).toString().equals(value)) throw SimulationFailure.unavailable(); }
            catch (IllegalArgumentException malformed) { throw SimulationFailure.unavailable(); }
        }
        if (!key.equals(row.get("reservationId")) || !(row.get("generation") instanceof Integer generation) || generation < 1
                || !(row.get("customerId") instanceof String customer) || customer.isBlank()
                || !(row.get("amountKrw") instanceof Long amount) || amount < 1 || amount > 50000000L
                || !(row.get("securityPolicyVersion") instanceof String policy) || policy.isBlank()
                || !("RESERVED".equals(row.get("reservationState")) && "RESERVED".equals(row.get("approvalState"))
                    || "COMMITTED".equals(row.get("reservationState")) && "CONSUMED".equals(row.get("approvalState"))))
            throw SimulationFailure.unavailable();
    }
    @SuppressWarnings("unchecked")
    private static void checkInvalidation(Map<String, Object> invalidation, Map<String, Object> plan) {
        if (!invalidation.keySet().equals(Set.of("plan", "quarantineId")) || !plan.equals(invalidation.get("plan"))
                || !(invalidation.get("quarantineId") instanceof String value)) throw SimulationFailure.unavailable();
        try { if (!UUID.fromString(value).toString().equals(value)) throw SimulationFailure.unavailable(); }
        catch (IllegalArgumentException malformed) { throw SimulationFailure.unavailable(); }
    }
}
