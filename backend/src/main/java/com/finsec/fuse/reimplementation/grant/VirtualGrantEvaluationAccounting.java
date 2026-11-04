package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;

/** Actual virtual accounting rows in the caller-owned transaction; no durable or authority proof. */
public final class VirtualGrantEvaluationAccounting {
    private static final String WORKFLOWS = "virtual_workflows", PREPARATIONS = "virtual_grant_profile_kyc_preparations";
    private static final String INPUTS = "virtual_grant_profile_kyc_inputs", CHARGES = "virtual_grant_profile_stage_charges";
    private static final String RISK = "virtual_grant_profile_payment_risk_reservations", PLANS = "virtual_grant_profile_payment_plans";
    static final Set<String> MARKER_KEYS = Set.of("identity", "inputSnapshotHash", "preparedAt", "chargedPoints", "kycRunsAfter", "usedRiskAfter");
    static final Set<String> CHARGE_KEYS = Set.of("workflowId", "generation", "customerId", "stage", "points", "phaseRequestId", "grantId", "actionId", "targetRunId", "resultId");
    static final Set<String> IDENTITY_KEYS = Set.of("actorId", "globalRequestId", "operation", "canonicalizationVersion", "canonicalBodyDigest", "grantId", "actionId", "targetRunId", "workflowId", "generation", "customerId");
    private VirtualGrantEvaluationAccounting() { }
    public record Counters(int usedRisk, int reservedRisk, int kycRuns, boolean kycCharged, boolean loanCharged) {
        public Counters {
            if (usedRisk < 0 || reservedRisk < 0 || kycRuns < 0 || (kycRuns > 0) != kycCharged || loanCharged && !kycCharged)
                throw unconfirmed();
        }
        @Override public String toString() { return "Counters[VIRTUAL_REDACTED]"; }
    }
    public static Counters readVerified(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope) {
        return readCurrent(tx, scope);
    }
    public static Counters readCurrent(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope) {
        return readCurrent(tx, scope, null);
    }
    private static Counters readCurrent(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope,
                                        VirtualGrantTransactionJournal.AccountingPhase phase) {
        try {
            VirtualGrantGenerationHistory.requireCurrent(tx, scope);
            return VirtualGrantHistoricalAccounting.readAggregate(tx, scope, phase);
        } catch (RuntimeException malformed) { throw unconfirmed(); }
    }

    public static PreparationMarker prepareKyc(TransactionalStore.Tx tx, PreparationCommand command, PreparedInput input) {
        return prepareKyc(tx, command, input, null);
    }
    public static PreparationMarker recordPrep(TransactionalStore.Tx tx, PreparationCommand command, PreparedInput input) {
        return prepareKyc(tx, command, input, null);
    }
    public static PreparationMarker recordPrep(TransactionalStore.Tx tx, PreparationCommand command, PreparedInput input,
                                               VirtualGrantTransactionJournal.AccountingPhase phase) {
        return prepareKyc(tx, command, input, phase);
    }
    public static PreparationMarker prepareKyc(TransactionalStore.Tx tx, PreparationCommand command, PreparedInput input,
                                               VirtualGrantTransactionJournal.AccountingPhase phase) {
        var i = command.identity(); var scope = scope(i);
        var before = readCurrent(tx, scope, phase); var terms = VirtualGrantGenerationHistory.requireCurrent(tx, scope).terms();
        var workflow = tx.get(WORKFLOWS, i.workflowId().toString());
        if (!terms.equals(command.terms()) || before.kycRuns() >= terms.maxAutomaticKycRuns()
                || tx.get(PREPARATIONS, i.targetRunId().toString()) != null || tx.get(INPUTS, i.targetRunId().toString()) != null
                || !"KYC_PENDING".equals(workflow.get("state")) || workflow.get("activeJobId") != null
                || !command.source().documentId().toString().equals(workflow.get("documentId"))
                || !Integer.valueOf(command.source().documentVersion()).equals(workflow.get("documentVersion"))) throw unconfirmed();
        var prepared = prepareRequested(command);
        if (!prepared.canonicalInput().equals(input.canonicalInput()) || !prepared.inputSnapshotHash().equals(input.inputSnapshotHash())) throw unconfirmed();
        verifyGrant(tx, i, AllowedAction.EVALUATE_KYC, false);
        int cost = before.kycCharged() ? 0 : terms.kycPoints();
        int used = add(before.usedRisk(), cost), count = add(before.kycRuns(), 1);
        if ((long) used + before.reservedRisk() > nonnegative(workflow, "riskLimit")) throw unconfirmed();
        var marker = new PreparationMarker(i, input.inputSnapshotHash(), command.preparedAt(), cost, count, used);
        if (!VirtualGrantTransactionJournal.accountingPreparationIsPending(tx, marker, phase)) throw unconfirmed();
        VirtualGrantTransactionJournal.requireAccountingPreparation(tx, marker, phase);
        tx.put(INPUTS, i.targetRunId().toString(), object("canonicalInput", input.canonicalInput(), "inputSnapshotHash", input.inputSnapshotHash()));
        tx.put(PREPARATIONS, i.targetRunId().toString(), markerMap(marker));
        if (!before.kycCharged()) tx.put(CHARGES, i.workflowId() + ":KYC", chargeMap(i, "KYC", cost, null));
        var changed = new java.util.LinkedHashMap<>(workflow); changed.put("usedRisk", used); changed.put("kycRuns", count);
        tx.put(WORKFLOWS, i.workflowId().toString(), changed);
        readCurrent(tx, scope, phase);
        return marker;
    }

    /** Called after the exact LOAN result/grant/reference is staged, before its receipt publication. */
    public static void recordLoanObservation(TransactionalStore.Tx tx, StageCommand command, UUID resultId) {
        recordLoanObservation(tx, command, resultId, null);
    }
    public static void recordLoan(TransactionalStore.Tx tx, StageCommand command, UUID resultId) {
        recordLoanObservation(tx, command, resultId, null);
    }
    public static void recordLoan(TransactionalStore.Tx tx, StageCommand command, UUID resultId,
                                  VirtualGrantTransactionJournal.AccountingPhase phase) {
        recordLoanObservation(tx, command, resultId, phase);
    }
    public static void recordLoanObservation(TransactionalStore.Tx tx, StageCommand command, UUID resultId,
                                             VirtualGrantTransactionJournal.AccountingPhase phase) {
        var i = command.identity(); var scope = scope(i);
        if (command.action() != AllowedAction.CREATE_LOAN_RECOMMENDATION || resultId == null) throw unconfirmed();
        verifyGrant(tx, i, AllowedAction.CREATE_LOAN_RECOMMENDATION, true);
        if (!VirtualGrantTransactionJournal.accountingConsumptionIsPending(tx, i.grantId(), resultId, phase)) throw unconfirmed();
        VirtualGrantTransactionJournal.requireAccountingConsumption(tx, i.grantId(), resultId, phase);
        var before = readCurrent(tx, scope, phase); var terms = VirtualGrantGenerationHistory.requireCurrent(tx, scope).terms();
        var result = tx.get("virtual_grant_profile_results", resultId.toString());
        if (result == null || !resultId.toString().equals(result.get("resultId"))) throw unconfirmed();
        int cost = before.loanCharged() ? 0 : terms.loanPoints();
        var workflow = tx.get(WORKFLOWS, i.workflowId().toString());
        int used = add(before.usedRisk(), cost);
        if ((long) used + before.reservedRisk() > nonnegative(workflow, "riskLimit")) throw unconfirmed();
        if (!before.loanCharged()) tx.put(CHARGES, i.workflowId() + ":LOAN", chargeMap(i, "LOAN", cost, resultId));
        var changed = new java.util.LinkedHashMap<>(workflow); changed.put("usedRisk", used);
        tx.put(WORKFLOWS, i.workflowId().toString(), changed);
        VirtualGrantTransactionJournal.requireAccountingConsumption(tx, i.grantId(), resultId, phase);
        readCurrent(tx, scope, phase);
    }
    public static PreparationMarker requirePrepared(TransactionalStore.Tx tx, StageCommand command, String inputSnapshotHash) {
        if (command == null || command.action() != AllowedAction.EVALUATE_KYC || !SimulationSpec.hash(inputSnapshotHash)) throw unconfirmed();
        readCurrent(tx, scope(command.identity()));
        return loadPrepared(tx, command, inputSnapshotHash);
    }
    /** Internal historical evidence only; the caller still applies current disclosure and ordinary replay time gates. */
    public static PreparationMarker requireHistoricalPrepared(TransactionalStore.Tx tx, StageCommand command, String inputSnapshotHash) {
        if (command == null || command.action() != AllowedAction.EVALUATE_KYC || !SimulationSpec.hash(inputSnapshotHash)) throw unconfirmed();
        VirtualGrantHistoricalAccounting.readAggregate(tx, scope(command.identity()));
        return loadPrepared(tx, command, inputSnapshotHash);
    }
    private static PreparationMarker loadPrepared(TransactionalStore.Tx tx, StageCommand command, String inputSnapshotHash) {
        if (command == null || command.action() != AllowedAction.EVALUATE_KYC || !SimulationSpec.hash(inputSnapshotHash)) throw unconfirmed();
        var i = command.identity();
        var row = tx.get(PREPARATIONS, i.targetRunId().toString());
        if (row == null) throw unconfirmed();
        var marker = decodeMarker(row); var p = marker.identity();
        if (!i.grantId().equals(p.grantId()) || !i.actionId().equals(p.actionId()) || !i.targetRunId().equals(p.targetRunId())
                || !i.workflowId().equals(p.workflowId()) || i.generation() != p.generation() || !i.customerId().equals(p.customerId())
                || !inputSnapshotHash.equals(marker.inputSnapshotHash())) throw unconfirmed();
        verifyMarker(tx, marker);
        VirtualGrantTransactionJournal.requireAccountingPreparation(tx, marker, null);
        return marker;
    }
    static void verifyMarker(TransactionalStore.Tx tx, PreparationMarker marker) {
        var i = marker.identity();
        verifyGrant(tx, i, AllowedAction.EVALUATE_KYC, null);
        if (marker.usedRiskAfter() < marker.chargedPoints()) throw unconfirmed();
        var grant = tx.get("virtual_grant_profile_grants", i.grantId().toString());
        if ("CONSUMED".equals(grant.get("state"))) {
            var refs = VirtualGrantTransactionJournal.typedReferences(tx).stream().filter(r ->
                    r.grantId().equals(i.grantId()) && r.actionId().equals(i.actionId())
                    && r.targetRunId().equals(i.targetRunId()) && r.workflowId().equals(i.workflowId())
                    && r.generation() == i.generation() && r.customerId().equals(i.customerId())).toList();
            if (refs.size() != 1 || refs.get(0).resultId() == null
                    || tx.get("virtual_grant_profile_results", refs.get(0).resultId().toString()) == null) throw unconfirmed();
        }
        var row = tx.get(INPUTS, i.targetRunId().toString());
        if (row == null || !row.keySet().equals(Set.of("canonicalInput", "inputSnapshotHash"))
                || !(row.get("canonicalInput") instanceof Map<?, ?> raw) || !marker.inputSnapshotHash().equals(row.get("inputSnapshotHash"))) throw unconfirmed();
        @SuppressWarnings("unchecked") var canonical = (Map<String, Object>) raw;
        if (!canonical.keySet().equals(Set.of("requestId", "workflowId", "generation", "runId", "customerId", "policyVersion", "evidenceFacts", "documents"))
                || !i.globalRequestId().toString().equals(canonical.get("requestId")) || !i.workflowId().toString().equals(canonical.get("workflowId"))
                || !Integer.valueOf(i.generation()).equals(canonical.get("generation")) || !i.targetRunId().toString().equals(canonical.get("runId"))
                || !i.customerId().equals(canonical.get("customerId")) || !marker.inputSnapshotHash().equals(CanonicalJson.orderedSha256(canonical))) throw unconfirmed();
    }
    static void verifyGrant(TransactionalStore.Tx tx, CommandIdentity i, AllowedAction action, Boolean consumed) {
        var row = tx.get("virtual_grant_profile_grants", i.grantId().toString());
        if (row == null || !i.grantId().toString().equals(row.get("grantId")) || !i.actionId().toString().equals(row.get("actionId"))
                || !i.targetRunId().toString().equals(row.get("targetRunId")) || !i.workflowId().toString().equals(row.get("workflowId"))
                || !Integer.valueOf(i.generation()).equals(row.get("generation")) || !i.customerId().equals(row.get("customerId"))
                || !action.name().equals(row.get("action")) || !("ISSUED".equals(row.get("state")) || "CONSUMED".equals(row.get("state")))) throw unconfirmed();
        if (consumed != null && !(consumed ? "CONSUMED" : "ISSUED").equals(row.get("state"))) throw unconfirmed();
    }
    static void verifyConsumed(TransactionalStore.Tx tx, Map<String, Object> row, AllowedAction action) {
        var grantId = uuid(row, "grantId"); var target = uuid(row, "targetRunId"); var resultId = uuid(row, "resultId");
        var grant = tx.get("virtual_grant_profile_grants", grantId.toString());
        if (grant == null || !"CONSUMED".equals(grant.get("state")) || !action.name().equals(grant.get("action"))) throw unconfirmed();
        for (String field : java.util.List.of("grantId", "actionId", "targetRunId", "workflowId", "generation", "customerId"))
            if (!java.util.Objects.equals(row.get(field), grant.get(field))) throw unconfirmed();
        var result = tx.get("virtual_grant_profile_results", resultId.toString());
        var index = tx.get("virtual_grant_profile_by_grant", grantId.toString());
        if (result == null || !resultId.toString().equals(result.get("resultId")) || index == null
                || !row.get("phaseRequestId").equals(index.get("requestId"))) throw unconfirmed();
        var refs = VirtualGrantTransactionJournal.typedReferences(tx).stream().filter(r -> r.grantId().equals(grantId)
                && r.targetRunId().equals(target) && resultId.equals(r.resultId())
                && r.workflowId().toString().equals(row.get("workflowId"))
                && Integer.valueOf(r.generation()).equals(row.get("generation")) && r.customerId().equals(row.get("customerId"))).toList();
        if (refs.size() != 1) throw unconfirmed();
    }
    private static Map<String, Object> chargeMap(CommandIdentity i, String stage, int points, UUID resultId) {
        return object("workflowId", i.workflowId().toString(), "generation", i.generation(), "customerId", i.customerId(), "stage", stage,
                "points", points, "phaseRequestId", i.globalRequestId().toString(), "grantId", i.grantId().toString(), "actionId", i.actionId().toString(),
                "targetRunId", i.targetRunId().toString(), "resultId", resultId == null ? null : resultId.toString());
    }
    private static Map<String, Object> markerMap(PreparationMarker m) {
        return object("identity", identityMap(m.identity()), "inputSnapshotHash", m.inputSnapshotHash(), "preparedAt", m.preparedAt().toString(),
                "chargedPoints", m.chargedPoints(), "kycRunsAfter", m.kycRunsAfter(), "usedRiskAfter", m.usedRiskAfter());
    }
    @SuppressWarnings("unchecked")
    static PreparationMarker decodeMarker(Map<String, Object> row) {
        try {
            if (!row.keySet().equals(MARKER_KEYS) || !(row.get("identity") instanceof Map<?, ?> raw)) throw unconfirmed();
            var i = (Map<String, Object>) raw;
            if (!i.keySet().equals(IDENTITY_KEYS)) throw unconfirmed();
            var identity = new CommandIdentity((String) i.get("actorId"), uuid(i, "globalRequestId"), (String) i.get("operation"),
                    (String) i.get("canonicalizationVersion"), (String) i.get("canonicalBodyDigest"), uuid(i, "grantId"), uuid(i, "actionId"),
                    uuid(i, "targetRunId"), uuid(i, "workflowId"), nonnegative(i, "generation"), (String) i.get("customerId"));
            return new PreparationMarker(identity, (String) row.get("inputSnapshotHash"), Instant.parse((String) row.get("preparedAt")),
                    nonnegative(row, "chargedPoints"), nonnegative(row, "kycRunsAfter"), nonnegative(row, "usedRiskAfter"));
        } catch (RuntimeException malformed) { throw unconfirmed(); }
    }
    private static Map<String, Object> identityMap(CommandIdentity i) {
        return object("actorId", i.actorId(), "globalRequestId", i.globalRequestId().toString(), "operation", i.operation(),
                "canonicalizationVersion", i.canonicalizationVersion(), "canonicalBodyDigest", i.canonicalBodyDigest(), "grantId", i.grantId().toString(),
                "actionId", i.actionId().toString(), "targetRunId", i.targetRunId().toString(), "workflowId", i.workflowId().toString(), "generation", i.generation(), "customerId", i.customerId());
    }
    static void requireScopeShape(Map<String, Object> row) {
        uuid(row, "workflowId");
        if (!(row.get("generation") instanceof Integer n) || n < 1 || !(row.get("customerId") instanceof String s) || s.isBlank()) throw unconfirmed();
    }
    static void requireScope(Map<String, Object> row, VirtualWorkflowLane.Scope s) {
        if (!s.workflowId().toString().equals(row.get("workflowId")) || !Integer.valueOf(s.generation()).equals(row.get("generation"))
                || !s.customerId().equals(row.get("customerId"))) throw unconfirmed();
    }
    static void requireIdentityScope(CommandIdentity i, VirtualWorkflowLane.Scope s) {
        if (!s.workflowId().equals(i.workflowId()) || s.generation() != i.generation() || !s.customerId().equals(i.customerId())) throw unconfirmed();
    }
    static VirtualWorkflowLane.Scope scope(CommandIdentity i) { return new VirtualWorkflowLane.Scope(i.workflowId(), i.generation(), i.customerId()); }
    static UUID uuid(Map<String, Object> row, String key) {
        if (!(row.get(key) instanceof String s)) throw unconfirmed();
        try { UUID u = UUID.fromString(s); if (!u.toString().equals(s)) throw unconfirmed(); return u; }
        catch (IllegalArgumentException malformed) { throw unconfirmed(); }
    }
    static int nonnegative(Map<String, Object> row, String key) {
        if (!(row.get(key) instanceof Integer n) || n < 0) throw unconfirmed(); return n;
    }
    static int add(int a, int b) { try { return Math.addExact(a, b); } catch (ArithmeticException overflow) { throw unconfirmed(); } }
    static RuntimeException unconfirmed() { return OwnedGrantTransactionPort.stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED); }
}
