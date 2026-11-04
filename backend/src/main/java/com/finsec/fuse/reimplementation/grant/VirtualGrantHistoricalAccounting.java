package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import static com.finsec.fuse.reimplementation.grant.VirtualGrantEvaluationAccounting.*;

/** Verifies original-generation accounting evidence; never grants business-result reuse. */
public final class VirtualGrantHistoricalAccounting {
    private static final String WORKFLOWS = "virtual_workflows", PREPARATIONS = "virtual_grant_profile_kyc_preparations";
    private static final String INPUTS = "virtual_grant_profile_kyc_inputs", CHARGES = "virtual_grant_profile_stage_charges";
    private static final String RISK = "virtual_grant_profile_payment_risk_reservations", PLANS = "virtual_grant_profile_payment_plans";
    private VirtualGrantHistoricalAccounting() { }
    public static Counters readAggregate(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope) {
        return readAggregate(tx, scope, null);
    }
    static Counters readAggregate(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope,
                                  VirtualGrantTransactionJournal.AccountingPhase phase) {
        try { return read(tx, scope, phase); }
        catch (RuntimeException malformed) { throw unconfirmed(); }
    }
    private static Counters read(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope scope,
                                  VirtualGrantTransactionJournal.AccountingPhase phase) {
        var origin = VirtualGrantGenerationHistory.validate(tx, scope);
        var terms = origin.terms();
        var workflow = tx.get(WORKFLOWS, scope.workflowId().toString());
        if (workflow == null) throw unconfirmed();
        var current = new VirtualWorkflowLane.Scope(uuid(workflow, "workflowId"), nonnegative(workflow, "generation"),
                (String) workflow.get("customerId"));
        if (!current.workflowId().equals(scope.workflowId()) || !current.customerId().equals(scope.customerId())
                || scope.generation() > current.generation()
                || !VirtualGrantGenerationHistory.requireCurrent(tx, current).terms().equals(terms)) throw unconfirmed();
        if (!terms.policyVersion().equals(workflow.get("policyVersion"))) throw unconfirmed();
        int charges = 0; boolean kyc = false, loan = false;
        for (var entry : tx.rows(CHARGES).entrySet()) {
            var row = entry.getValue();
            requireScopeShape(row);
            if (!scope.workflowId().toString().equals(row.get("workflowId"))) continue;
            validateRow(tx, row, current, terms);
            if (!row.keySet().equals(CHARGE_KEYS) || !(row.get("stage") instanceof String stage)
                    || !entry.getKey().equals(scope.workflowId() + ":" + stage)) throw unconfirmed();
            int points = nonnegative(row, "points");
            if (stage.equals("KYC")) { if (kyc || points != terms.kycPoints() || row.get("resultId") != null) throw unconfirmed();
                var markerRow = tx.get(PREPARATIONS, uuid(row, "targetRunId").toString());
                if (markerRow == null) throw unconfirmed();
                var marker = decodeMarker(markerRow); var identity = marker.identity();
                requireScope(row, scope(identity));
                if (!identity.globalRequestId().toString().equals(row.get("phaseRequestId"))
                        || !identity.grantId().toString().equals(row.get("grantId"))
                        || !identity.actionId().toString().equals(row.get("actionId")) || marker.chargedPoints() != points) throw unconfirmed();
                if (marker.kycRunsAfter() != 1) throw unconfirmed();
                kyc = true; }
            else if (stage.equals("LOAN")) { if (loan || points != terms.loanPoints()) throw unconfirmed(); loan = true; verifyConsumed(tx, row, AllowedAction.CREATE_LOAN_RECOMMENDATION); }
            else throw unconfirmed();
            uuid(row, "phaseRequestId"); uuid(row, "grantId"); uuid(row, "actionId"); uuid(row, "targetRunId");
            charges = add(charges, points);
        }
        int count = 0, markerCharges = 0;
        var ordinals = new LinkedHashSet<Integer>();
        for (var entry : tx.rows(PREPARATIONS).entrySet()) {
            var marker = decodeMarker(entry.getValue());
            if (!scope.workflowId().equals(marker.identity().workflowId())) continue;
            validateIdentity(tx, marker.identity(), current, terms);
            if (!entry.getKey().equals(marker.identity().targetRunId().toString())) throw unconfirmed();
            verifyMarker(tx, marker);
            validateMarkerSource(tx, marker, terms);
            VirtualGrantTransactionJournal.requireAccountingPreparation(tx, marker, phase);
            count = add(count, 1); markerCharges = add(markerCharges, marker.chargedPoints());
            if (!ordinals.add(marker.kycRunsAfter())) throw unconfirmed();
        }
        if (kyc != (count > 0) || markerCharges != (kyc ? terms.kycPoints() : 0) || count > terms.maxAutomaticKycRuns()) throw unconfirmed();
        for (int n = 1; n <= count; n++) if (!ordinals.contains(n)) throw unconfirmed();
        int reserved = 0, consumed = 0;
        for (var entry : tx.rows(RISK).entrySet()) {
            var row = entry.getValue(); requireScopeShape(row);
            if (!scope.workflowId().toString().equals(row.get("workflowId"))) continue;
            validateRow(tx, row, current, terms);
            if (!row.keySet().equals(Set.of("reservationId", "paymentId", "approvalId", "grantId", "actionId", "targetRunId", "workflowId", "generation", "customerId", "policyVersion", "points", "state"))
                    || !entry.getKey().equals(uuid(row, "reservationId").toString()) || !terms.policyVersion().equals(row.get("policyVersion"))
                    || nonnegative(row, "points") != terms.payPoints()) throw unconfirmed();
            var plan = tx.get(PLANS, entry.getKey());
            if (plan == null) throw unconfirmed();
            for (String field : java.util.List.of("reservationId", "paymentId", "approvalId", "grantId", "actionId", "targetRunId", "workflowId", "generation", "customerId"))
                if (!java.util.Objects.equals(row.get(field), plan.get(field))) throw unconfirmed();
            if ("RESERVED".equals(row.get("state"))) {
                VirtualGrantTransactionJournal.requireAccountingReservation(tx, uuid(row, "reservationId"));
                if (!"RESERVED".equals(plan.get("reservationState")) || !"RESERVED".equals(plan.get("approvalState"))) throw unconfirmed();
                reserved = add(reserved, terms.payPoints());
            } else if ("CONSUMED".equals(row.get("state"))) {
                boolean coherent = VirtualGrantTransactionJournal.committedPaymentDomains(tx).stream().anyMatch(p ->
                        p.reservationId().toString().equals(entry.getKey()) && p.workflowId().equals(scope.workflowId())
                        && Integer.valueOf(p.generation()).equals(row.get("generation")) && p.customerId().equals(scope.customerId()));
                if (!coherent) throw unconfirmed();
                consumed = add(consumed, terms.payPoints());
            } else throw unconfirmed();
        }
        for (var reference : VirtualGrantTransactionJournal.typedReferences(tx)) {
            if (!reference.workflowId().equals(scope.workflowId())) continue;
            validateIdentityScope(tx, new VirtualWorkflowLane.Scope(reference.workflowId(), reference.generation(), reference.customerId()), current, terms);
            var grant = tx.get("virtual_grant_profile_grants", reference.grantId().toString());
            if (grant == null) throw unconfirmed();
            if ("CONSUMED".equals(grant.get("state"))) {
                if ("EVALUATE_KYC".equals(grant.get("action"))) {
                    var markerRow = tx.get(PREPARATIONS, reference.targetRunId().toString());
                    if (markerRow == null) throw unconfirmed();
                    var marker = decodeMarker(markerRow);
                    if (!marker.identity().grantId().equals(reference.grantId()) || reference.resultId() == null) throw unconfirmed();
                    VirtualGrantTransactionJournal.requireAccountingConsumption(tx, reference.grantId(), reference.resultId(), phase);
                } else if ("CREATE_LOAN_RECOMMENDATION".equals(grant.get("action"))) {
                    if (reference.resultId() == null) throw unconfirmed();
                    VirtualGrantTransactionJournal.requireAccountingConsumption(tx, reference.grantId(), reference.resultId(), phase);
                    if (!loan && !VirtualGrantTransactionJournal.accountingConsumptionIsPending(
                            tx, reference.grantId(), reference.resultId(), phase)) throw unconfirmed();
                }
            }
        }
        int used = add(charges, consumed);
        for (var row : tx.rows(PREPARATIONS).values()) {
            var marker = decodeMarker(row);
            if (scope.workflowId().equals(marker.identity().workflowId()) && marker.usedRiskAfter() > used) throw unconfirmed();
        }
        if (nonnegative(workflow, "usedRisk") != used || nonnegative(workflow, "reservedRisk") != reserved
                || nonnegative(workflow, "kycRuns") != count) throw unconfirmed();
        return new Counters(used, reserved, count, kyc, loan);
    }
    private static void validateRow(TransactionalStore.Tx tx, Map<String,Object> row,
                                    VirtualWorkflowLane.Scope current, SimulationSpec.RiskTerms terms) {
        requireScopeShape(row);
        validateIdentityScope(tx, new VirtualWorkflowLane.Scope(uuid(row, "workflowId"), nonnegative(row, "generation"),
                (String) row.get("customerId")), current, terms);
    }
    private static void validateIdentity(TransactionalStore.Tx tx, CommandIdentity i,
                                         VirtualWorkflowLane.Scope current, SimulationSpec.RiskTerms terms) {
        validateIdentityScope(tx, new VirtualWorkflowLane.Scope(i.workflowId(), i.generation(), i.customerId()), current, terms);
    }
    private static void validateIdentityScope(TransactionalStore.Tx tx, VirtualWorkflowLane.Scope own,
                                              VirtualWorkflowLane.Scope current, SimulationSpec.RiskTerms terms) {
        if (!own.workflowId().equals(current.workflowId()) || !own.customerId().equals(current.customerId())
                || own.generation() > current.generation()
                || !VirtualGrantGenerationHistory.validate(tx, own).terms().equals(terms)) throw unconfirmed();
    }
    private static void validateMarkerSource(TransactionalStore.Tx tx,
            com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.PreparationMarker marker,
            SimulationSpec.RiskTerms terms) {
        var i = marker.identity();
        var own = VirtualGrantGenerationHistory.validate(tx, new VirtualWorkflowLane.Scope(i.workflowId(), i.generation(), i.customerId()));
        var input = tx.get(INPUTS, i.targetRunId().toString());
        if (input == null || !(input.get("canonicalInput") instanceof Map<?,?> canonical)
                || !terms.policyVersion().equals(canonical.get("policyVersion"))
                || !(canonical.get("documents") instanceof java.util.List<?> documents) || documents.size() != 1
                || !(documents.get(0) instanceof Map<?,?> document)
                || !own.sourceDocId().toString().equals(document.get("documentId"))
                || !Integer.valueOf(own.sourceVersion()).equals(document.get("documentVersion"))) throw unconfirmed();
    }
}
