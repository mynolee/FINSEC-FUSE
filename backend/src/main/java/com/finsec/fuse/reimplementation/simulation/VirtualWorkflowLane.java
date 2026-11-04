package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.grant.VirtualGrantGenerationHistory;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Same-transaction business-writer ownership; no authority or durable-store proof. */
public final class VirtualWorkflowLane {
    private static final String TABLE = "virtual_workflow_lanes";
    private static final String WORKFLOWS = "virtual_workflows";
    private static final Set<String> KEYS = Set.of("workflowId", "generation", "customerId", "lane");
    public enum Lane { LEGACY, TYPED }
    public record Scope(UUID workflowId, int generation, String customerId) {
        public Scope {
            if (workflowId == null || generation < 1 || customerId == null || customerId.isBlank())
                throw SimulationFailure.invalid();
        }
        @Override public String toString() { return "Scope[REDACTED]"; }
    }
    private VirtualWorkflowLane() { }

    /** Registers only before creation of a new workflow in this same caller-owned transaction. */
    public static void registerTyped(TransactionalStore.Tx tx, Scope scope) {
        inputs(tx, scope);
        if (tx.get(WORKFLOWS, scope.workflowId().toString()) != null
                || tx.get(TABLE, scope.workflowId().toString()) != null) throw SimulationFailure.invalid();
        tx.put(TABLE, scope.workflowId().toString(), Map.of("workflowId", scope.workflowId().toString(),
                "generation", scope.generation(), "customerId", scope.customerId(), "lane", Lane.TYPED.name()));
    }

    /** Historical rows without a lane remain legacy; this never writes or advances a lane. */
    public static void requireLegacy(TransactionalStore.Tx tx, Scope scope) {
        inputs(tx, scope);
        checkWorkflow(tx, scope);
        var row = tx.get(TABLE, scope.workflowId().toString());
        if (row != null && lane(row, scope) != Lane.LEGACY) throw SimulationFailure.invalid();
    }

    /** Requires an actual workflow and its exact typed lane in this transaction. */
    public static void requireTyped(TransactionalStore.Tx tx, Scope scope) {
        inputs(tx, scope);
        boolean actualWorkflow = checkWorkflow(tx, scope);
        var row = tx.get(TABLE, scope.workflowId().toString());
        if (!actualWorkflow || row == null || lane(row, scope) != Lane.TYPED)
            throw SimulationFailure.invalid();
        VirtualGrantGenerationHistory.checkCurrentScope(tx, scope);
    }

    /** Only the same atomic continuation may replace the exact old typed generation. */
    public static void advanceTyped(TransactionalStore.Tx tx, Scope oldScope, Scope nextScope) {
        inputs(tx, oldScope); inputs(tx, nextScope);
        final int next;
        try { next = Math.addExact(oldScope.generation(), 1); }
        catch (ArithmeticException overflow) { throw SimulationFailure.invalid(); }
        if (!oldScope.workflowId().equals(nextScope.workflowId()) || !oldScope.customerId().equals(nextScope.customerId())
                || nextScope.generation() != next || !checkWorkflow(tx, nextScope)) throw SimulationFailure.invalid();
        var row = tx.get(TABLE, oldScope.workflowId().toString());
        if (row == null || lane(row, oldScope) != Lane.TYPED) throw SimulationFailure.invalid();
        var head = VirtualGrantGenerationHistory.readHead(tx, oldScope.workflowId());
        if (head == null || !head.scope().equals(nextScope)
                || !head.rootGrantId().equals(VirtualGrantGenerationHistory.validate(tx, nextScope).rootGrantId()))
            throw SimulationFailure.invalid();
        tx.put(TABLE, nextScope.workflowId().toString(), Map.of("workflowId", nextScope.workflowId().toString(),
                "generation", nextScope.generation(), "customerId", nextScope.customerId(), "lane", Lane.TYPED.name()));
    }

    private static void inputs(TransactionalStore.Tx tx, Scope scope) {
        if (tx == null || scope == null) throw SimulationFailure.invalid();
    }
    private static boolean checkWorkflow(TransactionalStore.Tx tx, Scope scope) {
        var row = tx.get(WORKFLOWS, scope.workflowId().toString());
        if (row == null) return false;
        if (!scope.workflowId().toString().equals(row.get("workflowId"))
                || !(row.get("generation") instanceof Integer generation) || generation != scope.generation()
                || !scope.customerId().equals(row.get("customerId"))) throw SimulationFailure.invalid();
        return true;
    }
    private static Lane lane(Map<String, Object> row, Scope scope) {
        if (!row.keySet().equals(KEYS) || !scope.workflowId().toString().equals(row.get("workflowId"))
                || !(row.get("generation") instanceof Integer generation) || generation != scope.generation()
                || !scope.customerId().equals(row.get("customerId"))) throw SimulationFailure.invalid();
        if (Lane.TYPED.name().equals(row.get("lane"))) return Lane.TYPED;
        if (Lane.LEGACY.name().equals(row.get("lane"))) return Lane.LEGACY;
        throw SimulationFailure.invalid();
    }
}
