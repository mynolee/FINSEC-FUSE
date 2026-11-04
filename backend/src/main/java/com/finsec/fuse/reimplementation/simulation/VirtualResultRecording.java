package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import static com.finsec.fuse.reimplementation.simulation.SimulationRows.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;
import static com.finsec.fuse.reimplementation.simulation.VirtualWorkflowService.*;

/** Typed virtual domain recording only: no grant lifecycle, issuer or authority proof. */
public final class VirtualResultRecording {
    private VirtualResultRecording() {}
    public enum AgentRole { KYC, LOAN }

    public record Scope(UUID workflowId, int generation) {
        public Scope {
            Objects.requireNonNull(workflowId);
            if (generation < 1) throw SimulationFailure.invalid();
        }
        @Override public String toString() { return "Scope[REDACTED]"; }
    }

    public record AgentResult(UUID resultId, UUID runId, Scope scope, AgentRole role,
                              Map<String, Object> body, String evidenceBundleHash) {
        public AgentResult {
            Objects.requireNonNull(resultId); Objects.requireNonNull(runId);
            Objects.requireNonNull(scope); Objects.requireNonNull(role);
            body = CanonicalJson.immutableObject(Objects.requireNonNull(body));
            Objects.requireNonNull(evidenceBundleHash);
        }
        @Override public String toString() { return "AgentResult[VIRTUAL_DOMAIN_ONLY]"; }
    }

    public record MockPayment(UUID paymentId, UUID runId, UUID actionId, Scope scope,
                              UUID reservationId, UUID approvalId, String customerId,
                              long amountKrw, UUID payoutAccountId, Instant createdAt) {
        public MockPayment {
            Objects.requireNonNull(paymentId); Objects.requireNonNull(runId);
            Objects.requireNonNull(actionId); Objects.requireNonNull(scope);
            Objects.requireNonNull(reservationId); Objects.requireNonNull(approvalId);
            Objects.requireNonNull(customerId); Objects.requireNonNull(payoutAccountId);
            Objects.requireNonNull(createdAt);
        }
        @Override public String toString() { return "MockPayment[VIRTUAL_DOMAIN_ONLY]"; }
    }

    /** Uses the caller's existing transaction; does not commit, dispatch or authorize. */
    public interface Port {
        void recordAgentResult(TransactionalStore.Tx tx, AgentResult result);
        void recordMockPayment(TransactionalStore.Tx tx, MockPayment payment);
    }

    public static Port transactionPort() { return RECORDING; }

    private static void runBinding(TransactionalStore.Tx tx, UUID runId, Scope scope, String role) {
        var run = require(tx, RUNS, runId);
        if (!sameWorkflow(run, scope.workflowId()) || integer(run, "generation") != scope.generation()
                || !role.equals(run.get("role"))) throw SimulationFailure.invalid();
    }

    private static final Port RECORDING = new Port() {
        @Override public void recordAgentResult(TransactionalStore.Tx tx, AgentResult result) {
            Objects.requireNonNull(tx); Objects.requireNonNull(result);
            runBinding(tx, result.runId(), result.scope(), result.role().name());
            tx.put(RESULTS, result.resultId().toString(), object(
                    "resultId", result.resultId().toString(), "runId", result.runId().toString(),
                    "workflowId", result.scope().workflowId().toString(), "generation", result.scope().generation(),
                    "role", result.role().name(), "body", result.body(),
                    "resultHash", CanonicalJson.sha256(result.body()), "evidenceBundleHash", result.evidenceBundleHash()));
        }

        @Override public void recordMockPayment(TransactionalStore.Tx tx, MockPayment payment) {
            Objects.requireNonNull(tx); Objects.requireNonNull(payment);
            runBinding(tx, payment.runId(), payment.scope(), "PAYMENT");
            var reservation = require(tx, RESERVATIONS, payment.reservationId());
            if (!sameWorkflow(reservation, payment.scope().workflowId())
                    || integer(reservation, "generation") != payment.scope().generation()
                    || !payment.runId().toString().equals(reservation.get("runId"))
                    || !payment.approvalId().toString().equals(reservation.get("approvalId")))
                throw SimulationFailure.invalid();
            tx.put(PAYMENTS, payment.paymentId().toString(), object(
                    "paymentId", payment.paymentId().toString(), "workflowId", payment.scope().workflowId().toString(),
                    "generation", payment.scope().generation(), "reservationId", payment.reservationId().toString(),
                    "approvalId", payment.approvalId().toString(), "runId", payment.runId().toString(),
                    "actionId", payment.actionId().toString(), "customerId", payment.customerId(),
                    "amountKrw", payment.amountKrw(), "payoutAccountId", payment.payoutAccountId().toString(),
                    "createdAt", payment.createdAt().toString(), "executionMode", VirtualTransactionalStore.MODE));
        }
    };
}
