package com.finsec.fuse.reimplementation.grant;

import java.util.Objects;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.*;

/** Explicit preparation only; no automatic job, provider invocation or grant consumption. */
public final class SyntheticKycPreparationService {
    private final OwnedKycPreparationPort port;
    private final PreparationResolver resolver;
    public SyntheticKycPreparationService(OwnedKycPreparationPort port, PreparationResolver resolver) {
        this.port = Objects.requireNonNull(port); this.resolver = Objects.requireNonNull(resolver);
    }
    private void current(ServerContext context, PreparationCommand command, OwnedKycPreparationPort.OwnedPreparationTx tx) {
        if (context == null || !command.identity().actorId().equals(context.actorId()))
            throw OwnedGrantTransactionPort.stop(Status.REFUSED_BEFORE_ADMISSION);
        Gate gate = resolver.current(context, command, tx);
        if (gate != Gate.CLEAR) throw OwnedGrantTransactionPort.stop(gate == Gate.REFUSED
                ? Status.REFUSED_BEFORE_ADMISSION : Status.UNCONFIRMED_BEFORE_ADMISSION);
    }
    private PreparationReceipt checkedPrior(PreparationCommand command, PreparedInput input, PreparationReceipt prior) {
        if (!command.identity().equals(prior.identity()) || !descriptor(command).equals(prior.descriptor())
                || !input.inputSnapshotHash().equals(prior.inputSnapshotHash())) throw OwnedGrantTransactionPort.stop(Status.IDENTITY_CONFLICT);
        return prior;
    }
    public PreparationOutcome prepare(ServerContext context, PreparationCommand command) {
        Objects.requireNonNull(command);
        return port.prepareKyc(command, tx -> {
            current(context, command, tx);
            var input = prepareRequested(command);
            var prior = tx.lookupPreparation(command);
            if (prior != null) return new PreparationOutcome(Status.VIRTUAL_REPLAYED_IN_PROCESS,
                    checkedPrior(command, input, prior), PreparationEffect.COMMITTED_IN_PROCESS);
            tx.admitFreshPreparation(command);
            current(context, command, tx);
            var bindings = tx.readPreparationBindings(command);
            checkBindings(command, bindings);
            Refusal refusal = !"KYC_PENDING".equals(bindings.workflowState()) || bindings.held()
                    || bindings.counters().kycRuns() >= bindings.riskTerms().maxAutomaticKycRuns()
                    ? Refusal.KYC_PRECONDITION_FAILED : Refusal.NONE;
            int cost = bindings.counters().kycCharged() ? 0 : bindings.riskTerms().kycPoints();
            if (refusal == Refusal.NONE && (long) bindings.counters().usedRisk() + bindings.counters().reservedRisk() + cost > bindings.riskLimit())
                refusal = Refusal.RISK_LIMIT_EXCEEDED;
            PreparationReceipt receipt = refusal == Refusal.NONE
                    ? tx.recordPreparation(command, new ResolvedPreparation(bindings, input))
                    : tx.recordRefusal(command, bindings, refusal);
            return new PreparationOutcome(Status.VIRTUAL_COMMITTED_IN_PROCESS, receipt, PreparationEffect.COMMITTED_IN_PROCESS);
        });
    }
    public PreparationOutcome reconcile(ServerContext context, PreparationCommand command) {
        Objects.requireNonNull(command);
        return port.prepareKyc(command, tx -> {
            current(context, command, tx);
            var input = prepareRequested(command);
            var prior = tx.lookupPreparation(command);
            return prior == null ? new PreparationOutcome(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, null, PreparationEffect.UNKNOWN)
                    : new PreparationOutcome(Status.VIRTUAL_REPLAYED_IN_PROCESS, checkedPrior(command, input, prior), PreparationEffect.COMMITTED_IN_PROCESS);
        });
    }
}
