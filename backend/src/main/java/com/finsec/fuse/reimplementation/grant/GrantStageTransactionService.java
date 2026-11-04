package com.finsec.fuse.reimplementation.grant;

import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.RunStatus.VALIDATED;

/** Explicit server entry; reference outcomes are never operational grant authority. */
public final class GrantStageTransactionService {
    private final OwnedGrantTransactionPort port;
    private final CurrentFactResolver resolver;
    public GrantStageTransactionService(OwnedGrantTransactionPort port, CurrentFactResolver resolver) {
        this.port = Objects.requireNonNull(port); this.resolver = Objects.requireNonNull(resolver);
    }
    private void current(ServerContext context, StageCommand command, OwnedTx tx) {
        if (context == null || !command.identity().actorId().equals(context.actorId()))
            throw OwnedGrantTransactionPort.stop(Status.REFUSED_BEFORE_ADMISSION);
        Gate gate = resolver.current(context, command, tx);
        if (gate != Gate.CLEAR) throw OwnedGrantTransactionPort.stop(gate == Gate.REFUSED
                ? Status.REFUSED_BEFORE_ADMISSION : Status.UNCONFIRMED_BEFORE_ADMISSION);
    }
    private StageOutcome replay(Receipt receipt) {
        return StageOutcome.of(Status.VIRTUAL_REPLAYED_IN_PROCESS, receipt, EffectKnowledge.COMMITTED_IN_PROCESS);
    }
    /** Agent-result reference stages only; no mock-payment finality profile is fabricated. */
    public StageOutcome completeStage(ServerContext context, StageCommand command, OutsidePreparedResult prepared) {
        Objects.requireNonNull(command);
        return port.transact(command, tx -> {
            current(context, command, tx);
            StageOutcome prior = tx.lookupRecordedOutcome(command);
            if (prior != null) {
                if (prior.evaluationRefusal() != null) {
                    if (command.action() != com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction.CREATE_LOAN_RECOMMENDATION
                            || !prior.evaluationRefusal().identity().equals(command.identity()))
                        throw OwnedGrantTransactionPort.stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
                    return prior;
                }
                if (prior.receipt() == null || prior.receipt().kind() != ReceiptKind.CONSUMPTION)
                    throw OwnedGrantTransactionPort.stop(Status.IDENTITY_CONFLICT);
                return replay(prior.receipt());
            }
            if (prepared == null) throw OwnedGrantTransactionPort.stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            tx.admitFresh(command);
            ResolvedStage stage = resolver.resolve(context, command, prepared, tx);
            if (prepared == null || stage == null || stage.runStatus() != VALIDATED
                    || stage.resultStatus() != com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.ResultStatus.VALIDATED
                    || command.action() == com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction.EXECUTE_MOCK_PAYMENT
                    || !"AGENT_RESULT_BINDING_RECORD_1".equals(stage.result().bindingProfile())
                    || !same(prepared, stage.result())) throw OwnedGrantTransactionPort.stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            return tx.commitEvaluation(command, stage);
        });
    }
    public StageOutcome reconcile(ServerContext context, StageCommand command) {
        Objects.requireNonNull(command);
        return port.transact(command, tx -> {
            current(context, command, tx);
            StageOutcome prior = tx.lookupRecordedOutcome(command);
            return prior == null ? StageOutcome.of(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, null, EffectKnowledge.UNKNOWN) : prior;
        });
    }
    /** Separate explicit issuance; completion never allocates a successor. */
    public StageOutcome issueSuccessor(ServerContext context, StageCommand command, UUID parentGrantId, GrantSnapshot child) {
        return issueSuccessor(context, command, parentGrantId, child, null);
    }
    public StageOutcome issueSuccessor(ServerContext context, StageCommand command, UUID parentGrantId, GrantSnapshot child,
            PaymentIssuanceProof proof) {
        Objects.requireNonNull(command);
        return port.transact(command, tx -> {
            current(context, command, tx);
            Receipt prior = tx.lookup(command);
            if (prior != null) {
                if (prior.kind() != ReceiptKind.ISSUANCE || !Objects.equals(parentGrantId, prior.parentGrantId()))
                    throw OwnedGrantTransactionPort.stop(Status.IDENTITY_CONFLICT);
                return replay(prior);
            }
            tx.admitFresh(command);
            Gate gate = resolver.checkIssuance(context, command, parentGrantId, child, tx);
            if (gate != Gate.CLEAR) throw OwnedGrantTransactionPort.stop(gate == Gate.REFUSED
                    ? Status.REFUSED_BEFORE_ADMISSION : Status.UNCONFIRMED_BEFORE_ADMISSION);
            return StageOutcome.of(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                    tx.issueSuccessor(command, parentGrantId, child, proof), EffectKnowledge.COMMITTED_IN_PROCESS);
        });
    }
    private static boolean same(OutsidePreparedResult a, OutsidePreparedResult b) {
        return a.resultId().equals(b.resultId()) && a.businessConclusion() == b.businessConclusion()
                && a.bindingProfile().equals(b.bindingProfile()) && Arrays.equals(a.bindingBytes(), b.bindingBytes())
                && Arrays.equals(a.bindingDigest(), b.bindingDigest());
    }
}
