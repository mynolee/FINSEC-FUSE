package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion;
import java.util.Arrays;
import java.util.Objects;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;

/** Explicit mock-payment reference completion; never real payment or commit authority. */
public final class SyntheticMockPaymentTransactionService {
    private final OwnedGrantTransactionPort port;
    private final PaymentFactResolver resolver;
    public SyntheticMockPaymentTransactionService(OwnedGrantTransactionPort port, PaymentFactResolver resolver) {
        this.port = Objects.requireNonNull(port); this.resolver = Objects.requireNonNull(resolver);
    }
    private void current(ServerContext context, PaymentCommand command, OwnedTx tx) {
        if (context == null || !command.stage().identity().actorId().equals(context.actorId()))
            throw OwnedGrantTransactionPort.stop(Status.REFUSED_BEFORE_ADMISSION);
        Gate gate = resolver.current(context, command, tx);
        if (gate != Gate.CLEAR) throw OwnedGrantTransactionPort.stop(gate == Gate.REFUSED
                ? Status.REFUSED_BEFORE_ADMISSION : Status.UNCONFIRMED_BEFORE_ADMISSION);
    }
    private com.finsec.fuse.reimplementation.auth.SyntheticMockPaymentReceiptCodec.Prepared requested(PaymentCommand command) {
        try { return prepareRequested(command); }
        catch (IllegalArgumentException mismatch) { throw OwnedGrantTransactionPort.stop(Status.IDENTITY_CONFLICT); }
    }
    private Receipt checkedPrior(PaymentCommand command, Receipt prior) {
        if (prior.kind() != ReceiptKind.CONSUMPTION || prior.result() == null) throw OwnedGrantTransactionPort.stop(Status.IDENTITY_CONFLICT);
        var expected = requested(command); var r = prior.result();
        if (!r.resultId().equals(command.expectedReceipt().paymentId()) || !RECEIPT_BINDING_PROFILE.equals(r.bindingProfile())
                || r.businessConclusion() != BusinessConclusion.POSITIVE
                || !Arrays.equals(expected.canonicalBytes(), r.bindingBytes()) || !Arrays.equals(expected.receiptDigest(), r.bindingDigest()))
            throw OwnedGrantTransactionPort.stop(Status.IDENTITY_CONFLICT);
        return prior;
    }
    public StageOutcome completePayment(ServerContext context, PaymentCommand command) {
        Objects.requireNonNull(command);
        return port.transact(command.stage(), tx -> {
            current(context, command, tx);
            requested(command);
            Receipt prior = tx.lookup(command.stage());
            if (prior != null) return StageOutcome.of(Status.VIRTUAL_REPLAYED_IN_PROCESS, checkedPrior(command, prior), EffectKnowledge.COMMITTED_IN_PROCESS);
            tx.admitFresh(command.stage());
            ResolvedPayment resolved = resolver.resolve(context, command, tx);
            checkResolved(command, resolved);
            return StageOutcome.of(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                    tx.commitMockPayment(command.stage(), resolved), EffectKnowledge.COMMITTED_IN_PROCESS);
        });
    }
    public StageOutcome reconcile(ServerContext context, PaymentCommand command) {
        Objects.requireNonNull(command);
        return port.transact(command.stage(), tx -> {
            current(context, command, tx); requested(command);
            Receipt prior = tx.lookup(command.stage());
            return prior == null ? StageOutcome.of(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, null, EffectKnowledge.UNKNOWN)
                    : StageOutcome.of(Status.VIRTUAL_REPLAYED_IN_PROCESS, checkedPrior(command, prior), EffectKnowledge.COMMITTED_IN_PROCESS);
        });
    }
}
