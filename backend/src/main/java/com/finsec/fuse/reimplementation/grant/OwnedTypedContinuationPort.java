package com.finsec.fuse.reimplementation.grant;

import static com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.*;

/** Continuation over the existing owned executor and global request namespace. */
public interface OwnedTypedContinuationPort extends OwnedKycPreparationPort {
    interface OwnedContinuationTx {
        ContinuationReceipt lookupExactContinuation(ContinuationCommand command);
        void admitFreshContinuation(ContinuationCommand command);
        CurrentBindings readContinuationBindings(ContinuationCommand command);
        ContinuationReceipt recordContinuation(ContinuationCommand command, ResolvedContinuation resolved);
        ContinuationReceipt recordDeniedContinuation(ContinuationCommand command, CurrentBindings bindings);
    }
    interface ContinuationWork { ContinuationOutcome apply(OwnedContinuationTx tx); }
    ContinuationOutcome continueWorkflow(ContinuationCommand command, ContinuationWork work);
}
