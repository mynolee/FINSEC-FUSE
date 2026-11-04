package com.finsec.fuse.reimplementation.grant;

import static com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.*;

/** Explicit KYC preparation phase over the same owned global request journal. */
public interface OwnedKycPreparationPort extends OwnedMockPaymentPlanPort {
    interface OwnedPreparationTx {
        PreparationReceipt lookupPreparation(PreparationCommand command);
        void admitFreshPreparation(PreparationCommand command);
        FreshBindings readPreparationBindings(PreparationCommand command);
        PreparationReceipt recordPreparation(PreparationCommand command, ResolvedPreparation prepared);
        PreparationReceipt recordRefusal(PreparationCommand command, FreshBindings bindings, Refusal reason);
    }
    interface PreparationWork { PreparationOutcome apply(OwnedPreparationTx tx); }
    PreparationOutcome prepareKyc(PreparationCommand command, PreparationWork work);
}
