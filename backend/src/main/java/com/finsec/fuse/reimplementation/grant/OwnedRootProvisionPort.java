package com.finsec.fuse.reimplementation.grant;

import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.*;

/** One owned root-purpose transaction in the existing global request namespace. */
public interface OwnedRootProvisionPort extends OwnedGrantTransactionPort {
    interface OwnedRootTx {
        RootReceipt lookupExactRoot(RootCommand command);
        void admitFreshRoot(RootCommand command);
        CurrentBindings readCurrentRootProvisionBindings(RootCommand command);
        RootReceipt recordRootAndWorkflow(RootCommand command, ResolvedRootProvision resolved);
    }
    interface RootWork { RootOutcome apply(OwnedRootTx tx); }
    RootOutcome provisionRoot(RootCommand command, RootWork work);
}
