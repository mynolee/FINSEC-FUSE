package com.finsec.fuse.reimplementation.grant;

import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;

/** Explicit initialization coordinator over one owned reference transaction. */
public final class SyntheticRootProvisionService {
    public interface RootServerContext extends ServerContext { String subjectId(); }
    /** Supplied local snapshots only; callbacks must not acquire provider/key/DB facts under the transaction. */
    public interface CurrentRootFactResolver {
        Gate current(RootServerContext context, RootCommand command, OwnedRootProvisionPort.OwnedRootTx tx);
        ResolvedRootProvision resolve(RootServerContext context, RootCommand command,
                                      CurrentBindings bindings, OwnedRootProvisionPort.OwnedRootTx tx);
    }
    private final OwnedRootProvisionPort port;
    private final CurrentRootFactResolver resolver;
    public SyntheticRootProvisionService(OwnedRootProvisionPort port, CurrentRootFactResolver resolver) {
        if (port == null || resolver == null) throw invalid();
        this.port = port; this.resolver = resolver;
    }
    private void current(RootServerContext context, RootCommand command, OwnedRootProvisionPort.OwnedRootTx tx) {
        if (context == null || context.subjectId() == null || context.subjectId().isBlank()
                || !command.identity().actorId().equals(context.actorId())) throw stop(Status.REFUSED_BEFORE_ADMISSION);
        Gate gate = resolver.current(context, command, tx);
        if (gate != Gate.CLEAR) throw stop(gate == Gate.REFUSED ? Status.REFUSED_BEFORE_ADMISSION : Status.UNCONFIRMED_BEFORE_ADMISSION);
    }
    public RootOutcome provisionRoot(RootServerContext context, RootCommand command) {
        if (command == null) throw invalid();
        return port.provisionRoot(command, tx -> {
            current(context, command, tx);
            RootReceipt prior = tx.lookupExactRoot(command);
            if (prior != null) return replay(command, prior);
            tx.admitFreshRoot(command);
            CurrentBindings bindings = tx.readCurrentRootProvisionBindings(command);
            if (bindings == null || !bindings.allAbsent()) throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            ResolvedRootProvision resolved = resolver.resolve(context, command, bindings, tx);
            if (resolved == null || !resolved.command().equals(command) || resolved.currentBindings() != bindings)
                throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            current(context, command, tx);
            validateIssuance(context, command, resolved);
            RootReceipt receipt = tx.recordRootAndWorkflow(command, resolved);
            if (receipt == null || !receipt.matches(command)) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
            return new RootOutcome(Status.VIRTUAL_COMMITTED_IN_PROCESS, receipt, RootEffect.COMMITTED_IN_PROCESS);
        });
    }
    public RootOutcome reconcileRoot(RootServerContext context, RootCommand command) {
        if (command == null) throw invalid();
        return port.provisionRoot(command, tx -> {
            current(context, command, tx);
            RootReceipt receipt = tx.lookupExactRoot(command);
            return receipt == null ? new RootOutcome(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, null, RootEffect.UNKNOWN)
                    : replay(command, receipt);
        });
    }
    private RootOutcome replay(RootCommand command, RootReceipt receipt) {
        if (!receipt.matches(command)) throw stop(Status.IDENTITY_CONFLICT);
        return new RootOutcome(Status.VIRTUAL_REPLAYED_IN_PROCESS, receipt, RootEffect.COMMITTED_IN_PROCESS);
    }
    private void validateIssuance(RootServerContext context, RootCommand command, ResolvedRootProvision resolved) {
        if (!resolved.issuerFacts().binding().subjectId().equals(context.subjectId()))
            throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
        try { checkResolved(command, resolved); }
        catch (IllegalArgumentException rejected) { throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION); }
    }
}
