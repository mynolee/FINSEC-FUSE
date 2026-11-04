package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import java.util.List;

import static com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;

/** One owned transaction; successful continuation is inert and never dispatches work. */
public final class SyntheticTypedContinuationService {
    public interface ContinuationServerContext extends ServerContext { String subjectId(); }
    /**
     * Current checks ordinary time, actor/owner/credential and current disclosure before history.
     * It must not fence history by an old generation's active head. Fresh-only owned read/record
     * rechecks prospective source/agent/workflow controls and the exact expected head; unused
     * old run/result holds and a remediated old-source hold are not automatically inherited.
     * Supplied local facts only: these callbacks do not acquire external facts under the transaction.
     */
    public interface CurrentContinuationFactResolver {
        Gate current(ContinuationServerContext context, ContinuationCommand command,
                     OwnedTypedContinuationPort.OwnedContinuationTx tx);
        ResolvedContinuation resolve(ContinuationServerContext context, ContinuationCommand command,
                     CurrentBindings bindings, OwnedTypedContinuationPort.OwnedContinuationTx tx);
    }
    private final OwnedTypedContinuationPort port;
    private final CurrentContinuationFactResolver resolver;
    private final List<SimulationSpec.Application> preparedApplications;
    /** Compatibility entry: existing history remains queryable, but fresh publication has no catalog admission. */
    public SyntheticTypedContinuationService(OwnedTypedContinuationPort port, CurrentContinuationFactResolver resolver) {
        if (port==null || resolver==null) throw invalid();
        this.port=port; this.resolver=resolver; this.preparedApplications=null;
    }
    /** Captures the existing immutable server-owned catalog before any request or transaction starts. */
    public SyntheticTypedContinuationService(OwnedTypedContinuationPort port, CurrentContinuationFactResolver resolver,
                                             SimulationSpec.Catalog catalog) {
        if (port==null || resolver==null || catalog==null) throw invalid();
        this.port=port; this.resolver=resolver;
        this.preparedApplications=List.copyOf(catalog.applications());
    }
    private void requirePreparedCandidate(ContinuationCommand command) {
        // Full immutable application equality includes domain fields and source identity/content/hash.
        // A reviewedSafe flag or hold-free coordinate alone is never a catalog admission.
        if (preparedApplications==null || preparedApplications.stream().noneMatch(command.application()::equals))
            throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
    }
    private void current(ContinuationServerContext context, ContinuationCommand command,
                         OwnedTypedContinuationPort.OwnedContinuationTx tx) {
        if (context==null || context.subjectId()==null || context.subjectId().isBlank()
                || !command.identity().actorId().equals(context.actorId())) throw stop(Status.REFUSED_BEFORE_ADMISSION);
        Gate gate=resolver.current(context,command,tx);
        if (gate!=Gate.CLEAR) throw stop(gate==Gate.REFUSED ? Status.REFUSED_BEFORE_ADMISSION:Status.UNCONFIRMED_BEFORE_ADMISSION);
    }
    public ContinuationOutcome continueWorkflow(ContinuationServerContext context, ContinuationCommand command) {
        if (command==null) throw invalid();
        return port.continueWorkflow(command,tx->{
            current(context,command,tx);
            ContinuationReceipt prior=tx.lookupExactContinuation(command);
            if (prior!=null) return replay(command,prior);
            requirePreparedCandidate(command);
            tx.admitFreshContinuation(command);
            CurrentBindings bindings=tx.readContinuationBindings(command);
            try { checkBindings(command,bindings); }
            catch (IllegalArgumentException rejected) { throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION); }
            // Fresh-only P1A: no denied receipt, head establishment or counter change.
            if (bindings.pendingDisposition()==PendingDisposition.COHERENT_NONEMPTY)
                throw stop(Status.REFUSED_BEFORE_ADMISSION);
            if (bindings.pendingDisposition()!=PendingDisposition.VERIFIED_EMPTY
                    || bindings.resumeReadiness()==ResumeReadiness.UNCONFIRMED)
                throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            current(context,command,tx);
            if (bindings.resumeReadiness()==ResumeReadiness.KNOWN_NOT_READY) {
                ContinuationReceipt denied=tx.recordDeniedContinuation(command,bindings);
                return committed(command,denied,ContinuationKind.DENIED);
            }
            ResolvedContinuation resolved=resolver.resolve(context,command,bindings,tx);
            if (resolved==null || !resolved.command().equals(command) || resolved.currentBindings()!=bindings
                    || !resolved.issuerFacts().binding().subjectId().equals(context.subjectId()))
                throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            current(context,command,tx);
            requirePreparedCandidate(command);
            try { checkResolved(command,resolved); }
            catch (IllegalArgumentException rejected) { throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION); }
            return committed(command,tx.recordContinuation(command,resolved),ContinuationKind.ADVANCED);
        });
    }
    /** No new admission or publication; a possible prior publication remains reconciliation-only. */
    public ContinuationOutcome reconcileContinuation(ContinuationServerContext context, ContinuationCommand command) {
        if (command==null) throw invalid();
        return port.continueWorkflow(command,tx->{
            current(context,command,tx);
            ContinuationReceipt receipt=tx.lookupExactContinuation(command);
            return receipt==null ? new ContinuationOutcome(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH,null,ContinuationEffect.UNKNOWN)
                    : replay(command,receipt);
        });
    }
    private ContinuationOutcome replay(ContinuationCommand command,ContinuationReceipt receipt) {
        if (!receipt.matches(command)) throw stop(Status.IDENTITY_CONFLICT);
        return new ContinuationOutcome(Status.VIRTUAL_REPLAYED_IN_PROCESS,receipt,ContinuationEffect.COMMITTED_IN_PROCESS);
    }
    private ContinuationOutcome committed(ContinuationCommand command,ContinuationReceipt receipt,ContinuationKind kind) {
        if (receipt==null || receipt.kind()!=kind || !receipt.matches(command)) throw stop(Status.TRANSACTION_INVARIANT_UNCONFIRMED);
        return new ContinuationOutcome(Status.VIRTUAL_COMMITTED_IN_PROCESS,receipt,ContinuationEffect.COMMITTED_IN_PROCESS);
    }
}
