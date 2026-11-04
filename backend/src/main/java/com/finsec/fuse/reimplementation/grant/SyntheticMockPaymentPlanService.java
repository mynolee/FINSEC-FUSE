package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;

/** Explicit non-HTTP review/reservation; no provider, root, consumption or money transfer. */
public final class SyntheticMockPaymentPlanService {
    public interface PlanServerContext extends ServerContext { }
    /** Required server-owned local source; supplied labels do not authenticate permission or evidence. */
    public interface LocalPlanFacts {
        Gate current(PlanServerContext context,CommandIdentity identity,PlanOperation operation,OwnedMockPaymentPlanPort.OwnedPlanTx tx);
        ResolvedEvidence resolveEvidence(PlanServerContext context,CommandIdentity identity,ReviewBindings bindings,OwnedMockPaymentPlanPort.OwnedPlanTx tx);
    }
    private final OwnedMockPaymentPlanPort port;
    private final LocalPlanFacts facts;
    public SyntheticMockPaymentPlanService(OwnedMockPaymentPlanPort port,LocalPlanFacts facts) {
        if(port==null || facts==null)throw invalid(); this.port=port; this.facts=facts;
    }
    private void current(PlanServerContext context,CommandIdentity identity,PlanOperation operation,OwnedMockPaymentPlanPort.OwnedPlanTx tx) {
        if(context==null || !identity.actorId().equals(context.actorId()))throw stop(Status.REFUSED_BEFORE_ADMISSION);
        Gate gate=facts.current(context,identity,operation,tx);
        if(gate!=Gate.CLEAR)throw stop(gate==Gate.REFUSED?Status.REFUSED_BEFORE_ADMISSION:Status.UNCONFIRMED_BEFORE_ADMISSION);
    }
    private EvidenceSnapshot evidence(PlanServerContext context,CommandIdentity identity,ReviewBindings bindings,OwnedMockPaymentPlanPort.OwnedPlanTx tx) {
        var resolved=facts.resolveEvidence(context,identity,bindings,tx);
        if(resolved==null || resolved.bindings()!=bindings)throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
        return resolved.evidence();
    }
    private static PlanOutcome outcome(PlanReceipt receipt,boolean replay) {
        return new PlanOutcome(replay?Status.VIRTUAL_REPLAYED_IN_PROCESS:Status.VIRTUAL_COMMITTED_IN_PROCESS,receipt,PlanEffect.COMMITTED_IN_PROCESS);
    }
    private static void reviewReceipt(ReviewCommand c,PlanReceipt r) {
        if(r==null || r.purpose()!=PlanOperation.REVIEW || !r.identity().equals(c.identity())
                || !r.approval().approvalId().equals(c.approvalId()) || r.approval().decision()!=c.decision()
                || !r.approval().reviewSnapshotHash().equals(c.expectedReviewSnapshotHash())
                || !r.approval().createdAt().equals(c.now()) || !r.approval().expiresAt().equals(c.expiresAt()))throw stop(Status.IDENTITY_CONFLICT);
    }
    private static void reservationReceipt(ReserveCommand c,PlanReceipt r) {
        if(r==null || r.purpose()!=PlanOperation.RESERVE || !r.identity().equals(c.identity()) || !c.domain().equals(r.domain())
                || !r.approval().approvalId().equals(c.domain().approvalId())
                || !r.approval().reviewSnapshotHash().equals(c.expectedReviewSnapshotHash()))throw stop(Status.IDENTITY_CONFLICT);
    }
    public PlanOutcome review(PlanServerContext context,ReviewCommand command) {
        if(command==null)throw invalid();
        return port.review(command,tx->{
            current(context,command.identity(),PlanOperation.REVIEW,tx);
            var prior=tx.lookupReview(command);
            if(prior!=null){reviewReceipt(command,prior);return outcome(prior,true);}
            tx.admitReview(command);
            var bindings=tx.readReviewBindings(command);
            if(bindings==null)throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            var evidence=evidence(context,command.identity(),bindings,tx);
            PreparedReview prepared;
            try{prepared=prepareReview(command,bindings,evidence);}catch(IllegalArgumentException rejected){throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);}
            current(context,command.identity(),PlanOperation.REVIEW,tx);
            var receipt=tx.recordReview(command,prepared);reviewReceipt(command,receipt);return outcome(receipt,false);
        });
    }
    public PlanOutcome reserve(PlanServerContext context,ReserveCommand command) {
        if(command==null)throw invalid();
        return port.reserve(command,tx->{
            current(context,command.identity(),PlanOperation.RESERVE,tx);
            var prior=tx.lookupReservation(command);
            if(prior!=null){reservationReceipt(command,prior);return outcome(prior,true);}
            tx.admitReservation(command);
            var bindings=tx.readReservationBindings(command);
            if(bindings==null)throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);
            var evidence=evidence(context,command.identity(),bindings.review(),tx);
            PreparedReservation prepared;
            try{prepared=prepareReservation(command,bindings,evidence);}catch(IllegalArgumentException rejected){throw stop(Status.UNCONFIRMED_BEFORE_ADMISSION);}
            current(context,command.identity(),PlanOperation.RESERVE,tx);
            var receipt=tx.recordReservation(command,prepared);reservationReceipt(command,receipt);return outcome(receipt,false);
        });
    }
    public PlanOutcome reconcileReview(PlanServerContext context,ReviewCommand command) {
        if(command==null)throw invalid();
        return port.review(command,tx->{current(context,command.identity(),PlanOperation.REVIEW,tx);
            var receipt=tx.lookupReview(command);
            if(receipt==null)return new PlanOutcome(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH,null,PlanEffect.UNKNOWN);
            reviewReceipt(command,receipt);return outcome(receipt,true);});
    }
    public PlanOutcome reconcileReservation(PlanServerContext context,ReserveCommand command) {
        if(command==null)throw invalid();
        return port.reserve(command,tx->{current(context,command.identity(),PlanOperation.RESERVE,tx);
            var receipt=tx.lookupReservation(command);
            if(receipt==null)return new PlanOutcome(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH,null,PlanEffect.UNKNOWN);
            reservationReceipt(command,receipt);return outcome(receipt,true);});
    }
    public boolean actualAuthority(){return false;} public boolean durable(){return false;}
    @Override public String toString(){return "MockPaymentPlanService[VIRTUAL_NON_AUTHORIZING]";}
}
