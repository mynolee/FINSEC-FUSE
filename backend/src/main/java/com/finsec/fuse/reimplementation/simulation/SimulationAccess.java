package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import java.util.Objects;
import java.util.UUID;

/** An explicit test-only decision port. It does not authenticate or grant real permissions. */
public final class SimulationAccess {
    public enum Operation { READ, START, RESUME, REVIEW, KYC_OBSERVATION, PAYMENT, QUARANTINE, RELEASE, EXPERIMENT }
    @FunctionalInterface
    public interface Authority {
        boolean allows(ActorRef actor, Operation operation, UUID workflowId, String customerId);
    }
    private final Authority authority;
    public SimulationAccess(Authority authority) { this.authority = Objects.requireNonNull(authority); }
    public void require(ActorRef actor, Operation operation, UUID workflow, String customer) {
        if (actor == null) throw SimulationFailure.unauthenticated();
        try {
            SimulationSpec.synthetic(actor.actorId());
            if (!authority.allows(actor, operation, workflow, customer)) throw SimulationFailure.forbidden();
        } catch (SimulationFailure fixed) { throw fixed; }
        catch (IllegalArgumentException invalidActor) { throw SimulationFailure.forbidden(); }
        catch (RuntimeException unavailable) { throw SimulationFailure.unavailable(); }
    }
}
