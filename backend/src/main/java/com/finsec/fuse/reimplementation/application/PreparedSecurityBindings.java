package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.simulation.SimulationAccess;
import com.finsec.fuse.reimplementation.simulation.SimulationApiController;
import com.finsec.fuse.reimplementation.simulation.VirtualQuarantineService;
import java.util.Objects;
import java.util.function.BooleanSupplier;

/** Explicit trusted server ports; this record neither authenticates nor assigns roles. */
public record PreparedSecurityBindings(SimulationAccess.Authority authority,
        VirtualQuarantineService.RemediationVerifier remediationVerifier,
        WorkflowHttpController.ActorPort startResumeActors, SimulationApiController.HttpActors otherActors,
        VirtualHttpApplication.ReadinessAuthorization readiness, BooleanSupplier dependenciesAvailable) {
    public PreparedSecurityBindings {
        Objects.requireNonNull(authority); Objects.requireNonNull(remediationVerifier);
        Objects.requireNonNull(startResumeActors); Objects.requireNonNull(otherActors);
        Objects.requireNonNull(readiness); Objects.requireNonNull(dependenciesAvailable);
    }
    @Override public String toString() { return "PreparedSecurityBindings[REDACTED]"; }
}
