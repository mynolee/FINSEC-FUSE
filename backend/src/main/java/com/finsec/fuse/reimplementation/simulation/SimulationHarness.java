package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.http.BoundedRequestFilter;
import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.http.PublicHttpAdvice;
import com.finsec.fuse.reimplementation.http.PublicHttpErrors;
import com.finsec.fuse.reimplementation.http.RequestGuard;
import java.util.Objects;

/**
 * Explicit controller/filter bundle for in-process integration.
 * No application, network listener, actor registry, DB, policy defaults or executor.
 */
public record SimulationHarness(WorkflowHttpController workflowController, SimulationApiController apiController,
                                SimulationModeFilter modeFilter, BoundedRequestFilter requestFilter,
                                PublicHttpAdvice publicErrors) {
    public SimulationHarness {
        Objects.requireNonNull(workflowController); Objects.requireNonNull(apiController);
        Objects.requireNonNull(modeFilter); Objects.requireNonNull(requestFilter); Objects.requireNonNull(publicErrors);
    }
    /** Register this exact order so early admission failures also identify the virtual mode. */
    public jakarta.servlet.Filter[] orderedFilters() {
        return new jakarta.servlet.Filter[] { modeFilter, requestFilter };
    }
    public static SimulationHarness compose(VirtualWorkflowService workflows,
            VirtualQuarantineService quarantines, VirtualExperimentService experiments,
            WorkflowHttpController.ActorPort startResumeActors, SimulationApiController.HttpActors otherActors,
            HttpLimits limits) {
        Objects.requireNonNull(limits);
        var renderer = new PublicHttpErrors();
        return new SimulationHarness(new WorkflowHttpController(Objects.requireNonNull(startResumeActors), workflows),
                new SimulationApiController(workflows, quarantines, experiments, Objects.requireNonNull(otherActors)),
                new SimulationModeFilter(), new BoundedRequestFilter(new RequestGuard(limits), renderer),
                new PublicHttpAdvice(renderer));
    }
}
