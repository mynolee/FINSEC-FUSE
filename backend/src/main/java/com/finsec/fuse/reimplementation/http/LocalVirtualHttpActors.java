package com.finsec.fuse.reimplementation.http;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.auth.LocalVirtualAdmissionContext;
import com.finsec.fuse.reimplementation.auth.LocalVirtualAccessPolicy;
import com.finsec.fuse.reimplementation.simulation.SimulationAccess;
import com.finsec.fuse.reimplementation.simulation.SimulationApiController;
import com.finsec.fuse.reimplementation.simulation.SimulationFailure;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Objects;
import java.util.UUID;

/** Explicit ports share the same live server admission; ActorRef alone never grants access. */
public final class LocalVirtualHttpActors implements WorkflowHttpController.ActorPort,SimulationApiController.HttpActors {
    private final LocalVirtualAdmissionContext context;
    public LocalVirtualHttpActors(LocalVirtualAdmissionContext context){this.context=Objects.requireNonNull(context);}
    @Override public ActorRef authorize(HttpServletRequest request,WorkflowHttpController.Operation operation,UUID workflow,String customer){
        Objects.requireNonNull(operation);
        try {
            return authorize(request,operation==WorkflowHttpController.Operation.START?SimulationAccess.Operation.START:SimulationAccess.Operation.RESUME,workflow,customer);
        } catch(SimulationFailure failure) {
            if(failure.status()==401)throw new WorkflowHttpController.Rejection(WorkflowHttpController.Denial.UNAUTHENTICATED);
            if(failure.status()==403)throw new WorkflowHttpController.Rejection(WorkflowHttpController.Denial.FORBIDDEN);
            throw failure;
        }
    }
    @Override public ActorRef authorize(HttpServletRequest request,SimulationAccess.Operation operation,UUID workflow){
        return authorize(request,operation,workflow,null);
    }
    private ActorRef authorize(HttpServletRequest request,SimulationAccess.Operation operation,UUID workflow,String customer){
        try {
            var admission=LocalVirtualAuthenticationFilter.admission(request,context);
            require(admission.authorize(operation,workflow,customer));
            return admission.actor();
        }catch(LocalVirtualAdmissionContext.Failure failure){throw fixed(failure);}
    }
    /** Supply this exact current-context authority alongside these HTTP ports; no global role lookup. */
    public SimulationAccess.Authority authority(){
        return (actor,operation,workflow,customer)->{
            try {return allowed(context.authorizeSameActor(actor,operation,workflow,customer));}
            catch(LocalVirtualAdmissionContext.Failure failure){throw fixed(failure);}
        };
    }
    private static boolean allowed(LocalVirtualAccessPolicy.Decision decision){
        if(decision==LocalVirtualAccessPolicy.Decision.SCOPE_UNCONFIRMED)throw SimulationFailure.unavailable();
        return decision==LocalVirtualAccessPolicy.Decision.ALLOW;
    }
    private static void require(LocalVirtualAccessPolicy.Decision decision){if(!allowed(decision))throw SimulationFailure.forbidden();}
    private static SimulationFailure fixed(LocalVirtualAdmissionContext.Failure failure){
        return switch(failure.code()){
            case UNAUTHENTICATED -> SimulationFailure.unauthenticated();
            case FORBIDDEN -> SimulationFailure.forbidden();
            case UNAVAILABLE -> SimulationFailure.unavailable();
        };
    }
    @Override public String toString(){return "LocalVirtualHttpActors[REDACTED]";}
}
