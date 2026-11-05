package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.simulation.SimulationAccess.Operation;
import java.util.UUID;

/** Closed local-development role and explicit-resource consistency only; domain ownership gates remain mandatory. */
public final class LocalVirtualAccessPolicy {
    private LocalVirtualAccessPolicy() {}
    public enum Decision { ALLOW, FORBIDDEN, SCOPE_UNCONFIRMED }
    public static boolean roleAllows(LocalVirtualPrincipal principal,Operation operation){
        if(principal==null||operation==null||principal.status()!=LocalVirtualPrincipal.Status.ACTIVE)return false;
        return principal.roles().stream().anyMatch(role->switch(role){
            case CUSTOMER -> operation==Operation.READ||operation==Operation.START||operation==Operation.RESUME;
            case LOAN_REVIEWER -> operation==Operation.READ||operation==Operation.REVIEW;
            case SECURITY_OPERATOR -> operation==Operation.READ||operation==Operation.QUARANTINE||operation==Operation.RELEASE;
            case DEVELOPER -> operation==Operation.READ||operation==Operation.EXPERIMENT;
            case KYC_SERVICE -> operation==Operation.READ||operation==Operation.KYC_OBSERVATION;
            case FUSE_WORKER -> operation==Operation.READ||operation==Operation.KYC_OBSERVATION||operation==Operation.PAYMENT;
        });
    }
    public static Decision assess(LocalVirtualPrincipal principal,Operation operation,UUID workflowId,String customerId){
        if(!roleAllows(principal,operation))return Decision.FORBIDDEN;
        if(workflowId!=null){
            String assigned=principal.workflowAssignments().get(workflowId);
            if(assigned==null)return Decision.FORBIDDEN;
            return customerId==null||assigned.equals(customerId)?Decision.ALLOW:Decision.FORBIDDEN;
        }
        if(customerId!=null)return principal.customerAssignments().contains(customerId)?Decision.ALLOW:Decision.FORBIDDEN;
        // No wildcard permission for collection, experiment creation or an unresolved containment target.
        return Decision.SCOPE_UNCONFIRMED;
    }
}
