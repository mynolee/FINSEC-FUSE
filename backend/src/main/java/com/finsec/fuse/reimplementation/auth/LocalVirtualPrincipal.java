package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Explicit server-owned principal snapshot, not a real identity or role-assignment proof. */
public record LocalVirtualPrincipal(UUID principalId,String actorAlias,long bindingRevision,Status status,
        Set<TokenRegistryInput.Role> roles,Set<String> customerAssignments,
        Map<UUID,String> workflowAssignments,int maximumAssignments) {
    public enum Status { ACTIVE, DISABLED, UNCONFIRMED }
    public LocalVirtualPrincipal {
        if(principalId==null||bindingRevision<0||status==null||roles==null||customerAssignments==null
                ||workflowAssignments==null||maximumAssignments<1)throw invalid();
        SimulationSpec.synthetic(actorAlias);
        roles=Set.copyOf(roles);customerAssignments=Set.copyOf(customerAssignments);workflowAssignments=Map.copyOf(workflowAssignments);
        if((long)customerAssignments.size()+workflowAssignments.size()>maximumAssignments)throw invalid();
        for(var customer:customerAssignments)SimulationSpec.synthetic(customer);
        for(var entry:workflowAssignments.entrySet()){if(entry.getKey()==null)throw invalid();SimulationSpec.synthetic(entry.getValue());}
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("INVALID_LOCAL_PRINCIPAL");}
    @Override public String toString(){return "LocalVirtualPrincipal[REDACTED]";}
}
