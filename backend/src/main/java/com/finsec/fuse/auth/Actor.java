package com.finsec.fuse.auth;

import java.util.Set;

/** Resolved exclusively from server-owned authentication mappings. */
public record Actor(String actorId,String role,Set<String> customerIds) {
    public Actor { customerIds=Set.copyOf(customerIds); }
    public boolean is(String requiredRole) { return role.equals(requiredRole); }
    public boolean canAccess(String customerId) { return customerIds.contains(customerId); }
}
