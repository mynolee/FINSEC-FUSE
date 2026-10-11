package com.finsec.fuse.auth;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Read-only admission authority. Implementations return one current committed snapshot. */
public interface DemoTokenStore {
    enum Status { ACTIVE, REVOKED }
    record Binding(String fingerprint, Actor actor) {
        public Binding { validateFingerprint(fingerprint); validateActor(actor); }
    }
    record Credential(String fingerprint, Actor initialActor, Set<String> currentScope,
                      Instant issuedAt, Instant expiresAt, Status status, Instant revokedAt, long revision) {
        public Credential {
            validateFingerprint(fingerprint); validateActor(initialActor); currentScope=canonicalScope(currentScope);
            if(issuedAt==null || expiresAt==null || !expiresAt.equals(issuedAt.plusSeconds(7200)) || status==null
                || revision<0 || (status==Status.ACTIVE)!=(revokedAt==null))
                throw new IllegalArgumentException("Invalid credential lifecycle");
        }
        public Actor actor() { return new Actor(initialActor.actorId(),initialActor.role(),currentScope); }
    }
    record Snapshot(Instant authorityTime, Credential credential) {
        public Snapshot { if(authorityTime==null)throw new IllegalArgumentException("Missing authority time"); }
    }
    /** A null fingerprint requests readiness only; configured bindings are checked in the same snapshot. */
    Snapshot lookup(String fingerprint,List<Binding> configured);
    default void requireReady(List<Binding> configured) { lookup(null,configured); }
    final class Unavailable extends RuntimeException {
        public Unavailable() { super("Authentication authority is unavailable"); }
    }
    static void validateFingerprint(String value) {
        if(value==null || !value.matches("[0-9a-f]{64}"))throw new IllegalArgumentException("Invalid credential fingerprint");
    }
    static void validateActor(Actor actor) {
        if(actor==null || actor.actorId()==null || !actor.actorId().matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
            || !Set.of("CUSTOMER","LOAN_REVIEWER","SECURITY_OPERATOR","DEVELOPER","KYC_SERVICE","FUSE_WORKER").contains(actor.role()))
            throw new IllegalArgumentException("Invalid credential identity");
        canonicalScope(actor.customerIds());
    }
    static Set<String> canonicalScope(Set<String> values) {
        if(values==null || values.size()>256)throw new IllegalArgumentException("Invalid credential scope");
        var sorted=new TreeSet<String>();
        for(String value:values) {
            if(value==null || !value.matches("customer-[A-Za-z0-9][A-Za-z0-9_-]{0,118}"))throw new IllegalArgumentException("Invalid credential scope");
            sorted.add(value);
        }
        return java.util.Collections.unmodifiableSet(sorted);
    }
}
