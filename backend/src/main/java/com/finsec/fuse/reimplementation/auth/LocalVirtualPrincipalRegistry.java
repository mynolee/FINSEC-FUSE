package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/** Bounded prepared principal snapshots; does not assign real identities, roles or administration authority. */
public final class LocalVirtualPrincipalRegistry {
    public enum UpdateStatus { UPDATED, NOT_FOUND, REVISION_CONFLICT, REVISION_EXHAUSTED }
    public record Update(UpdateStatus status,long currentRevision) {
        public Update {if(status==null || currentRevision< -1)throw invalid();}
    }
    private final int maximumPrincipals,maximumAliasBindings;
    private final Map<UUID,LocalVirtualPrincipal> principals=new LinkedHashMap<>();
    // Reserved aliases cannot be recycled into a different principal's historical ActorRef.
    private final Map<String,UUID> aliases=new LinkedHashMap<>();
    public LocalVirtualPrincipalRegistry(int maximumPrincipals,int maximumAliasBindings){
        if(maximumPrincipals<1 || maximumAliasBindings<1)throw invalid();
        this.maximumPrincipals=maximumPrincipals;this.maximumAliasBindings=maximumAliasBindings;
    }
    /** Low-level prepared-data operation; actual principal administration is independently authorized. */
    public synchronized void registerPrepared(LocalVirtualPrincipal principal){
        if(principal==null)throw invalid();
        if(principals.containsKey(principal.principalId()) || aliases.containsKey(principal.actorAlias()))throw conflict();
        if(principals.size()>=maximumPrincipals || aliases.size()>=maximumAliasBindings)throw unavailable();
        principals.put(principal.principalId(),principal);aliases.put(principal.actorAlias(),principal.principalId());
    }
    /** Exact monotonic binding revision CAS; does not reissue credentials or change existing token bindings. */
    public synchronized Update replacePrepared(UUID principalId,long expectedRevision,LocalVirtualPrincipal replacement){
        if(principalId==null || expectedRevision<0 || replacement==null || !principalId.equals(replacement.principalId()))throw invalid();
        var old=principals.get(principalId);
        if(old==null)return new Update(UpdateStatus.NOT_FOUND,-1);
        if(old.bindingRevision()!=expectedRevision)return new Update(UpdateStatus.REVISION_CONFLICT,old.bindingRevision());
        if(expectedRevision==Long.MAX_VALUE)return new Update(UpdateStatus.REVISION_EXHAUSTED,expectedRevision);
        if(replacement.bindingRevision()!=expectedRevision+1)throw invalid();
        var owner=aliases.get(replacement.actorAlias());
        if(owner!=null && !owner.equals(principalId))throw conflict();
        if(owner==null && aliases.size()>=maximumAliasBindings)throw unavailable();
        // All ordinary validation precedes publication; fatal memory/VM failure is not durable atomicity.
        aliases.put(replacement.actorAlias(),principalId);principals.put(principalId,replacement);
        return new Update(UpdateStatus.UPDATED,replacement.bindingRevision());
    }
    public synchronized LocalVirtualPrincipal findCurrent(UUID principalId){
        if(principalId==null)throw invalid();
        var p=principals.get(principalId);
        if(p!=null && !principalId.equals(aliases.get(p.actorAlias())))throw unavailable();
        return p;
    }
    public synchronized LocalVirtualPrincipal findCurrentAlias(String alias){
        SimulationSpec.synthetic(alias);
        var id=aliases.get(alias);if(id==null)return null;
        var p=findCurrent(id);if(p==null)throw unavailable();
        return p.actorAlias().equals(alias)?p:null;
    }
    public synchronized int size(){return principals.size();}
    public synchronized int reservedAliases(){return aliases.size();}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("INVALID_LOCAL_PRINCIPAL_REGISTRY",null);}
    private static IllegalStateException conflict(){return new IllegalStateException("LOCAL_PRINCIPAL_BINDING_CONFLICT",null);}
    private static IllegalStateException unavailable(){return new IllegalStateException("LOCAL_PRINCIPAL_REGISTRY_UNAVAILABLE",null);}
    @Override public String toString(){return "LocalVirtualPrincipalRegistry[REDACTED]";}
}
