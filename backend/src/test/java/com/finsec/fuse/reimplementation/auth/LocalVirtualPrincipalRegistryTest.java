package com.finsec.fuse.reimplementation.auth;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.auth.LocalVirtualAdmissionContext.*;

/** Synthetic prepared snapshots and current joins; no real principal, role assignment, DB or entropy. */
final class LocalVirtualPrincipalRegistryTest {
    private static final UUID P=new UUID(1,1),OTHER=new UUID(2,2),TOKEN=new UUID(3,3);
    private static final Instant START=Instant.parse("2026-11-05T00:00:00Z"),END=START.plusSeconds(60);
    private static LocalVirtualPrincipal principal(UUID id,String alias,long revision,LocalVirtualPrincipal.Status status){
        return new LocalVirtualPrincipal(id,alias,revision,status,Set.of(TokenRegistryInput.Role.CUSTOMER),Set.of("synthetic-customer"),Map.of(),4);
    }
    private static LocalVirtualTokenRegistry tokens(byte[] fingerprint){
        var t=new LocalVirtualTokenRegistry(2);t.registerPrepared(new LocalVirtualTokenRegistry.Credential(TOKEN,P,LocalVirtualTokenRegistry.Status.ACTIVE,2,START,END,3,fingerprint));return t;
    }
    private static CredentialReference reference(){return new CredentialReference(TOKEN,P,2,3,START,END);}
    @Test void aliasCollisionAndRenamedHistoricalAliasCannotMoveToAnotherPrincipal(){
        var r=new LocalVirtualPrincipalRegistry(2,3);var old=principal(P,"synthetic-one",3,LocalVirtualPrincipal.Status.ACTIVE);r.registerPrepared(old);
        assertThrows(IllegalStateException.class,()->r.registerPrepared(principal(OTHER,"synthetic-one",0,LocalVirtualPrincipal.Status.ACTIVE)));
        var next=principal(P,"synthetic-renamed",4,LocalVirtualPrincipal.Status.ACTIVE);
        assertEquals(LocalVirtualPrincipalRegistry.UpdateStatus.UPDATED,r.replacePrepared(P,3,next).status());
        assertNull(r.findCurrentAlias("synthetic-one"));assertSame(next,r.findCurrentAlias("synthetic-renamed"));
        assertThrows(IllegalStateException.class,()->r.registerPrepared(principal(OTHER,"synthetic-one",0,LocalVirtualPrincipal.Status.ACTIVE)));
        assertEquals(1,r.size());assertEquals(2,r.reservedAliases());
    }
    @Test void exactCasPreservesOldSnapshotAndExplicitBoundsDoNotEvict(){
        var r=new LocalVirtualPrincipalRegistry(1,1);var old=principal(P,"synthetic-one",3,LocalVirtualPrincipal.Status.ACTIVE);r.registerPrepared(old);
        var next=principal(P,"synthetic-one",4,LocalVirtualPrincipal.Status.DISABLED);
        assertEquals(LocalVirtualPrincipalRegistry.UpdateStatus.REVISION_CONFLICT,r.replacePrepared(P,2,next).status());assertSame(old,r.findCurrent(P));
        assertThrows(IllegalStateException.class,()->r.replacePrepared(P,3,principal(P,"synthetic-new",4,LocalVirtualPrincipal.Status.ACTIVE)));assertSame(old,r.findCurrent(P));
        assertEquals(LocalVirtualPrincipalRegistry.UpdateStatus.UPDATED,r.replacePrepared(P,3,next).status());assertSame(next,r.findCurrent(P));
        assertEquals(LocalVirtualPrincipal.Status.ACTIVE,old.status());assertEquals(3,old.bindingRevision());
        assertThrows(IllegalStateException.class,()->r.registerPrepared(principal(OTHER,"synthetic-other",0,LocalVirtualPrincipal.Status.ACTIVE)));assertEquals(1,r.size());
    }
    @Test void assignmentSnapshotsAndRoleReplacementAreImmutable(){
        var roles=new HashSet<TokenRegistryInput.Role>();roles.add(TokenRegistryInput.Role.CUSTOMER);
        var customers=new HashSet<String>();customers.add("synthetic-customer");var workflows=new HashMap<UUID,String>();workflows.put(new UUID(4,4),"synthetic-customer");
        var p=new LocalVirtualPrincipal(P,"synthetic-one",3,LocalVirtualPrincipal.Status.ACTIVE,roles,customers,workflows,4);
        roles.clear();customers.clear();workflows.clear();assertEquals(Set.of(TokenRegistryInput.Role.CUSTOMER),p.roles());assertEquals(1,p.customerAssignments().size());assertEquals(1,p.workflowAssignments().size());
        assertThrows(UnsupportedOperationException.class,()->p.roles().clear());assertThrows(UnsupportedOperationException.class,()->p.workflowAssignments().clear());
        var r=new LocalVirtualPrincipalRegistry(1,1);r.registerPrepared(p);
        var next=new LocalVirtualPrincipal(P,"synthetic-one",4,LocalVirtualPrincipal.Status.ACTIVE,Set.of(TokenRegistryInput.Role.DEVELOPER),Set.of("synthetic-customer"),Map.of(),4);
        r.replacePrepared(P,3,next);assertEquals(Set.of(TokenRegistryInput.Role.DEVELOPER),r.findCurrent(P).roles());assertEquals(Set.of(TokenRegistryInput.Role.CUSTOMER),p.roles());
    }
    @Test void currentVerifierUsesActualTokenAndPrincipalTupleAndNeverMintsEvidence(){
        var t=tokens(new byte[32]);var p=principal(P,"synthetic-one",3,LocalVirtualPrincipal.Status.ACTIVE);var r=new LocalVirtualPrincipalRegistry(2,2);r.registerPrepared(p);var v=new LocalVirtualCurrentVerifier(t,r);
        var snapshot=v.current(reference(),START);assertEquals(CredentialState.ACTIVE,snapshot.state());assertSame(p,snapshot.principal());
        assertFalse(CredentialEvidence.class.isInstance(snapshot));
        assertEquals(CredentialState.ABSENT,v.current(new CredentialReference(TOKEN,P,1,3,START,END),START).state());
        assertEquals(CredentialState.ABSENT,v.current(reference(),END).state());
        t.revoke(TOKEN,2);assertEquals(CredentialState.ABSENT,v.current(reference(),START).state());
    }
    @Test void missingOrUnknownPrincipalIsUnavailableAndDisabledOrStaleBindingUnauthenticated(){
        var t=tokens(new byte[32]);var r=new LocalVirtualPrincipalRegistry(1,1);var v=new LocalVirtualCurrentVerifier(t,r);
        assertEquals(CredentialState.UNCONFIRMED,v.current(reference(),START).state());
        r.registerPrepared(principal(P,"synthetic-one",3,LocalVirtualPrincipal.Status.UNCONFIRMED));assertEquals(CredentialState.UNCONFIRMED,v.current(reference(),START).state());
        r.replacePrepared(P,3,principal(P,"synthetic-one",4,LocalVirtualPrincipal.Status.DISABLED));assertEquals(CredentialState.ABSENT,v.current(reference(),START).state());
        var disabled=new LocalVirtualPrincipalRegistry(1,1);disabled.registerPrepared(principal(P,"synthetic-disabled",3,LocalVirtualPrincipal.Status.DISABLED));
        assertEquals(CredentialState.ABSENT,new LocalVirtualCurrentVerifier(t,disabled).current(reference(),START).state());
    }
    @Test void canonicalEvidenceStillRequiresCurrentPrincipalBindingAtEveryNewAdmission(){
        var material=TokenMaterialCodec.encode(new byte[32]);var t=tokens(material.fingerprint());var r=new LocalVirtualPrincipalRegistry(1,1);r.registerPrepared(principal(P,"synthetic-one",3,LocalVirtualPrincipal.Status.ACTIVE));
        var context=new LocalVirtualAdmissionContext(new LocalVirtualCurrentVerifier(t,r),t);var evidence=t.admitCanonical(material.bearer(),START);
        try(var admitted=context.openRequest(evidence,START)){assertEquals("synthetic-one",admitted.actor().actorId());}
        r.replacePrepared(P,3,principal(P,"synthetic-one",4,LocalVirtualPrincipal.Status.ACTIVE));
        assertEquals(LocalVirtualTokenRegistry.LookupStatus.FOUND,t.lookupCanonical(material.bearer(),START).status());
        assertEquals(Code.UNAUTHENTICATED,assertThrows(Failure.class,()->context.openRequest(evidence,START)).code());assertNull(context.current());
    }
    @Test void maxRevisionAndMalformedUpdatesDoNotPublishOrBackfill(){
        var r=new LocalVirtualPrincipalRegistry(1,1);var p=principal(P,"synthetic-one",Long.MAX_VALUE,LocalVirtualPrincipal.Status.ACTIVE);r.registerPrepared(p);
        assertEquals(LocalVirtualPrincipalRegistry.UpdateStatus.REVISION_EXHAUSTED,r.replacePrepared(P,Long.MAX_VALUE,p).status());assertSame(p,r.findCurrent(P));
        assertThrows(IllegalArgumentException.class,()->r.replacePrepared(P,-1,p));
        assertThrows(IllegalArgumentException.class,()->new LocalVirtualPrincipalRegistry(0,1));
        assertThrows(IllegalArgumentException.class,()->new LocalVirtualCurrentVerifier(tokens(new byte[32]),r).current(null,START));
        assertEquals("LocalVirtualPrincipalRegistry[REDACTED]",r.toString());
    }
}
