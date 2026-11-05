package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.simulation.SimulationAccess.Operation;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.auth.LocalVirtualAdmissionContext.*;
import static com.finsec.fuse.reimplementation.auth.LocalVirtualAccessPolicy.Decision.*;

/** Only synthetic prepared registry rows; no entropy, real bearer/key, HTTP filter or domain side effect. */
final class LocalVirtualAdmissionContextTest {
    private static final Instant T=Instant.parse("2030-01-01T00:00:00Z");
    private static final UUID PID=new UUID(0,1), TOKEN=new UUID(0,2), WF=new UUID(0,3), OTHER=new UUID(0,4);
    private static final String CUSTOMER="synthetic-customer", ALIAS="synthetic-request-actor";
    private LocalVirtualPrincipal principal(long revision,LocalVirtualPrincipal.Status status) {
        return new LocalVirtualPrincipal(PID,ALIAS,revision,status,Set.of(TokenRegistryInput.Role.CUSTOMER),
            Set.of(CUSTOMER),Map.of(WF,CUSTOMER,OTHER,CUSTOMER),3);
    }
    private final class Rig {
        final LocalVirtualTokenRegistry registry=new LocalVirtualTokenRegistry(2);
        final TokenMaterialCodec.Material material=TokenMaterialCodec.encode(new byte[32]);
        final AtomicReference<LocalVirtualPrincipal> principal=new AtomicReference<>(principal(0,LocalVirtualPrincipal.Status.ACTIVE));
        final LocalVirtualAdmissionContext context;
        final CredentialEvidence evidence;
        int verifierCalls;
        Rig() {
            registry.registerPrepared(new LocalVirtualTokenRegistry.Credential(TOKEN,PID,LocalVirtualTokenRegistry.Status.ACTIVE,
                0,T,T.plusSeconds(60),0,material.fingerprint()));
            evidence=registry.admitCanonical(material.bearer(),T);assertNotNull(evidence);
            context=new LocalVirtualAdmissionContext(this::current,registry);
        }
        VerifiedSnapshot current(CredentialReference reference,Instant now) {
            verifierCalls++;
            var found=registry.revalidateReference(reference.tokenId(),reference.principalId(),reference.tokenRevision(),
                reference.bindingRevision(),reference.issuedAt(),reference.expiresAt(),now);
            return new VerifiedSnapshot(reference,found.status()==LocalVirtualTokenRegistry.LookupStatus.FOUND
                ?CredentialState.ACTIVE:CredentialState.ABSENT,principal.get());
        }
    }
    private Failure failure(Code code,org.junit.jupiter.api.function.Executable action) {
        var failure=assertThrows(Failure.class,action);assertEquals(code,failure.code());
        assertEquals(code.name(),failure.getMessage());assertNull(failure.getCause());assertEquals(0,failure.getStackTrace().length);
        return failure;
    }
    @Test void canonicalRegistryProofOpensOneCurrentRequestAndFinallyRemovesIt() {
        var r=new Rig();assertNull(r.context.current());
        assertTrue(r.evidence.issuedBy(r.registry));assertFalse(r.evidence.issuedBy(new Object()));
        try(var admitted=r.context.openRequest(r.evidence,T)) {
            assertSame(admitted,r.context.current());assertEquals(1,r.verifierCalls);
            assertEquals(r.evidence.reference(),admitted.credential());assertEquals(T,admitted.admittedAt());
            assertSame(r.principal.get(),admitted.principal());assertEquals(ALIAS,admitted.actor().actorId());
            assertEquals(ALLOW,r.context.authorizeSameActor(admitted.actor(),Operation.READ,WF,CUSTOMER));
            assertEquals("LocalVirtualAdmission[REDACTED]",admitted.toString());
        }
        assertNull(r.context.current());
        try(var again=r.context.openRequest(r.evidence,T.plusSeconds(1))) {assertNotNull(again);}
        assertEquals(2,r.verifierCalls);
    }
    @Test void referenceAndFingerprintLookupCannotInstallAdmissionAndWrongIssuerRejectsBeforeVerifier() {
        var r=new Rig();
        assertEquals(LocalVirtualTokenRegistry.LookupStatus.FOUND,r.registry.lookupFingerprint(r.material.fingerprint(),T).status());
        assertEquals(LocalVirtualTokenRegistry.LookupStatus.FOUND,r.registry.revalidateReference(TOKEN,PID,0,0,T,T.plusSeconds(60),T).status());
        assertNull(r.context.current());failure(Code.UNAUTHENTICATED,()->r.context.openRequest(null,T));
        var foreign=new LocalVirtualTokenRegistry(1);
        foreign.registerPrepared(new LocalVirtualTokenRegistry.Credential(TOKEN,PID,LocalVirtualTokenRegistry.Status.ACTIVE,
            0,T,T.plusSeconds(60),0,r.material.fingerprint()));
        var otherEvidence=foreign.admitCanonical(r.material.bearer(),T);assertNotNull(otherEvidence);
        failure(Code.UNAUTHENTICATED,()->r.context.openRequest(otherEvidence,T));assertEquals(0,r.verifierCalls);
        failure(Code.UNAUTHENTICATED,()->r.context.authorizeSameActor(new ActorRef(ALIAS),Operation.READ,WF,CUSTOMER));
    }
    @Test void exactIssuedBoundaryAcceptsButBeforeExpiryEqualityAndRevocationRefuseFreshAdmission() {
        var r=new Rig();try(var admitted=r.context.openRequest(r.evidence,T)){assertNotNull(admitted);}
        failure(Code.UNAUTHENTICATED,()->r.context.openRequest(r.evidence,T.minusNanos(1)));
        failure(Code.UNAUTHENTICATED,()->r.context.openRequest(r.evidence,T.plusSeconds(60)));
        assertEquals(LocalVirtualTokenRegistry.RevokeStatus.REVOKED,r.registry.revoke(TOKEN,0).status());
        failure(Code.UNAUTHENTICATED,()->r.context.openRequest(r.evidence,T.plusSeconds(1)));
        assertNull(r.context.current());
    }
    @Test void staleBindingDisabledUnknownAndInconsistentPrincipalAreNotTrustedCurrentFacts() {
        var r=new Rig();
        r.principal.set(principal(1,LocalVirtualPrincipal.Status.ACTIVE));
        failure(Code.UNAUTHENTICATED,()->r.context.openRequest(r.evidence,T));
        r.principal.set(principal(0,LocalVirtualPrincipal.Status.DISABLED));
        failure(Code.UNAUTHENTICATED,()->r.context.openRequest(r.evidence,T));
        r.principal.set(principal(0,LocalVirtualPrincipal.Status.UNCONFIRMED));
        failure(Code.UNAVAILABLE,()->r.context.openRequest(r.evidence,T));
        r.principal.set(null);failure(Code.UNAVAILABLE,()->r.context.openRequest(r.evidence,T));
        r.principal.set(new LocalVirtualPrincipal(OTHER,ALIAS,0,LocalVirtualPrincipal.Status.ACTIVE,
            Set.of(TokenRegistryInput.Role.CUSTOMER),Set.of(CUSTOMER),Map.of(WF,CUSTOMER),2));
        failure(Code.UNAVAILABLE,()->r.context.openRequest(r.evidence,T));assertNull(r.context.current());
    }
    @Test void trustedVerifierUnknownThrowAndChangedCredentialTupleCannotEstablishContext() {
        var r=new Rig();
        for(int mode=0;mode<5;mode++) {
            final int selected=mode;
            var context=new LocalVirtualAdmissionContext((requested,now)->{
                if(selected==0)return null;
                if(selected==1)throw new IllegalStateException("SYNTHETIC_RAW_VERIFIER_CAUSE");
                if(selected==2)return new VerifiedSnapshot(requested,CredentialState.UNCONFIRMED,r.principal.get());
                if(selected==3)return new VerifiedSnapshot(requested,CredentialState.REVOKED,r.principal.get());
                var changed=new CredentialReference(requested.tokenId(),requested.principalId(),1,requested.bindingRevision(),requested.issuedAt(),requested.expiresAt());
                return new VerifiedSnapshot(changed,CredentialState.ACTIVE,r.principal.get());
            },r.registry);
            failure(mode<3?Code.UNAVAILABLE:Code.UNAUTHENTICATED,()->context.openRequest(r.evidence,T));
            assertNull(context.current());
        }
    }
    @Test void aliasOperationAndResourceLatchesCannotBeReusedForAnotherActionOrWorkflow() {
        var r=new Rig();try(var admitted=r.context.openRequest(r.evidence,T)) {
            assertEquals(FORBIDDEN,r.context.authorizeSameActor(new ActorRef("synthetic-other-actor"),Operation.READ,WF,CUSTOMER));
            assertEquals(SCOPE_UNCONFIRMED,admitted.authorize(Operation.READ,null,null));
            assertEquals(ALLOW,admitted.authorize(Operation.READ,WF,null));
            assertEquals(ALLOW,admitted.authorize(Operation.READ,WF,CUSTOMER));
            assertEquals(FORBIDDEN,admitted.authorize(Operation.READ,OTHER,CUSTOMER));
            assertEquals(FORBIDDEN,admitted.authorize(Operation.READ,WF,"synthetic-other-customer"));
            assertEquals(FORBIDDEN,admitted.authorize(Operation.RESUME,WF,CUSTOMER));
            assertEquals(FORBIDDEN,admitted.authorize(null,WF,CUSTOMER));
        }
    }
    @Test void nestedAdmissionAndClosedHandleCannotLeakAcrossRequests() {
        var r=new Rig();var first=r.context.openRequest(r.evidence,T);
        try {failure(Code.UNAVAILABLE,()->r.context.openRequest(r.evidence,T));assertSame(first,r.context.current());}
        finally {first.close();}
        first.close();assertNull(r.context.current());failure(Code.UNAVAILABLE,first::actor);
        try(var second=r.context.openRequest(r.evidence,T)) {
            assertNotSame(first,second);failure(Code.UNAVAILABLE,()->first.authorize(Operation.READ,WF,CUSTOMER));
            assertSame(second,r.context.current());
        }
        assertNull(r.context.current());
    }
    @Test void plainThreadLocalDoesNotInheritAndForeignThreadCannotUseOrCloseHandle() throws Exception {
        var r=new Rig();var admitted=r.context.openRequest(r.evidence,T);
        var childFailure=new AtomicReference<Throwable>();
        // This is future test source only. No Thread is constructed or started during authoring.
        var child=new Thread(()->{
            try {
                assertNull(r.context.current());
                failure(Code.UNAUTHENTICATED,()->r.context.authorizeSameActor(new ActorRef(ALIAS),Operation.READ,WF,CUSTOMER));
                failure(Code.UNAVAILABLE,admitted::actor);failure(Code.UNAVAILABLE,admitted::close);
            } catch(Throwable failed) {childFailure.set(failed);}
        },"synthetic-local-admission-test");
        child.setDaemon(true);
        try {
            child.start();child.join(1000);assertFalse(child.isAlive(),"Finite child must complete");
            assertNull(childFailure.get());assertSame(admitted,r.context.current());
            assertEquals(ALLOW,admitted.authorize(Operation.READ,WF,CUSTOMER));
        } finally {if(child.isAlive())child.interrupt();admitted.close();}
        assertNull(r.context.current());
    }
    @Test void referenceBoundsAndRedactionDoNotTurnReferenceDataIntoEvidence() {
        var r=new Rig();var reference=r.evidence.reference();
        assertThrows(IllegalArgumentException.class,()->new CredentialReference(TOKEN,PID,-1,0,T,T.plusSeconds(1)));
        assertThrows(IllegalArgumentException.class,()->new CredentialReference(TOKEN,PID,0,0,T,T));
        assertEquals("CredentialReference[REDACTED]",reference.toString());
        assertEquals("LocalVirtualCredentialEvidence[REDACTED]",r.evidence.toString());
        assertEquals("LocalVirtualAdmissionContext[REDACTED]",r.context.toString());
        assertNull(r.context.current());
    }
}
