package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.simulation.*;
import com.finsec.fuse.reimplementation.persistence.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Supported actual synthetic creation producer; no private proof construction or execution claim. */
final class LocalVirtualOwnerDelegationRegistryTest {
    static UUID id(long n) { return new UUID(102,n); }
    static final Instant NOW=Instant.ofEpochSecond(150);
    static final class Fixture implements AutoCloseable {
        final LocalVirtualTokenRegistry tokens=new LocalVirtualTokenRegistry(4);
        final LocalVirtualPrincipalRegistry principals=new LocalVirtualPrincipalRegistry(4,4);
        final LocalVirtualAdmissionContext context=new LocalVirtualAdmissionContext(new LocalVirtualCurrentVerifier(tokens,principals),tokens);
        final LocalVirtualAdmissionContext.Admission owner;
        final LocalVirtualTargetRegistry registry;
        final LocalVirtualTargetRegistry.CollectionAdmission collection;
        final VirtualTransactionalStore store=new VirtualTransactionalStore();
        final VirtualExperimentService service;
        final VirtualExperimentService.Plan plan=new VirtualExperimentService.Plan("synthetic-fixture",List.of("synthetic-case"),"PAIRED","REPLAY",1);
        boolean stale;
        LocalVirtualAdmissionContext.CredentialEvidence executor;
        LocalVirtualOwnerDelegationRegistry delegations;
        VirtualExperimentService.CreationProof proof;
        Fixture() {
            principals.registerPrepared(new LocalVirtualPrincipal(id(1),"synthetic-owner",0,LocalVirtualPrincipal.Status.ACTIVE,
                    Set.of(TokenRegistryInput.Role.DEVELOPER),Set.of(),Map.of(),1));
            var material=TokenMaterialCodec.encode(new byte[32]);
            tokens.registerPrepared(new LocalVirtualTokenRegistry.Credential(id(2),id(1),LocalVirtualTokenRegistry.Status.ACTIVE,0,
                    NOW.minusSeconds(1),NOW.plusSeconds(60),0,material.fingerprint()));
            var evidence=tokens.admitCanonical(material.bearer(),NOW);owner=context.openRequest(evidence,NOW);
            var boundary=new LocalVirtualTargetRegistry.ExperimentCreation(id(1),"synthetic-fixture");
            var member=new LocalVirtualTargetRegistry.FixtureSet("synthetic-fixture");
            var intent=new LocalVirtualTargetRegistry.Intent(SimulationAccess.Operation.EXPERIMENT,boundary);
            registry=new LocalVirtualTargetRegistry(tokens,principals,context,new LocalVirtualTargetRegistry.Limits(8,2,4,4,4,4096),
                    (requested,p,limits)->new LocalVirtualTargetRegistry.OwnedCollection(){
                        public void requireCompleteCurrent(){if(stale)throw SimulationFailure.unavailable();assertEquals(intent,requested);}
                        public List<LocalVirtualTargetRegistry.Target> members(){return List.of(member);}
                        public int relationCount(){return 1;}public int caseCount(){return 1;}public void close(){}
                    });
            var assignments=List.of(boundary,member).stream().map(t->new LocalVirtualTargetRegistry.Assignment(id(1),0,SimulationAccess.Operation.EXPERIMENT,t)).toList();
            assertEquals(LocalVirtualTargetRegistry.Update.APPLIED,registry.replacePrepared(0,assignments,
                    List.of(new LocalVirtualTargetRegistry.Declaration(id(1),0,intent))));
            collection=registry.openCollection(owner,evidence,intent,NOW);
            principals.registerPrepared(new LocalVirtualPrincipal(id(20),"synthetic-executor",0,LocalVirtualPrincipal.Status.ACTIVE,
                    Set.of(TokenRegistryInput.Role.FUSE_WORKER),Set.of(),Map.of(),1));
            byte[] raw=new byte[32];raw[0]=1;var worker=TokenMaterialCodec.encode(raw);
            tokens.registerPrepared(new LocalVirtualTokenRegistry.Credential(id(21),id(20),LocalVirtualTokenRegistry.Status.ACTIVE,0,
                    NOW.minusSeconds(1),NOW.plusSeconds(60),0,worker.fingerprint()));
            executor=tokens.admitCanonical(worker.bearer(),NOW);
            var evaluator=new VirtualExperimentService.PairEvaluator(){
                public String mode(){return VirtualTransactionalStore.MODE;}
                public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment e,String c,int r,Map<String,Object> proposal){throw new AssertionError("No evaluation during creation");}
            };
            service=new VirtualExperimentService(store,new SimulationAccess((a,o,w,c)->false),
                    List.of(new VirtualExperimentService.FixtureSet("synthetic-fixture",List.of(new VirtualExperimentService.Case("synthetic-case",SimulationSpec.KycStatus.VERIFIED,List.of())))),
                    evaluator,()->id(9),null,context);
        }
        LocalVirtualOwnerDelegationRegistry.DelegationEvidence mint(){
            proof=create().proof();assertNotNull(proof);
            delegations=new LocalVirtualOwnerDelegationRegistry(context,tokens,principals,service,executor.reference(),2);
            return delegations.mint(owner,proof,executor,id(30),0,new LocalVirtualOwnerDelegationRegistry.Validity(NOW,NOW.plusSeconds(30)),NOW);
        }
        void detachOwner(){collection.close();owner.close();}
        VirtualExperimentService.CreationResult create(){return service.createForDelegation(owner.actor(),id(5),plan,collection,NOW);}
        public void close(){stale=false;if(context.currentDelegated()!=null)context.currentDelegated().close();collection.close();owner.close();}
    }
    @Test void actualCreationDelegatesExactExperimentOnlyAndClosesWithoutOrdinaryFrame(){
        try(var f=new Fixture()){
            var proof=f.mint();assertEquals(1,f.delegations.size());f.detachOwner();
            try(var phase=f.delegations.openDelegated(f.executor,proof,id(9),NOW)){
                assertNull(f.context.current());assertSame(phase,f.context.currentDelegated());
                assertEquals("synthetic-owner",phase.actor().actorId());
                assertEquals(LocalVirtualAccessPolicy.Decision.ALLOW,phase.authorize(phase.actor(),SimulationAccess.Operation.EXPERIMENT,id(9)));
                assertEquals(LocalVirtualAccessPolicy.Decision.FORBIDDEN,phase.authorize(phase.actor(),SimulationAccess.Operation.READ,id(9)));
                assertEquals(LocalVirtualAccessPolicy.Decision.FORBIDDEN,phase.authorize(phase.actor(),SimulationAccess.Operation.EXPERIMENT,id(99)));
                assertFalse(phase.toString().contains("synthetic-owner"));
            }
            assertNull(f.context.currentDelegated());
        }
    }
    @Test void activeOrdinaryFrameAndWrongPreparedContextCannotAcceptDelegation(){
        try(var f=new Fixture()){
            var proof=f.mint();assertEquals(LocalVirtualAdmissionContext.Code.UNAVAILABLE,
                    assertThrows(LocalVirtualAdmissionContext.Failure.class,()->f.delegations.openDelegated(f.executor,proof,id(9),NOW)).code());
            f.detachOwner();var other=new LocalVirtualAdmissionContext(new LocalVirtualCurrentVerifier(f.tokens,f.principals),f.tokens);
            assertEquals(LocalVirtualAdmissionContext.Code.UNAVAILABLE,assertThrows(LocalVirtualAdmissionContext.Failure.class,
                    ()->other.openDelegated(f.delegations,f.executor,proof,id(9),NOW)).code());
            assertNull(other.currentDelegated());
        }
    }
    @Test void delegationCasRevocationIsPermanentAndStaleRevisionDoesNotMutate(){
        try(var f=new Fixture()){
            var proof=f.mint();assertEquals(LocalVirtualOwnerDelegationRegistry.RevokeStatus.REVISION_CONFLICT,f.delegations.revoke(id(30),1).status());
            assertEquals(LocalVirtualOwnerDelegationRegistry.RevokeStatus.REVOKED,f.delegations.revoke(id(30),0).status());
            assertEquals(LocalVirtualOwnerDelegationRegistry.RevokeStatus.ALREADY_REVOKED,f.delegations.revoke(id(30),1).status());f.detachOwner();
            assertThrows(LocalVirtualAdmissionContext.Failure.class,()->f.delegations.openDelegated(f.executor,proof,id(9),NOW));
            assertNull(f.context.currentDelegated());
        }
    }
    @Test void revokedOwnerAndRevokedExecutorAreRecheckedAtEachNewPhase(){
        try(var f=new Fixture()){
            var proof=f.mint();f.detachOwner();
            try(var phase=f.delegations.openDelegated(f.executor,proof,id(9),NOW)){assertNotNull(phase);}
            f.tokens.revoke(id(2),0);
            assertThrows(LocalVirtualAdmissionContext.Failure.class,()->f.delegations.openDelegated(f.executor,proof,id(9),NOW));
        }
        try(var f=new Fixture()){
            var proof=f.mint();f.detachOwner();f.tokens.revoke(id(21),0);
            assertThrows(LocalVirtualAdmissionContext.Failure.class,()->f.delegations.openDelegated(f.executor,proof,id(9),NOW));
        }
    }
    @Test void expiryAndWrongExperimentFailWithoutLeavingThreadScope(){
        try(var f=new Fixture()){
            var proof=f.mint();f.detachOwner();
            assertThrows(LocalVirtualAdmissionContext.Failure.class,()->f.delegations.openDelegated(f.executor,proof,id(99),NOW));
            assertThrows(LocalVirtualAdmissionContext.Failure.class,()->f.delegations.openDelegated(f.executor,proof,id(9),NOW.plusSeconds(30)));
            assertNull(f.context.currentDelegated());
        }
    }
    @Test void missingCreationProofAndDuplicateRegistrationCannotMintEvidence(){
        try(var f=new Fixture()){
            f.delegations=new LocalVirtualOwnerDelegationRegistry(f.context,f.tokens,f.principals,f.service,f.executor.reference(),2);
            assertEquals(LocalVirtualOwnerDelegationRegistry.Code.UNAVAILABLE,assertThrows(LocalVirtualOwnerDelegationRegistry.Failure.class,
                    ()->f.delegations.mint(f.owner,null,f.executor,id(30),0,new LocalVirtualOwnerDelegationRegistry.Validity(NOW,NOW.plusSeconds(30)),NOW)).code());
            assertEquals(0,f.delegations.size());var proof=f.mint();
            assertEquals(LocalVirtualOwnerDelegationRegistry.Code.CONFLICT,assertThrows(LocalVirtualOwnerDelegationRegistry.Failure.class,
                    ()->f.delegations.mint(f.owner,f.proof,f.executor,id(31),0,new LocalVirtualOwnerDelegationRegistry.Validity(NOW,NOW.plusSeconds(30)),NOW)).code());
            assertNotNull(proof);assertEquals(1,f.delegations.size());
        }
    }
    @Test void committedOwnershipTamperingCannotBeReplacedByCachedReference(){
        try(var f=new Fixture()){
            var proof=f.mint();f.detachOwner();
            f.store.transaction(tx->{var row=new LinkedHashMap<>(tx.get("virtual_experiments",id(9).toString()));row.remove("creationOwner");tx.put("virtual_experiments",id(9).toString(),row);return null;});
            assertEquals(LocalVirtualAdmissionContext.Code.UNAVAILABLE,assertThrows(LocalVirtualAdmissionContext.Failure.class,
                    ()->f.delegations.openDelegated(f.executor,proof,id(9),NOW)).code());
            assertNull(f.context.currentDelegated());
        }
    }
    @Test void equalSnapshotsInDifferentPrincipalGraphCannotBindGenuineCreationDelegation(){
        try(var f=new Fixture()){
            var genuine=f.create().proof();assertNotNull(genuine);
            var different=new LocalVirtualPrincipalRegistry(4,4);
            different.registerPrepared(f.principals.findCurrent(id(1)));
            different.registerPrepared(f.principals.findCurrent(id(20)));
            assertEquals(f.principals.findCurrent(id(1)),different.findCurrent(id(1)));
            assertEquals(LocalVirtualOwnerDelegationRegistry.Code.UNAVAILABLE,
                    assertThrows(LocalVirtualOwnerDelegationRegistry.Failure.class,()->new LocalVirtualOwnerDelegationRegistry(
                            f.context,f.tokens,different,f.service,f.executor.reference(),2)).code());
            var original=f.principals.findCurrent(id(1));
            assertEquals(LocalVirtualPrincipalRegistry.UpdateStatus.UPDATED,f.principals.replacePrepared(id(1),0,
                    new LocalVirtualPrincipal(id(1),original.actorAlias(),1,LocalVirtualPrincipal.Status.DISABLED,
                            original.roles(),original.customerAssignments(),original.workflowAssignments(),1)).status());
            assertEquals(LocalVirtualPrincipal.Status.ACTIVE,different.findCurrent(id(1)).status());
            assertEquals(LocalVirtualOwnerDelegationRegistry.Code.UNAVAILABLE,
                    assertThrows(LocalVirtualOwnerDelegationRegistry.Failure.class,()->new LocalVirtualOwnerDelegationRegistry(
                            f.context,f.tokens,different,f.service,f.executor.reference(),2)).code());
        }
    }
    @Test void actualContextPrincipalGraphDenialIsFreshAndOpaqueVerifierDoesNotAttestGraph(){
        try(var f=new Fixture()){
            var evidence=f.mint();f.detachOwner();
            var executor=f.principals.findCurrent(id(20));
            assertEquals(LocalVirtualPrincipalRegistry.UpdateStatus.UPDATED,f.principals.replacePrepared(id(20),0,
                    new LocalVirtualPrincipal(id(20),executor.actorAlias(),1,LocalVirtualPrincipal.Status.DISABLED,
                            executor.roles(),executor.customerAssignments(),executor.workflowAssignments(),1)).status());
            assertThrows(LocalVirtualAdmissionContext.Failure.class,()->f.delegations.openDelegated(f.executor,evidence,id(9),NOW));
            assertNull(f.context.currentDelegated());
        }
        try(var f=new Fixture()){
            var underlying=new LocalVirtualCurrentVerifier(f.tokens,f.principals);
            var opaque=new LocalVirtualAdmissionContext((reference,now)->underlying.current(reference,now),f.tokens);
            assertEquals(LocalVirtualOwnerDelegationRegistry.Code.UNAVAILABLE,
                    assertThrows(LocalVirtualOwnerDelegationRegistry.Failure.class,()->new LocalVirtualOwnerDelegationRegistry(
                            opaque,f.tokens,f.principals,f.service,f.executor.reference(),2)).code());
        }
    }
}
