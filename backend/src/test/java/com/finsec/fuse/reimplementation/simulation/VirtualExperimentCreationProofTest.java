package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.auth.*;
import com.finsec.fuse.reimplementation.persistence.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit synthetic canonical credentials and finite owned collection; no external identity claim. */
final class VirtualExperimentCreationProofTest {
    static UUID id(long n) { return new UUID(102,n); }
    static final Instant NOW=Instant.ofEpochSecond(150);
    static final class Fixture implements AutoCloseable {
        final LocalVirtualTokenRegistry tokens=new LocalVirtualTokenRegistry(2);
        final LocalVirtualPrincipalRegistry principals=new LocalVirtualPrincipalRegistry(2,2);
        final LocalVirtualAdmissionContext context=new LocalVirtualAdmissionContext(new LocalVirtualCurrentVerifier(tokens,principals),tokens);
        final LocalVirtualAdmissionContext.Admission owner;
        final LocalVirtualTargetRegistry registry;
        final LocalVirtualTargetRegistry.CollectionAdmission collection;
        final VirtualTransactionalStore store=new VirtualTransactionalStore();
        final VirtualExperimentService service;
        final VirtualExperimentService.Plan plan=new VirtualExperimentService.Plan("synthetic-fixture",List.of("synthetic-case"),"PAIRED","REPLAY",1);
        boolean stale;
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
            var evaluator=new VirtualExperimentService.PairEvaluator(){
                public String mode(){return VirtualTransactionalStore.MODE;}
                public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment e,String c,int r,Map<String,Object> proposal){throw new AssertionError("No evaluation during creation");}
            };
            service=new VirtualExperimentService(store,new SimulationAccess((a,o,w,c)->false),
                    List.of(new VirtualExperimentService.FixtureSet("synthetic-fixture",List.of(new VirtualExperimentService.Case("synthetic-case",SimulationSpec.KycStatus.VERIFIED,List.of())))),
                    evaluator,()->id(9),null,context);
        }
        VirtualExperimentService.CreationResult create(){return service.createForDelegation(owner.actor(),id(5),plan,collection,NOW);}
        public void close(){stale=false;collection.close();owner.close();}
    }
    @Test void actualCollectionCreationCommitsOriginalOwnerAndProducesIssuerBoundProofWithoutEvaluation(){
        try(var f=new Fixture()){
            var result=f.create();assertEquals("PENDING",result.receipt().get("status"));assertNotNull(result.proof());
            assertTrue(result.proof().createdBy(f.owner));var ref=result.proof().reference();assertTrue(ref.issuedBy(f.service));assertFalse(ref.issuedBy(new Object()));
            assertEquals(f.owner.credential(),ref.ownerCredential());assertEquals(id(9),ref.experimentId());
            assertEquals("SIM_EXPERIMENT",ref.creationIdentity().operation());assertEquals(id(5),ref.creationIdentity().requestId());
            var before=f.store.snapshot();f.service.requireCurrentCreation(ref);assertEquals(before,f.store.snapshot());
            assertEquals(1,before.get("virtual_experiments").size());assertEquals(1,before.get(ActionJournal.TABLE).size());
            assertThrows(UnsupportedOperationException.class,()->result.receipt().put("private","value"));
            assertFalse(result.toString().contains("synthetic-owner"));assertFalse(ref.toString().contains(id(9).toString()));
        }
    }
    @Test void sameCommittedRequestReplaysReceiptWithoutMintingAnotherProof(){
        try(var f=new Fixture()){
            assertNotNull(f.create().proof());var before=f.store.snapshot();var replay=f.create();
            assertEquals(Boolean.TRUE,replay.receipt().get("replayed"));assertNull(replay.proof());assertEquals(before,f.store.snapshot());
        }
    }
    @Test void legacyNullScopeRemainsDeniedAndNoCreationIsPublished(){
        try(var f=new Fixture()){
            var before=f.store.snapshot();assertEquals(403,assertThrows(SimulationFailure.class,()->f.service.create(f.owner.actor(),id(5),f.plan)).status());
            assertEquals(before,f.store.snapshot());
        }
    }
    @Test void staleCollectionRefusesBeforeJournalOrDomainWrite(){
        try(var f=new Fixture()){
            var before=f.store.snapshot();f.stale=true;assertEquals(503,assertThrows(SimulationFailure.class,f::create).status());assertEquals(before,f.store.snapshot());
        }
    }
    @Test void currentOriginalOwnerMetadataAndGlobalReplyAreBothMandatory(){
        try(var f=new Fixture()){
            var ref=f.create().proof().reference();var original=f.store.snapshot();
            f.store.transaction(tx->{var row=new LinkedHashMap<>(tx.get("virtual_experiments",id(9).toString()));row.remove("creationOwner");tx.put("virtual_experiments",id(9).toString(),row);return null;});
            assertEquals(503,assertThrows(SimulationFailure.class,()->f.service.requireCurrentCreation(ref)).status());
            f.store.transaction(tx->{tx.put("virtual_experiments",id(9).toString(),original.get("virtual_experiments").get(id(9).toString()));
                var global=new LinkedHashMap<>(tx.get(ActionJournal.TABLE,id(5).toString()));global.put("canonicalBodyHash","b".repeat(64));tx.put(ActionJournal.TABLE,id(5).toString(),global);return null;});
            assertEquals(503,assertThrows(SimulationFailure.class,()->f.service.requireCurrentCreation(ref)).status());
        }
    }
    @Test void absentCollectionCannotReplaceTypedAdmissionWithActorAlias(){
        try(var f=new Fixture()){
            var before=f.store.snapshot();assertEquals(503,assertThrows(SimulationFailure.class,()->f.service.createForDelegation(f.owner.actor(),id(5),f.plan,null,NOW)).status());assertEquals(before,f.store.snapshot());
        }
    }
    @Test void collectionFromAnotherLiveContextWithSameAliasCannotMintForThisOwnerFrame(){
        try(var f=new Fixture();var other=new Fixture()){
            var before=f.store.snapshot();
            assertEquals(503,assertThrows(SimulationFailure.class,()->f.service.createForDelegation(f.owner.actor(),id(5),f.plan,other.collection,NOW)).status());
            assertEquals(before,f.store.snapshot());
        }
    }

}
