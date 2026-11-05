package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.simulation.SimulationAccess.Operation;
import com.finsec.fuse.reimplementation.simulation.SimulationFailure;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.auth.LocalVirtualTargetRegistry.*;

/** Synthetic current registry/canonical evidence; controlled owned-read fake is protocol coverage, not domain proof. */
final class LocalVirtualTargetRegistryTest {
    static UUID id(long n){return new UUID(93,n);}
    static final Instant NOW=Instant.ofEpochSecond(150);
    static final ExperimentCreation CREATION=new ExperimentCreation(id(1),"synthetic-fixture");
    static final Intent INTENT=new Intent(Operation.EXPERIMENT,CREATION);
    static final Target FIXTURE=new FixtureSet("synthetic-fixture"),SOURCE=new Source(id(8),1),AGENT=new Agent("synthetic-agent",1);
    static final Limits LIMITS=new Limits(10,4,8,8,8,8192);
    static final class Owned implements OwnedCollection {
        List<Target> targets=List.of(FIXTURE,SOURCE,AGENT);int checks,closes;boolean stale;
        public void requireCompleteCurrent(){checks++;if(stale)throw SimulationFailure.unavailable();}
        public List<Target> members(){return targets;}
        public int relationCount(){return targets.size();}
        public int caseCount(){return 1;}
        public void close(){closes++;}
    }
    static final class Fixture implements AutoCloseable {
        final LocalVirtualTokenRegistry tokens=new LocalVirtualTokenRegistry(2);
        final LocalVirtualPrincipalRegistry principals=new LocalVirtualPrincipalRegistry(2,2);
        final LocalVirtualAdmissionContext context=new LocalVirtualAdmissionContext(new LocalVirtualCurrentVerifier(tokens,principals),tokens);
        final LocalVirtualAdmissionContext.CredentialEvidence evidence;
        final LocalVirtualAdmissionContext.Admission owner;
        final LocalVirtualPrincipal principal;
        Fixture(){this(Set.of(TokenRegistryInput.Role.DEVELOPER));}
        Fixture(Set<TokenRegistryInput.Role> roles){
            principal=new LocalVirtualPrincipal(id(1),"synthetic-owner",0,LocalVirtualPrincipal.Status.ACTIVE,roles,Set.of(),Map.of(),1);
            principals.registerPrepared(principal);var material=TokenMaterialCodec.encode(new byte[32]);
            tokens.registerPrepared(new LocalVirtualTokenRegistry.Credential(id(2),id(1),LocalVirtualTokenRegistry.Status.ACTIVE,0,
                    NOW.minusSeconds(1),NOW.plusSeconds(60),0,material.fingerprint()));
            evidence=tokens.admitCanonical(material.bearer(),NOW);owner=context.openRequest(evidence,NOW);
        }
        LocalVirtualTargetRegistry registry(Owned owned){
            return new LocalVirtualTargetRegistry(tokens,principals,context,LIMITS,(intent,p,limits)->{
                assertEquals(INTENT,intent);assertSame(principal,p);assertSame(LIMITS,limits);return owned;});
        }
        List<Assignment> assignments(){return List.of(CREATION,FIXTURE,SOURCE,AGENT).stream()
                .map(t->new Assignment(id(1),0,Operation.EXPERIMENT,t)).toList();}
        void install(LocalVirtualTargetRegistry registry){assertEquals(Update.APPLIED,registry.replacePrepared(0,assignments(),List.of(new Declaration(id(1),0,INTENT))));}
        public void close(){owner.close();}
    }
    static void unavailable(org.junit.jupiter.api.function.Executable action){assertEquals(503,assertThrows(SimulationFailure.class,action).status());}
    @Test void canonicalExactIntentAndAllMembersProducePrivateFiniteSnapshotWithoutOrdinaryGlobalAllow(){
        try(var f=new Fixture()){
            var owned=new Owned();var registry=f.registry(owned);f.install(registry);
            assertEquals(LocalVirtualAccessPolicy.Decision.SCOPE_UNCONFIRMED,f.owner.authorize(Operation.EXPERIMENT,null,null));
            try(var collection=registry.openCollection(f.owner,f.evidence,INTENT,NOW)){
                assertSame(collection,registry.currentCollection());assertEquals(3,collection.snapshot().members().size());
                assertEquals(1,collection.snapshot().assignmentRevision());
                collection.requireCreation(f.owner.actor(),"synthetic-fixture",NOW);
                assertEquals(LocalVirtualAccessPolicy.Decision.SCOPE_UNCONFIRMED,f.owner.authorize(Operation.EXPERIMENT,null,null));
                assertThrows(UnsupportedOperationException.class,()->collection.snapshot().members().clear());
            }
            assertNull(registry.currentCollection());assertEquals(1,owned.closes);assertSame(f.owner,f.context.current());
        }
    }
    @Test void unconfiguredUndeclaredAndMissingMemberAssignmentNeverPermitPartialCollection(){
        try(var f=new Fixture()){
            var owned=new Owned();var registry=f.registry(owned);
            unavailable(()->registry.openCollection(f.owner,f.evidence,INTENT,NOW));assertEquals(0,owned.checks);
            var a=f.assignments().subList(0,3);
            registry.replacePrepared(0,a,List.of(new Declaration(id(1),0,INTENT)));
            unavailable(()->registry.openCollection(f.owner,f.evidence,INTENT,NOW));assertEquals(1,owned.closes);assertNull(registry.currentCollection());
            var absent=new LocalVirtualTargetRegistry(f.tokens,f.principals,f.context,LIMITS,null);f.install(absent);
            unavailable(()->absent.openCollection(f.owner,f.evidence,INTENT,NOW));
        }
    }
    @Test void declaredEmptyStillRequiresPositiveOwnedResolverAndExplicitBoundaryAssignment(){
        try(var f=new Fixture()){
            var owned=new Owned();owned.targets=List.of();var registry=f.registry(owned);
            registry.replacePrepared(0,List.of(new Assignment(id(1),0,Operation.EXPERIMENT,CREATION)),List.of(new Declaration(id(1),0,INTENT)));
            try(var scope=registry.openCollection(f.owner,f.evidence,INTENT,NOW)){
                assertTrue(scope.snapshot().members().isEmpty());scope.requireCreation(f.owner.actor(),"synthetic-fixture",NOW);
            }
            assertTrue(owned.checks>=3);assertEquals(1,owned.closes);
        }
    }
    @Test void CASRevisionChangeAndOwnedNewMemberFenceRejectLiveSnapshot(){
        try(var f=new Fixture()){
            var owned=new Owned();var registry=f.registry(owned);f.install(registry);
            var scope=registry.openCollection(f.owner,f.evidence,INTENT,NOW);
            assertEquals(Update.CONFLICT,registry.replacePrepared(0,f.assignments(),List.of(new Declaration(id(1),0,INTENT))));
            registry.replacePrepared(1,f.assignments(),List.of(new Declaration(id(1),0,INTENT)));
            unavailable(()->scope.requireCurrent(NOW));unavailable(scope::close);assertNull(registry.currentCollection());assertEquals(1,owned.closes);
        }
        try(var f=new Fixture()){
            var owned=new Owned();var registry=f.registry(owned);f.install(registry);var scope=registry.openCollection(f.owner,f.evidence,INTENT,NOW);
            owned.stale=true;unavailable(()->scope.requireCurrent(NOW));unavailable(scope::close);assertNull(registry.currentCollection());
        }
    }
    @Test void wrongActorFixtureOperationAndWorkerRoleDoNotBecomeExperimentPermission(){
        try(var f=new Fixture()){
            var owned=new Owned();var registry=f.registry(owned);f.install(registry);
            try(var scope=registry.openCollection(f.owner,f.evidence,INTENT,NOW)){
                assertEquals(403,assertThrows(SimulationFailure.class,()->scope.requireCreation(new ActorRef("synthetic-foreign"),"synthetic-fixture",NOW)).status());
                assertEquals(403,assertThrows(SimulationFailure.class,()->scope.requireCreation(f.owner.actor(),"synthetic-other",NOW)).status());
                assertEquals(403,assertThrows(SimulationFailure.class,()->scope.requireMember(f.owner.actor(),Operation.READ,FIXTURE,NOW)).status());
                unavailable(()->registry.openCollection(f.owner,f.evidence,INTENT,NOW));
            }
        }
        try(var f=new Fixture(Set.of(TokenRegistryInput.Role.FUSE_WORKER))){
            var owned=new Owned();var registry=f.registry(owned);f.install(registry);
            assertEquals(403,assertThrows(SimulationFailure.class,()->registry.openCollection(f.owner,f.evidence,INTENT,NOW)).status());assertEquals(0,owned.checks);
        }
    }
    @Test void canonicalIssuerRevokeExpiryAndClosedHandlesFailBeforeAuthorization(){
        try(var f=new Fixture()){
            var owned=new Owned();var registry=f.registry(owned);f.install(registry);
            assertEquals(401,assertThrows(SimulationFailure.class,()->registry.openCollection(f.owner,null,INTENT,NOW)).status());
            var foreign=new LocalVirtualTokenRegistry(1);var material=TokenMaterialCodec.encode(new byte[32]);
            foreign.registerPrepared(new LocalVirtualTokenRegistry.Credential(id(2),id(1),LocalVirtualTokenRegistry.Status.ACTIVE,0,NOW.minusSeconds(1),NOW.plusSeconds(60),0,material.fingerprint()));
            assertEquals(401,assertThrows(SimulationFailure.class,()->registry.openCollection(f.owner,foreign.admitCanonical(material.bearer(),NOW),INTENT,NOW)).status());
            var scope=registry.openCollection(f.owner,f.evidence,INTENT,NOW);f.tokens.revoke(id(2),0);
            assertEquals(401,assertThrows(SimulationFailure.class,()->scope.requireCurrent(NOW)).status());scope.close();
            unavailable(scope::snapshot);
        }
        try(var f=new Fixture()){
            var registry=f.registry(new Owned());f.install(registry);
            assertEquals(401,assertThrows(SimulationFailure.class,()->registry.openCollection(f.owner,f.evidence,INTENT,NOW.plusSeconds(60))).status());
        }
    }
    @Test void boundsDuplicateMembersAndConstructorSnapshotsAreNotTruncated(){
        try(var f=new Fixture()){
            var foreignContext=new LocalVirtualAdmissionContext(new LocalVirtualCurrentVerifier(f.tokens,f.principals),new Object());
            unavailable(()->new LocalVirtualTargetRegistry(f.tokens,f.principals,foreignContext,LIMITS,null));
            var owned=new Owned();owned.targets=List.of(FIXTURE,FIXTURE);var registry=f.registry(owned);f.install(registry);
            unavailable(()->registry.openCollection(f.owner,f.evidence,INTENT,NOW));assertEquals(1,owned.closes);
            var small=new LocalVirtualTargetRegistry(f.tokens,f.principals,f.context,new Limits(10,4,2,8,8,8192),(i,p,l)->new Owned());f.install(small);
            unavailable(()->small.openCollection(f.owner,f.evidence,INTENT,NOW));
            List<Assignment> growing=new AbstractList<>(){
                public int size(){return 0;}public Assignment get(int i){throw new AssertionError();}
                public Object[] toArray(){return Collections.nCopies(11,f.assignments().get(0)).toArray();}
            };
            assertThrows(SimulationFailure.class,()->registry.replacePrepared(registry.revision(),growing,List.of()));
        }
    }
    @Test void ordinaryFirstOperationLatchCannotBeResetByCollectionMode(){
        try(var f=new Fixture()){
            var owned=new Owned();var registry=f.registry(owned);f.install(registry);
            assertEquals(LocalVirtualAccessPolicy.Decision.SCOPE_UNCONFIRMED,f.owner.authorize(Operation.READ,null,null));
            assertEquals(403,assertThrows(SimulationFailure.class,()->registry.openCollection(f.owner,f.evidence,INTENT,NOW)).status());
            assertEquals(0,owned.checks);assertNull(registry.currentCollection());
        }
    }

    @Test void serviceOwnerGuardRequiresExactContextAndLiveParentNotSameAlias(){
        try(var f=new Fixture()){
            var owned=new Owned();var registry=f.registry(owned);f.install(registry);
            try(var scope=registry.openCollection(f.owner,f.evidence,INTENT,NOW)){
                scope.requireOwner(f.context);scope.requireOwner(f.owner);
                var foreign=new LocalVirtualAdmissionContext(new LocalVirtualCurrentVerifier(f.tokens,f.principals),f.tokens);
                try(var other=foreign.openRequest(f.evidence,NOW)){
                    assertEquals(f.owner.actor(),other.actor());assertNotSame(f.owner,other);
                    unavailable(()->scope.requireOwner(foreign));
                    unavailable(()->scope.requireOwner(other));
                    scope.requireOwner(f.context);
                }
                unavailable(()->scope.requireOwner((LocalVirtualAdmissionContext)null));
            }
        }
    }

}
