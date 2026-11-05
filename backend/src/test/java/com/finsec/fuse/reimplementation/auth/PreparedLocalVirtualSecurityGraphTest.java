package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.application.PreparedLocalVirtualSecurity;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Package access only to actual graph predicate; no reflection, forged graph proof or running application. */
final class PreparedLocalVirtualSecurityGraphTest {
    static UUID id(long n){return new UUID(94,n);}
    static final Instant NOW=Instant.ofEpochSecond(150);
    static final Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);
    static final class Fixture {
        final LocalVirtualTokenRegistry tokens=new LocalVirtualTokenRegistry(2);
        final LocalVirtualPrincipalRegistry principals=new LocalVirtualPrincipalRegistry(2,2);
        final LocalVirtualAdmissionContext.CredentialEvidence owner,executor;
        Fixture(){
            principals.registerPrepared(new LocalVirtualPrincipal(id(1),"synthetic-owner",0,LocalVirtualPrincipal.Status.ACTIVE,
                    Set.of(TokenRegistryInput.Role.DEVELOPER),Set.of("synthetic-customer"),Map.of(id(9),"synthetic-customer"),2));
            principals.registerPrepared(new LocalVirtualPrincipal(id(3),"synthetic-executor",0,LocalVirtualPrincipal.Status.ACTIVE,
                    Set.of(TokenRegistryInput.Role.FUSE_WORKER),Set.of(),Map.of(),1));
            owner=credential(2,1,new byte[32]);byte[] second=new byte[32];second[0]=1;executor=credential(4,3,second);
        }
        LocalVirtualAdmissionContext.CredentialEvidence credential(long token,long principal,byte[] raw){
            var material=TokenMaterialCodec.encode(raw);
            tokens.registerPrepared(new LocalVirtualTokenRegistry.Credential(id(token),id(principal),LocalVirtualTokenRegistry.Status.ACTIVE,
                    0,NOW.minusSeconds(1),NOW.plusSeconds(60),0,material.fingerprint()));
            return tokens.admitCanonical(material.bearer(),NOW);
        }
        VirtualExperimentService creator(LocalVirtualAdmissionContext context){
            var evaluator=new VirtualExperimentService.PairEvaluator(){
                public String mode(){return VirtualTransactionalStore.MODE;}
                public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment e,String c,int r,Map<String,Object> p){throw new AssertionError("No provider execution");}
            };
            return new VirtualExperimentService(new VirtualTransactionalStore(),new SimulationAccess((a,o,w,c)->false),
                    List.of(),evaluator,()->{throw new AssertionError("No ID allocation");},null,context);
        }
    }
    @Test void explicitFactoryCarriesActualSameGraphIntoDelegationConstructorAndCachedPorts(){
        var f=new Fixture();var bundle=PreparedLocalVirtualSecurity.prepareCurrentRegistries(f.tokens,f.principals,CLOCK);
        assertTrue(bundle.context().boundToCurrentGraph(f.tokens,f.principals));
        assertSame(CLOCK,bundle.clock());assertSame(bundle.authority(),bundle.authority());assertSame(bundle.actors(),bundle.actors());
        assertSame(bundle.authenticationFilter(),bundle.authenticationFilter());
        bundle.requireBindings(bundle.authority(),bundle.actors(),bundle.actors(),CLOCK);
        assertNotNull(new LocalVirtualOwnerDelegationRegistry(bundle.context(),f.tokens,f.principals,
                f.creator(bundle.context()),f.executor.reference(),2)); // Construction is not a delegation mint.
        try(var admission=bundle.context().openRequest(f.owner,NOW)){
            assertEquals(id(1),admission.principal().principalId());
            assertEquals(LocalVirtualAccessPolicy.Decision.ALLOW,admission.authorize(SimulationAccess.Operation.READ,id(9),"synthetic-customer"));
        }
        assertNull(bundle.context().current());
    }
    @Test void foreignCredentialOrPrincipalGraphCannotPassConstructorEvenWithEqualPreparedData(){
        var f=new Fixture();var bundle=PreparedLocalVirtualSecurity.prepareCurrentRegistries(f.tokens,f.principals,CLOCK);
        var otherTokens=new LocalVirtualTokenRegistry(2);var otherPrincipals=new LocalVirtualPrincipalRegistry(2,2);
        assertFalse(bundle.context().boundToCurrentGraph(otherTokens,f.principals));
        assertFalse(bundle.context().boundToCurrentGraph(f.tokens,otherPrincipals));
        assertThrows(LocalVirtualOwnerDelegationRegistry.Failure.class,()->new LocalVirtualOwnerDelegationRegistry(bundle.context(),
                otherTokens,f.principals,f.creator(bundle.context()),f.executor.reference(),2));
        assertThrows(LocalVirtualOwnerDelegationRegistry.Failure.class,()->new LocalVirtualOwnerDelegationRegistry(bundle.context(),
                f.tokens,otherPrincipals,f.creator(bundle.context()),f.executor.reference(),2));
    }
    @Test void genericVerifierPathRetainsOrdinaryAuthButCannotAssertConcreteGraph(){
        var f=new Fixture();var bundle=PreparedLocalVirtualSecurity.prepare(f.tokens,new LocalVirtualCurrentVerifier(f.tokens,f.principals),CLOCK);
        assertFalse(bundle.context().boundToCurrentGraph(f.tokens,f.principals));
        try(var admission=bundle.context().openRequest(f.owner,NOW)){
            assertEquals(LocalVirtualAccessPolicy.Decision.ALLOW,admission.authorize(SimulationAccess.Operation.READ,id(9),"synthetic-customer"));
        }
        assertThrows(LocalVirtualOwnerDelegationRegistry.Failure.class,()->new LocalVirtualOwnerDelegationRegistry(bundle.context(),
                f.tokens,f.principals,f.creator(bundle.context()),f.executor.reference(),2));
    }
    @Test void explicitFactoryMissingInputsFailClosedAndRealRevocationIsStillObserved(){
        var f=new Fixture();
        assertThrows(IllegalStateException.class,()->PreparedLocalVirtualSecurity.prepareCurrentRegistries(null,f.principals,CLOCK));
        assertThrows(IllegalStateException.class,()->PreparedLocalVirtualSecurity.prepareCurrentRegistries(f.tokens,null,CLOCK));
        assertThrows(IllegalStateException.class,()->PreparedLocalVirtualSecurity.prepareCurrentRegistries(f.tokens,f.principals,null));
        var bundle=PreparedLocalVirtualSecurity.prepareCurrentRegistries(f.tokens,f.principals,CLOCK);
        f.tokens.revoke(id(2),0);
        assertThrows(LocalVirtualAdmissionContext.Failure.class,()->bundle.context().openRequest(f.owner,NOW));
    }
}
