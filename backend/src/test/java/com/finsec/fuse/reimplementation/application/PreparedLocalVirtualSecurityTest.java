package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.auth.*;
import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.*;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Prepared object graph only; no listener, servlet container, task, provider or actual security identity. */
final class PreparedLocalVirtualSecurityTest {
    private static final Instant T=Instant.parse("2030-01-01T00:00:00Z");
    private static final UUID PID=new UUID(0,1),TOKEN=new UUID(0,2),WF=new UUID(0,3);
    private static final class FakeExecutor extends AbstractExecutorService {
        int shutdowns,awaits,executions;
        public void shutdown(){shutdowns++;}
        public List<Runnable> shutdownNow(){throw new AssertionError("No forced executor cleanup");}
        public boolean isShutdown(){return shutdowns!=0;}
        public boolean isTerminated(){return shutdowns!=0;}
        public boolean awaitTermination(long wait,TimeUnit unit){awaits++;return true;}
        public void execute(Runnable task){executions++;throw new AssertionError("No execution during composition");}
    }
    private static final class Fixture {
        final Clock clock=Clock.fixed(T,ZoneOffset.UTC);
        final LocalVirtualTokenRegistry tokens=new LocalVirtualTokenRegistry(2);
        final LocalVirtualPrincipalRegistry principals=new LocalVirtualPrincipalRegistry(2,2);
        final LocalVirtualPrincipal principal=new LocalVirtualPrincipal(PID,"synthetic-local-actor",0,
            LocalVirtualPrincipal.Status.ACTIVE,Set.of(TokenRegistryInput.Role.CUSTOMER),
            Set.of("synthetic-local-customer"),Map.of(WF,"synthetic-local-customer"),2);
        final TokenMaterialCodec.Material material=TokenMaterialCodec.encode(new byte[32]);
        final FakeExecutor executor=new FakeExecutor();
        final PreparedSyntheticProviders providers=new PreparedSyntheticProviders(List.of(),List.of(),1,1);
        final VirtualQuarantineService.RemediationVerifier remediation=(actor,target,remediation)->{throw new AssertionError("No remediation query");};
        final VirtualHttpApplication.ReadinessAuthorization readiness=request->{throw new AssertionError("No readiness query");};
        final java.util.function.BooleanSupplier dependencies=()->{throw new AssertionError("No dependency query");};
        final PreparedVirtualConfiguration configuration;
        Fixture(){
            tokens.registerPrepared(new LocalVirtualTokenRegistry.Credential(TOKEN,PID,LocalVirtualTokenRegistry.Status.ACTIVE,
                0,T,T.plusSeconds(60),0,material.fingerprint()));principals.registerPrepared(principal);
            var limits=new HttpLimits(4096,8192,16);var base=Path.of("/synthetic-unopened-local-auth");
            var settings=new VirtualLoopbackListener.Settings(new VirtualHttpApplication.Config("127.0.0.1",18080,
                "/internal/v1/ready",limits,1000,1),base,base.resolve("doc"),base.resolve("work"),0,2,1,1,1,0,1,1000,2,1000);
            configuration=new PreparedVirtualConfiguration(settings,new SimulationSpec.Catalog(List.of(),List.of()),
                new SimulationSpec.RiskTerms("SYNTHETIC-ONLY",1,2,3,10,2,1,Duration.ofMinutes(1)),List.of(),1,clock,
                ()->{throw new AssertionError("No IDs during composition");},new ActorRef("synthetic-delivery"),1);
        }
        LocalVirtualCurrentVerifier verifier(){return new LocalVirtualCurrentVerifier(tokens,principals);}
        PreparedLocalVirtualSecurity bundle(){return PreparedLocalVirtualSecurity.prepare(tokens,verifier(),clock);}
        DataConfiguredVirtualApplicationFactory factory(PreparedResourceLease lease){
            return DataConfiguredVirtualApplicationFactory.localAuthA(configuration,tokens,verifier(),remediation,
                readiness,dependencies,providers,lease);
        }
    }
    private void configRequired(org.junit.jupiter.api.function.Executable action){
        var error=assertThrows(IllegalStateException.class,action);
        assertEquals("CONFIGURATION_REQUIRED",error.getMessage());assertNull(error.getCause());
    }
    private VirtualProductAssembly.Inputs inputs(Fixture f,PreparedLocalVirtualSecurity bundle,
            SimulationAccess.Authority authority,Clock clock){
        return new VirtualProductAssembly.Inputs(new VirtualTransactionalStore(),f.configuration.catalog(),f.configuration.riskTerms(),
            authority,f.remediation,List.of(),f.providers.pairs(),clock,f.configuration.actionIds(),bundle.actors(),bundle.actors(),
            f.configuration.listener().application().httpLimits(),bundle);
    }
    @Test void actualFactoryCarriesExactCachedLocalPortsClockAndOwnedLeaseWithoutCallbacks(){
        var f=new Fixture();var lease=PreparedResourceLease.owned(f.executor,17);var factory=f.factory(lease);
        var prepared=factory.prepare();var input=prepared.inputs();var bundle=input.localAuthentication();
        assertNotNull(bundle);assertSame(bundle.authority(),input.authority());
        assertSame(bundle.actors(),input.startResumeActors());assertSame(bundle.actors(),input.otherActors());
        assertSame(f.clock,bundle.clock());assertSame(f.clock,input.clock());
        assertSame(f.readiness,prepared.authorization());assertSame(f.dependencies,prepared.dependenciesAvailable());
        assertSame(f.executor,prepared.delivery().executor());
        assertSame(f.executor,((ConfiguredVirtualApplicationHost.OwnedExecutor)prepared.ownership()).executor());
        assertEquals(PreparedResourceLease.State.TRANSFERRED,lease.state());
        assertEquals(PreparedResourceLease.Cleanup.TRANSFERRED_TO_PREPARED,lease.cleanup());
        lease.close();assertEquals(0,f.executor.shutdowns);assertEquals(0,f.executor.awaits);assertEquals(0,f.executor.executions);
        assertThrows(IllegalStateException.class,factory::prepare);
        assertEquals("PreparedLocalVirtualSecurity[REDACTED]",bundle.toString());
    }
    @Test void sameActualRegistryAndCurrentPrincipalVerifierOpenAndAuthorizeBundleContext(){
        var f=new Fixture();var bundle=f.bundle();var evidence=f.tokens.admitCanonical(f.material.bearer(),T);assertNotNull(evidence);
        try(var admission=bundle.context().openRequest(evidence,T)){
            assertSame(f.principal,admission.principal());assertSame(admission,bundle.context().current());
            assertTrue(bundle.authority().allows(admission.actor(),SimulationAccess.Operation.READ,WF,"synthetic-local-customer"));
            assertFalse(bundle.authority().allows(new ActorRef("synthetic-foreign"),SimulationAccess.Operation.READ,WF,"synthetic-local-customer"));
        }
        assertNull(bundle.context().current());
    }
    @Test void mixedAuthorityActorsOrEquivalentButDifferentClockRefuseCanonicalInputs(){
        var f=new Fixture();var bundle=f.bundle();
        assertNotNull(inputs(f,bundle,bundle.authority(),f.clock));
        configRequired(()->inputs(f,bundle,(actor,op,w,c)->true,f.clock));
        configRequired(()->inputs(f,bundle,bundle.authority(),Clock.fixed(T,ZoneOffset.UTC)));
        var other=f.bundle();
        configRequired(()->bundle.requireBindings(bundle.authority(),other.actors(),bundle.actors(),f.clock));
        configRequired(()->bundle.requireBindings(bundle.authority(),bundle.actors(),other.actors(),f.clock));
        // actors.authority() creates a new callback; identity must use the cached bundle getter.
        configRequired(()->bundle.requireBindings(bundle.actors().authority(),bundle.actors(),bundle.actors(),f.clock));
    }
    @Test void missingMandatoryConfigurationRefusesBeforeLeaseClaimAndNeverDefaultsVerifier(){
        var f=new Fixture();var lease=PreparedResourceLease.owned(f.executor,17);
        configRequired(()->PreparedLocalVirtualSecurity.prepare(null,f.verifier(),f.clock));
        configRequired(()->PreparedLocalVirtualSecurity.prepare(f.tokens,null,f.clock));
        configRequired(()->PreparedLocalVirtualSecurity.prepare(f.tokens,f.verifier(),null));
        configRequired(()->DataConfiguredVirtualApplicationFactory.localAuthA(null,f.tokens,f.verifier(),f.remediation,f.readiness,f.dependencies,f.providers,lease));
        configRequired(()->DataConfiguredVirtualApplicationFactory.localAuthA(f.configuration,f.tokens,null,f.remediation,f.readiness,f.dependencies,f.providers,lease));
        assertEquals(PreparedResourceLease.State.AVAILABLE,lease.state());assertEquals(0,f.executor.shutdowns);
        lease.close();assertEquals(1,f.executor.shutdowns);assertEquals(1,f.executor.awaits);
    }
    @Test void bundleSameTokenRechecksBeforeAndAfterTrustedVerifierPreventRevocationRacePromotion(){
        var f=new Fixture();var calls=new AtomicInteger();
        var bundle=PreparedLocalVirtualSecurity.prepare(f.tokens,(reference,now)->{
            calls.incrementAndGet();f.tokens.revoke(TOKEN,0);
            return new LocalVirtualAdmissionContext.VerifiedSnapshot(reference,LocalVirtualAdmissionContext.CredentialState.ACTIVE,f.principal);
        },f.clock);
        var evidence=f.tokens.admitCanonical(f.material.bearer(),T);assertNotNull(evidence);
        var failure=assertThrows(LocalVirtualAdmissionContext.Failure.class,()->bundle.context().openRequest(evidence,T));
        assertEquals(LocalVirtualAdmissionContext.Code.UNAUTHENTICATED,failure.code());assertEquals(1,calls.get());
        assertNull(bundle.context().current());
        assertThrows(LocalVirtualAdmissionContext.Failure.class,()->bundle.context().openRequest(evidence,T));
        assertEquals(1,calls.get(),"Already revoked credential must stop before verifier");
    }
    @Test void foreignRegistryCanonicalEvidenceCannotUsePreparedBundleIssuer(){
        var f=new Fixture();var other=new Fixture();var calls=new AtomicInteger();
        var bundle=PreparedLocalVirtualSecurity.prepare(f.tokens,(ref,now)->{calls.incrementAndGet();return f.verifier().current(ref,now);},f.clock);
        var foreign=other.tokens.admitCanonical(other.material.bearer(),T);assertNotNull(foreign);
        var failure=assertThrows(LocalVirtualAdmissionContext.Failure.class,()->bundle.context().openRequest(foreign,T));
        assertEquals(LocalVirtualAdmissionContext.Code.UNAUTHENTICATED,failure.code());assertEquals(0,calls.get());
    }
    @Test void actualPublicApplicationOrderedFiltersContainsSameBundleFilterAfterExistingGuards(){
        var f=new Fixture();var prepared=f.factory(PreparedResourceLease.borrowed(f.executor)).prepare();
        var app=new VirtualHttpApplication(prepared.settings().application(),prepared.inputs(),prepared.authorization(),prepared.dependenciesAvailable());
        var filters=app.orderedFilters();var existing=app.product().http().orderedFilters();
        assertEquals(3,filters.length);assertEquals(2,existing.length);
        assertSame(existing[0],filters[0]);assertSame(existing[1],filters[1]);
        assertSame(prepared.inputs().localAuthentication().authenticationFilter(),filters[2]);
        filters[2]=null;assertNotNull(app.orderedFilters()[2]);
        assertEquals(0,f.executor.executions);assertEquals(0,f.executor.shutdowns);
    }
    @Test void oldTwelveArgumentExternalInputsKeepNoLocalBundleAndTwoGuards(){
        var f=new Fixture();var bundle=f.bundle();
        var input=new VirtualProductAssembly.Inputs(new VirtualTransactionalStore(),f.configuration.catalog(),f.configuration.riskTerms(),
            bundle.authority(),f.remediation,List.of(),f.providers.pairs(),f.clock,f.configuration.actionIds(),bundle.actors(),bundle.actors(),
            f.configuration.listener().application().httpLimits());
        assertNull(input.localAuthentication());
        var app=new VirtualHttpApplication(f.configuration.listener().application(),input,f.readiness,f.dependencies);
        assertEquals(2,app.orderedFilters().length);assertEquals(0,f.executor.executions);
    }
}
