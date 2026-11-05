package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.auth.*;
import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.http.*;
import com.finsec.fuse.reimplementation.simulation.*;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;

/** Prepared graph only. Throwing facts are acquisition traps, not invented current CLEAR/commit results. */
final class PreparedTypedVirtualApplicationFactoryTest {
    private static UUID id(long n){return new UUID(92,n);}
    private static final class Executor extends AbstractExecutorService {
        int shutdowns,awaits,executions;
        public void shutdown(){shutdowns++;}public List<Runnable> shutdownNow(){throw new AssertionError("No forced stop");}
        public boolean isShutdown(){return shutdowns!=0;}public boolean isTerminated(){return shutdowns!=0;}
        public boolean awaitTermination(long value,TimeUnit unit){awaits++;return true;}
        public void execute(Runnable task){executions++;throw new AssertionError("No submitted work");}
    }
    private static final class Facts implements VirtualGrantWorkflowBridge.ContinuationFacts {
        int calls;
        private <T>T unused(){calls++;throw new AssertionError("No fact acquisition during construction");}
        public VirtualGrantFactResolver.Snapshot load(ServerContext c,StageCommand command,OwnedTx tx){return unused();}
        public SyntheticGrantTemporalAssessment.Fact versionChanged(ServerContext c,StageCommand command,OwnedTx tx,String version){return unused();}
        public VirtualMockPaymentFactResolver.PaymentSnapshot loadPayment(ServerContext c,SyntheticMockPaymentTransactionBinding.PaymentCommand command,
                OwnedTx tx,VirtualGrantFactResolver.Snapshot snapshot){return unused();}
        public Gate current(SyntheticRootProvisionService.RootServerContext c,SyntheticRootProvisionBinding.RootCommand command,OwnedRootProvisionPort.OwnedRootTx tx){return unused();}
        public SyntheticRootProvisionBinding.ResolvedRootProvision resolve(SyntheticRootProvisionService.RootServerContext c,SyntheticRootProvisionBinding.RootCommand command,
                SyntheticRootProvisionBinding.CurrentBindings bindings,OwnedRootProvisionPort.OwnedRootTx tx){return unused();}
        public Gate current(ServerContext c,SyntheticKycPreparationBinding.PreparationCommand command,OwnedKycPreparationPort.OwnedPreparationTx tx){return unused();}
        public Gate current(SyntheticMockPaymentPlanService.PlanServerContext c,CommandIdentity identity,SyntheticMockPaymentPlanBinding.PlanOperation operation,OwnedMockPaymentPlanPort.OwnedPlanTx tx){return unused();}
        public SyntheticMockPaymentPlanBinding.ResolvedEvidence resolveEvidence(SyntheticMockPaymentPlanService.PlanServerContext c,CommandIdentity identity,
                SyntheticMockPaymentPlanBinding.ReviewBindings bindings,OwnedMockPaymentPlanPort.OwnedPlanTx tx){return unused();}
        public Gate current(SyntheticTypedContinuationService.ContinuationServerContext c,SyntheticTypedContinuationBinding.ContinuationCommand command,OwnedTypedContinuationPort.OwnedContinuationTx tx){return unused();}
        public SyntheticTypedContinuationBinding.ResolvedContinuation resolve(SyntheticTypedContinuationService.ContinuationServerContext c,SyntheticTypedContinuationBinding.ContinuationCommand command,
                SyntheticTypedContinuationBinding.CurrentBindings bindings,OwnedTypedContinuationPort.OwnedContinuationTx tx){return unused();}
    }
    private static final class Fixture {
        final Clock clock=Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"),ZoneOffset.UTC);
        final SimulationSpec.Catalog catalog=new SimulationSpec.Catalog(List.of(),List.of());
        final SimulationSpec.RiskTerms terms=new SimulationSpec.RiskTerms("synthetic-policy",1,1,1,20,5,1,Duration.ofSeconds(60));
        final Executor executor=new Executor();final Facts facts=new Facts();
        final PreparedSyntheticProviders providers=new PreparedSyntheticProviders(List.of(),List.of(),1,1);
        final LocalVirtualTokenRegistry tokens=new LocalVirtualTokenRegistry(1);
        final LocalVirtualPrincipalRegistry principals=new LocalVirtualPrincipalRegistry(1,1);
        final PreparedLocalVirtualSecurity security=PreparedLocalVirtualSecurity.prepare(tokens,new LocalVirtualCurrentVerifier(tokens,principals),clock);
        final PreparedSecurityBindings ports=new PreparedSecurityBindings(security.authority(),(a,t,r)->{throw new AssertionError("No remediation");},
            security.actors(),security.actors(),r->{throw new AssertionError("No readiness");},()->{throw new AssertionError("No dependencies");});
        final PreparedVirtualConfiguration configuration;
        final VirtualProductAssembly.TypedInputs nativeTyped;
        final PreparedTypedInputs typed;
        Fixture(){
            var limits=new HttpLimits(4096,8192,16);var base=Path.of("/synthetic-unopened-typed-factory");
            var settings=new VirtualLoopbackListener.Settings(new VirtualHttpApplication.Config("127.0.0.1",18080,"/internal/v1/ready",limits,1000,1),
                base,base.resolve("doc"),base.resolve("work"),0,2,1,1,1,0,1,1000,2,1000);
            configuration=new PreparedVirtualConfiguration(settings,catalog,terms,List.of(),1,clock,()->{throw new AssertionError("No ID allocation");},new ActorRef("synthetic-delivery"),1);
            var issuer=new SyntheticGrantIssuerBindings.Binding("synthetic-subject",id(90),"synthetic-principal","synthetic-issuer",
                SyntheticGrantIssuerBindings.Stage.KYC_EVALUATOR,AllowedAction.EVALUATE_KYC,"synthetic-customer",id(10),id(1),"synthetic-intent",
                new SyntheticGrantIssuerBindings.KeyReference("synthetic-key","HMAC-SHA256","synthetic-key-owner"));
            var registry=SyntheticGrantIssuerBindings.prepare("synthetic-registry",List.of(issuer),new SyntheticGrantIssuerBindings.Limits(1,128));
            nativeTyped=new VirtualProductAssembly.TypedInputs(registry,facts,()->{throw new AssertionError("No journal token allocation");},65536);
            var source=new SimulationSpec.Source(id(20),1,"synthetic-unexecuted-source",SimulationSpec.rawHash("synthetic-unexecuted-source"),true);
            var identity=new CommandIdentity("synthetic-actor",id(100),"synthetic-prepare","synthetic-v1","a".repeat(64),id(101),id(102),id(103),id(1),1,"synthetic-customer");
            var payload=new PreparedTypedActionCatalog.Preparation(new SyntheticKycPreparationBinding.PreparationCommand(identity,source,List.of(),terms,clock.instant()));
            var action=new PreparedTypedActionCatalog.PreparedAction(id(104),payload,new PreparedTypedActionCatalog.PrincipalBinding(id(90),0,"synthetic-actor","synthetic-subject"),
                new PreparedTypedActionCatalog.Coordinates(id(1),1,"synthetic-customer",id(20),1,source.contentHash(),terms.policyVersion()));
            // Explicit unresolved producer; construction must not invoke it or call it current truth.
            TypedWorkflowMutationController.CurrentCoordinates current=(ref,purpose,request,admission,reconcile)->{throw new AssertionError("No current coordinate query");};
            typed=new PreparedTypedInputs(nativeTyped,new VirtualProductAssembly.ContinuationInputs(facts,catalog),
                new PreparedTypedActionCatalog(List.of(action),1),security,current);
        }
        PreparedTypedVirtualApplicationFactory factory(PreparedResourceLease lease){return new PreparedTypedVirtualApplicationFactory(configuration,ports,providers,lease,typed);}
    }
    private void required(org.junit.jupiter.api.function.Executable action){
        var error=assertThrows(IllegalStateException.class,action);assertEquals("CONFIGURATION_REQUIRED",error.getMessage());assertNull(error.getCause());
    }
    @Test void actualPreparedCarriesSharedTypedDeliveryContextClockAndExecutorWithoutEffects(){
        var f=new Fixture();var lease=PreparedResourceLease.owned(f.executor,19);var prepared=f.factory(lease).prepare();
        assertSame(f.typed,prepared.typed());assertSame(f.security,prepared.inputs().localAuthentication());
        assertSame(f.clock,prepared.inputs().clock());assertSame(f.catalog,prepared.inputs().catalog());
        assertSame(f.executor,prepared.delivery().executor());assertSame(f.configuration.actionIds(),prepared.delivery().actionIds());
        assertSame(f.security.context(),prepared.typed().security().context());
        assertSame(f.facts,prepared.typed().typed().facts());assertSame(f.facts,prepared.typed().continuation().facts());
        assertEquals(1,prepared.typed().actions().size());
        var metadata=prepared.typed().actions().metadata(id(104));
        assertEquals(id(1),metadata.coordinates().workflowId());assertEquals(1,metadata.coordinates().generation());
        assertEquals("synthetic-customer",metadata.coordinates().customerId());
        assertSame(f.typed.currentCoordinates(),prepared.typed().currentCoordinates());
        assertEquals(0,f.facts.calls);assertEquals(0,f.executor.executions);
        assertTrue(prepared.inputs().store().snapshot().values().stream().allMatch(Map::isEmpty));
        assertEquals(PreparedResourceLease.State.TRANSFERRED,lease.state());lease.close();assertEquals(0,f.executor.shutdowns);
    }
    @Test void publicApplicationExposesOneStableProductStoreBridgeAndDeliveryCoordinator(){
        var f=new Fixture();var prepared=f.factory(PreparedResourceLease.borrowed(f.executor)).prepare();
        var app=new VirtualHttpApplication(prepared.settings().application(),prepared.inputs(),prepared.delivery(),prepared.authorization(),prepared.dependenciesAvailable(),prepared.typed());
        assertSame(prepared.inputs().store(),app.product().store());
        assertSame(app.product().grantWorkflows(),app.product().grantWorkflows());
        assertSame(app.product().deliveries(),app.product().deliveries());
        assertEquals(new VirtualDeliveryCoordinator.DispatchStatus(0,0,0,0),app.product().deliveries().status());
        assertEquals(3,app.orderedFilters().length);assertSame(f.security.authenticationFilter(),app.orderedFilters()[2]);
        assertEquals(0,f.executor.executions);assertEquals(0,f.facts.calls);
        assertTrue(app.product().store().snapshot().values().stream().allMatch(Map::isEmpty));
    }
    @Test void nullMandatoryTypedInputsAndDifferentFactsAreNeverDefaulted(){
        var f=new Fixture();
        assertThrows(NullPointerException.class,()->new VirtualProductAssembly.TypedInputs(f.nativeTyped.issuerRegistry(),null,f.nativeTyped.journalTokens(),65536));
        required(()->new PreparedTypedInputs(null,f.typed.continuation(),f.typed.actions(),f.security,f.typed.currentCoordinates()));
        required(()->new PreparedTypedInputs(f.nativeTyped,null,f.typed.actions(),f.security,f.typed.currentCoordinates()));
        required(()->new PreparedTypedInputs(f.nativeTyped,f.typed.continuation(),null,f.security,f.typed.currentCoordinates()));
        required(()->new PreparedTypedInputs(f.nativeTyped,f.typed.continuation(),f.typed.actions(),null,f.typed.currentCoordinates()));
        required(()->new PreparedTypedInputs(f.nativeTyped,f.typed.continuation(),f.typed.actions(),f.security,null));
        required(()->new PreparedTypedInputs(f.nativeTyped,new VirtualProductAssembly.ContinuationInputs(new Facts(),f.catalog),f.typed.actions(),f.security,f.typed.currentCoordinates()));
    }
    @Test void mixedCatalogClockAndPortsFailBeforeLeaseClaimAndCallerOwnsCleanup(){
        var f=new Fixture();var lease=PreparedResourceLease.owned(f.executor,19);
        required(()->new PreparedTypedVirtualApplicationFactory(null,f.ports,f.providers,lease,f.typed));
        required(()->new PreparedTypedVirtualApplicationFactory(f.configuration,f.ports,f.providers,lease,null));
        var wrongCatalog=new PreparedTypedInputs(f.nativeTyped,new VirtualProductAssembly.ContinuationInputs(f.facts,new SimulationSpec.Catalog(List.of(),List.of())),f.typed.actions(),f.security,f.typed.currentCoordinates());
        required(()->new PreparedTypedVirtualApplicationFactory(f.configuration,f.ports,f.providers,lease,wrongCatalog));
        var otherClock=new PreparedVirtualConfiguration(f.configuration.listener(),f.catalog,f.terms,List.of(),1,Clock.fixed(f.clock.instant(),ZoneOffset.UTC),f.configuration.actionIds(),f.configuration.deliveryActor(),1);
        required(()->new PreparedTypedVirtualApplicationFactory(otherClock,f.ports,f.providers,lease,f.typed));
        var otherPorts=new PreparedSecurityBindings((a,o,w,c)->true,f.ports.remediationVerifier(),f.security.actors(),f.security.actors(),f.ports.readiness(),f.ports.dependenciesAvailable());
        required(()->new PreparedTypedVirtualApplicationFactory(f.configuration,otherPorts,f.providers,lease,f.typed));
        assertEquals(PreparedResourceLease.State.AVAILABLE,lease.state());assertEquals(0,f.executor.shutdowns);
        lease.close();assertEquals(1,f.executor.shutdowns);assertEquals(1,f.executor.awaits);assertEquals(0,f.executor.executions);
    }
    @Test void actualPreparedCanonicalConstructorRechecksDifferentSecurityBundle(){
        var f=new Fixture();var prepared=f.factory(PreparedResourceLease.borrowed(f.executor)).prepare();
        var other=PreparedLocalVirtualSecurity.prepare(f.tokens,new LocalVirtualCurrentVerifier(f.tokens,f.principals),f.clock);
        var wrong=new PreparedTypedInputs(f.nativeTyped,f.typed.continuation(),f.typed.actions(),other,f.typed.currentCoordinates());
        required(()->new PreparedVirtualApplicationFactory.Prepared(prepared.settings(),prepared.inputs(),prepared.delivery(),prepared.authorization(),prepared.dependenciesAvailable(),prepared.ownership(),wrong));
        assertEquals(0,f.executor.executions);assertEquals(0,f.facts.calls);
    }
    @Test void oldSixArgumentPreparedKeepsLegacyGraphWithoutImplicitTypedActivation(){
        var f=new Fixture();var actual=f.factory(PreparedResourceLease.borrowed(f.executor)).prepare();
        var legacy=new PreparedVirtualApplicationFactory.Prepared(actual.settings(),actual.inputs(),actual.delivery(),actual.authorization(),actual.dependenciesAvailable(),actual.ownership());
        assertNull(legacy.typed());
        var app=new VirtualHttpApplication(legacy.settings().application(),legacy.inputs(),legacy.delivery(),legacy.authorization(),legacy.dependenciesAvailable());
        assertThrows(IllegalStateException.class,()->app.product().grantWorkflows());
        assertNotNull(app.product().deliveries());assertEquals(0,f.executor.executions);
    }
}
