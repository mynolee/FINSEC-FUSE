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

import jakarta.servlet.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

/** Local synthetic registration only: no servlet init, context refresh or listener start. */
final class PreparedTypedServletRegistrationTest {
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

    private static final class Recording {
        final ServletContext container=mock(ServletContext.class);
        final Map<String,Servlet> servlets=new LinkedHashMap<>();
        final Map<String,ServletRegistration.Dynamic> servletRegistrations=new LinkedHashMap<>();
        final Map<String,FilterRegistration.Dynamic> filterRegistrations=new LinkedHashMap<>();
        Recording(){
            when(container.getServletRegistrations()).thenReturn(Map.of());
            when(container.getFilterRegistrations()).thenReturn(Map.of());
            when(container.addServlet(anyString(),any(Servlet.class))).thenAnswer(call->{
                String name=call.getArgument(0);Servlet servlet=call.getArgument(1);
                assertNull(servlets.put(name,servlet));
                var registration=mock(ServletRegistration.Dynamic.class);
                when(registration.addMapping(any(String[].class))).thenReturn(Set.of());
                servletRegistrations.put(name,registration);return registration;
            });
            when(container.addFilter(anyString(),any(Filter.class))).thenAnswer(call->{
                String name=call.getArgument(0);var registration=mock(FilterRegistration.Dynamic.class);
                assertNull(filterRegistrations.put(name,registration));return registration;
            });
        }
    }
    private static VirtualHttpApplication application(Fixture f){
        var p=f.factory(PreparedResourceLease.borrowed(f.executor)).prepare();
        return new VirtualHttpApplication(p.settings().application(),p.inputs(),p.delivery(),p.authorization(),p.dependenciesAvailable(),p.typed());
    }
    @Test void actualRegisterSuppliesTypedControllerAndPreservesFilterAndReadinessMappings(){
        var f=new Fixture();var app=application(f);var recording=new Recording();var verified=new AtomicInteger();
        app.register(recording.container,config->{assertSame(app.config(),config);verified.incrementAndGet();});
        assertEquals(1,verified.get());assertEquals(Set.of("fuseVirtualReadiness","fuseVirtualMvc"),recording.servlets.keySet());
        var dispatcher=assertInstanceOf(DispatcherServlet.class,recording.servlets.get("fuseVirtualMvc"));
        var context=assertInstanceOf(GenericWebApplicationContext.class,dispatcher.getWebApplicationContext());
        assertTrue(context.containsBeanDefinition("typedWorkflowMutationController"));
        assertInstanceOf(TypedWorkflowMutationController.class,context.getBeanFactory().getBean("typedWorkflowMutationController"));
        assertFalse(context.isActive()); // The bean supplier is exercised, not an initialized MVC/container runtime.
        verify(recording.servletRegistrations.get("fuseVirtualReadiness")).addMapping("/internal/v1/ready");
        verify(recording.servletRegistrations.get("fuseVirtualMvc")).addMapping("/");
        verify(recording.servletRegistrations.get("fuseVirtualMvc")).setLoadOnStartup(1);
        var order=inOrder(recording.container);
        order.verify(recording.container).addFilter(eq("fuseVirtualFilter0"),same(app.orderedFilters()[0]));
        order.verify(recording.container).addFilter(eq("fuseVirtualFilter1"),same(app.orderedFilters()[1]));
        order.verify(recording.container).addFilter(eq("fuseVirtualFilter2"),same(f.security.authenticationFilter()));
        for(int i=0;i<3;i++)verify(recording.filterRegistrations.get("fuseVirtualFilter"+i)).setAsyncSupported(false);
        for(int i=0;i<2;i++)verify(recording.filterRegistrations.get("fuseVirtualFilter"+i)).addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST),true,"/*");
        verify(recording.filterRegistrations.get("fuseVirtualFilter2")).addMappingForServletNames(EnumSet.of(DispatcherType.REQUEST),true,"fuseVirtualMvc");
        verify(recording.filterRegistrations.get("fuseVirtualFilter2"),never()).addMappingForUrlPatterns(any(),anyBoolean(),any(String[].class));
        assertEquals(0,f.facts.calls);assertEquals(0,f.executor.executions);
        assertTrue(app.product().store().snapshot().values().stream().allMatch(Map::isEmpty));
    }
    @Test void readinessRemainsSeparatelyAuthorizedWithoutInvokingTypedFacts() throws Exception {
        var f=new Fixture();var p=f.factory(PreparedResourceLease.borrowed(f.executor)).prepare();
        var app=new VirtualHttpApplication(p.settings().application(),p.inputs(),p.delivery(),request->VirtualHttpApplication.Access.FORBIDDEN,
                ()->{throw new AssertionError("Forbidden readiness must not check dependencies");},p.typed());
        var recording=new Recording();app.register(recording.container,config->{});
        var request=new MockHttpServletRequest("GET","/internal/v1/ready");var response=new MockHttpServletResponse();
        recording.servlets.get("fuseVirtualReadiness").service(request,response);
        assertEquals(403,response.getStatus());assertEquals(0,f.facts.calls);assertEquals(0,f.executor.executions);
    }
    @Test void bindingFailurePrecedesContainerMutationAndRegistrationCannotBeRetried(){
        var f=new Fixture();var app=application(f);var container=mock(ServletContext.class);
        var failure=new IllegalStateException("synthetic-binding-unavailable");
        assertSame(failure,assertThrows(IllegalStateException.class,()->app.register(container,config->{throw failure;})));
        verifyNoInteractions(container);
        assertThrows(IllegalStateException.class,()->app.register(container,config->fail("No retry binding")));
        verifyNoInteractions(container);assertEquals(0,f.facts.calls);assertEquals(0,f.executor.executions);
    }
}
