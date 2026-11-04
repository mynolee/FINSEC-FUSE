package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualExperimentService;
import com.finsec.fuse.reimplementation.simulation.VirtualProductAssembly;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterRegistration;
import jakarta.servlet.Servlet;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import static com.finsec.fuse.reimplementation.application.VirtualHttpApplication.Access.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Synthetic source-only registration tests; no listener, runtime or test was executed during authoring. */
final class VirtualHttpApplicationTest {
    private final HttpLimits limits = new HttpLimits(4096, 8192, 16);
    private VirtualHttpApplication.Config config() {
        return new VirtualHttpApplication.Config("127.0.0.1", 8080, "/internal/v1/ready", limits, 10000, 8);
    }
    private VirtualProductAssembly.Inputs inputs(VirtualTransactionalStore store) {
        return new VirtualProductAssembly.Inputs(store, new SimulationSpec.Catalog(List.of(), List.of()),
                new SimulationSpec.RiskTerms("SYNTHETIC-POLICY", 1, 2, 3, 10, 2, 1, Duration.ofMinutes(1)),
                (actor, operation, workflow, customer) -> false, (actor, target, remediation) -> false,
                List.of(), new VirtualExperimentService.PairEvaluator() {
                    public String mode() { return VirtualTransactionalStore.MODE; }
                    public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                            String caseId, int repeat, Map<String, Object> shared) {
                        throw new AssertionError("No evaluator invocation during composition");
                    }
                }, Clock.systemUTC(), () -> { throw new AssertionError("No automatic IDs or seed"); },
                (request, operation, workflow, customer) -> null, (request, operation, workflow) -> null, limits);
    }
    @Test void constructionDoesNotInvokeReadinessOrMutateVirtualStore() {
        var calls = new AtomicInteger(); var store = new VirtualTransactionalStore();
        var app = new VirtualHttpApplication(config(), inputs(store), request -> { calls.incrementAndGet(); return ALLOW; },
                () -> { calls.incrementAndGet(); return true; });
        assertEquals(0, calls.get()); assertTrue(store.snapshot().isEmpty()); assertEquals(config(), app.config());
    }
    @Test void explicitLocalConfigAndMatchingLimitsAreRequired() {
        assertThrows(IllegalArgumentException.class, () -> new VirtualHttpApplication.Config("0.0.0.0", 8080,
                "/internal/v1/ready", limits, 10000, 8));
        assertThrows(IllegalArgumentException.class, () -> new VirtualHttpApplication.Config("127.0.0.1", 8080,
                "/api/*", limits, 10000, 8));
        assertThrows(NullPointerException.class, () -> VirtualHttpApplication.readinessServlet(null, () -> true));
    }
    @Test void readinessAuthenticatesBeforeAvailabilityAndDiscardsFailureText() throws Exception {
        var calls = new AtomicInteger();
        var servlet = VirtualHttpApplication.readinessServlet(request -> UNAUTHENTICATED,
                () -> { calls.incrementAndGet(); return true; });
        var response = new MockHttpServletResponse();
        servlet.service(new MockHttpServletRequest("GET", "/internal/v1/ready"), response);
        assertEquals(401, response.getStatus()); assertEquals(0, calls.get());
        assertEquals("no-store", response.getHeader("Cache-Control"));
        servlet = VirtualHttpApplication.readinessServlet(request -> { throw new IllegalStateException("synthetic-private-detail"); }, () -> true);
        response = new MockHttpServletResponse();
        servlet.service(new MockHttpServletRequest("GET", "/internal/v1/ready"), response);
        assertEquals(503, response.getStatus()); assertFalse(response.getContentAsString().contains("synthetic-private-detail"));
    }
    @Test void readinessDescribesOnlyVirtualAvailabilityAndRejectsQueryOrUnavailable() throws Exception {
        var servlet = VirtualHttpApplication.readinessServlet(request -> ALLOW, () -> true);
        var response = new MockHttpServletResponse();
        servlet.service(new MockHttpServletRequest("GET", "/internal/v1/ready"), response);
        assertEquals(200, response.getStatus()); assertTrue(response.getContentAsString().contains("\"productionReady\":false"));
        var query = new MockHttpServletRequest("GET", "/internal/v1/ready"); query.setQueryString("diagnostics=true");
        response = new MockHttpServletResponse(); servlet.service(query, response); assertEquals(400, response.getStatus());
        servlet = VirtualHttpApplication.readinessServlet(request -> ALLOW, () -> false);
        response = new MockHttpServletResponse();
        servlet.service(new MockHttpServletRequest("GET", "/internal/v1/ready"), response); assertEquals(503, response.getStatus());
    }
    @Test void registrationChecksContainerContractBeforeAnyServletAndIsSingleAttempt() {
        var app = new VirtualHttpApplication(config(), inputs(new VirtualTransactionalStore()), request -> FORBIDDEN, () -> false);
        var container = mock(ServletContext.class);
        assertThrows(IllegalStateException.class, () -> app.register(container, required -> { throw new IllegalStateException("not configured"); }));
        verifyNoInteractions(container);
        assertThrows(IllegalStateException.class, () -> app.register(container, required -> {}));
    }
    @Test void registrationUsesOnlyExplicitDispatcherReadinessAndOrderedFilters() {
        var app = new VirtualHttpApplication(config(), inputs(new VirtualTransactionalStore()), request -> FORBIDDEN, () -> false);
        var container = mock(ServletContext.class);
        when(container.getServletRegistrations()).thenReturn(Map.of());
        when(container.getFilterRegistrations()).thenReturn(Map.of());
        var servlet = mock(ServletRegistration.Dynamic.class);
        when(container.addServlet(anyString(), any(Servlet.class))).thenReturn(servlet);
        when(servlet.addMapping(any(String[].class))).thenReturn(Set.of());
        var filter = mock(FilterRegistration.Dynamic.class);
        when(container.addFilter(anyString(), any(Filter.class))).thenReturn(filter);
        var verified = new AtomicInteger(); app.register(container, required -> { assertEquals(config(), required); verified.incrementAndGet(); });
        assertEquals(1, verified.get()); verify(container, times(2)).addServlet(anyString(), any(Servlet.class));
        var ordered = inOrder(container);
        ordered.verify(container).addFilter(eq("fuseVirtualFilter0"), same(app.product().http().modeFilter()));
        ordered.verify(container).addFilter(eq("fuseVirtualFilter1"), same(app.product().http().requestFilter()));
        verify(filter, times(2)).setAsyncSupported(false);
    }
}
