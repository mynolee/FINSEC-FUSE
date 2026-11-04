package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.SimulationFailure;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualExperimentService;
import com.finsec.fuse.reimplementation.simulation.VirtualProductAssembly;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterRegistration;
import jakarta.servlet.Servlet;
import jakarta.servlet.ServletRegistration;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Source-only synthetic MVC initialization tests. No listener, model or database is opened. */
final class VirtualHttpApplicationMvcTest {
    private static final String READY = "/internal/v1/ready";
    private static final HttpLimits LIMITS = new HttpLimits(4096, 8192, 16);

    private VirtualProductAssembly.Inputs inputs(VirtualTransactionalStore store, AtomicInteger actors) {
        return new VirtualProductAssembly.Inputs(store, new SimulationSpec.Catalog(List.of(), List.of()),
                new SimulationSpec.RiskTerms("SYNTHETIC-MVC", 1, 2, 3, 10, 2, 1, Duration.ofMinutes(1)),
                (actor, operation, workflow, customer) -> false,
                (actor, target, remediation) -> false, List.of(),
                new VirtualExperimentService.PairEvaluator() {
                    public String mode() { return VirtualTransactionalStore.MODE; }
                    public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                            String caseId, int repeat, Map<String, Object> shared) {
                        throw new AssertionError("No model or evaluator dispatch");
                    }
                }, Clock.systemUTC(), () -> { throw new AssertionError("No automatic identifiers"); },
                (request, operation, workflow, customer) -> null,
                (request, operation, workflow) -> {
                    actors.incrementAndGet();
                    if ("synthetic-forbidden".equals(request.getHeader("X-Synthetic-Test")))
                        throw SimulationFailure.forbidden();
                    if ("synthetic-unavailable".equals(request.getHeader("X-Synthetic-Test")))
                        throw new IllegalStateException("synthetic-private-detail");
                    throw SimulationFailure.unauthenticated();
                }, LIMITS);
    }

    private static final class Registered implements AutoCloseable {
        final MockServletContext context = spy(new MockServletContext());
        final Map<String, Servlet> routes = new LinkedHashMap<>();
        final List<Filter> filters = new ArrayList<>();
        final DispatcherServlet dispatcher;

        Registered(VirtualHttpApplication app) throws Exception {
            doReturn(Map.of()).when(context).getServletRegistrations();
            doReturn(Map.of()).when(context).getFilterRegistrations();
            doAnswer(invocation -> {
                Servlet servlet = invocation.getArgument(1);
                var registration = mock(ServletRegistration.Dynamic.class);
                when(registration.addMapping(any(String[].class))).thenAnswer(mapping -> {
                    String[] paths = (String[]) mapping.getRawArguments()[0];
                    for (String path : paths) assertNull(routes.putIfAbsent(path, servlet));
                    return Set.of();
                });
                return registration;
            }).when(context).addServlet(anyString(), any(Servlet.class));
            doAnswer(invocation -> {
                Filter filter = invocation.getArgument(1);
                var registration = mock(FilterRegistration.Dynamic.class);
                doAnswer(mapping -> {
                    assertEquals(EnumSet.of(DispatcherType.REQUEST), mapping.getArgument(0));
                    assertEquals(Boolean.TRUE, mapping.getArgument(1));
                    assertArrayEquals(new String[]{"/*"}, (String[]) mapping.getRawArguments()[2]);
                    filters.add(filter);
                    return null;
                }).when(registration).addMappingForUrlPatterns(any(), anyBoolean(), any(String[].class));
                return registration;
            }).when(context).addFilter(anyString(), any(Filter.class));
            app.register(context, required -> assertEquals(app.config(), required));
            assertEquals(Set.of("/", READY), routes.keySet());
            dispatcher = assertInstanceOf(DispatcherServlet.class, routes.get("/"));
            try {
                dispatcher.init(new MockServletConfig(context, "fuseVirtualMvc"));
                routes.get(READY).init(new MockServletConfig(context, "fuseVirtualReadiness"));
            } catch (Exception | Error failure) {
                dispatcher.destroy();
                throw failure;
            }
        }

        MockHttpServletResponse get(String path, String syntheticHeader) throws Exception {
            var request = new MockHttpServletRequest(context, "GET", path);
            request.setServletPath(path); request.addHeader("Accept", "application/json");
            if (syntheticHeader != null) request.addHeader("X-Synthetic-Test", syntheticHeader);
            var response = new MockHttpServletResponse();
            Servlet servlet = routes.getOrDefault(path, routes.get("/"));
            new MockFilterChain(servlet, filters.toArray(Filter[]::new)).doFilter(request, response);
            return response;
        }

        public void close() { routes.get(READY).destroy(); dispatcher.destroy(); }
    }

    @Test void initializedRegisteredMvcRoutesAuthenticationFailuresThroughActualControllersAndFilters() throws Exception {
        var store = new VirtualTransactionalStore(); var actors = new AtomicInteger();
        var app = new VirtualHttpApplication(new VirtualHttpApplication.Config("127.0.0.1", 8080, READY,
                LIMITS, 10000, 8), inputs(store, actors), request -> VirtualHttpApplication.Access.FORBIDDEN, () -> false);
        try (var registered = new Registered(app)) {
            var context = registered.dispatcher.getWebApplicationContext(); assertNotNull(context);
            var mappings = context.getBean(RequestMappingHandlerMapping.class).getHandlerMethods();
            assertTrue(mappings.values().stream().anyMatch(handler -> handler.getMethod().getName().equals("workflows")));
            assertSame(app.product().http().modeFilter(), registered.filters.get(0));
            assertSame(app.product().http().requestFilter(), registered.filters.get(1));
            for (var entry : Map.of("synthetic-unauthenticated", 401,
                    "synthetic-forbidden", 403, "synthetic-unavailable", 503).entrySet()) {
                var response = registered.get("/api/v1/workflows", entry.getKey());
                assertEquals(entry.getValue().intValue(), response.getStatus());
                assertEquals(VirtualTransactionalStore.MODE, response.getHeader("X-Fuse-Execution-Mode"));
                assertFalse(response.getContentAsString().contains("synthetic-private-detail"));
                assertFalse(response.getContentAsString().contains(entry.getKey()));
            }
            assertEquals(3, actors.get()); assertTrue(store.snapshot().isEmpty());
        }
    }

    @Test void registeredReadinessPathUsesItsDedicatedServletWithoutEnteringMvcAuthority() throws Exception {
        var store = new VirtualTransactionalStore(); var actors = new AtomicInteger(); var probes = new AtomicInteger();
        var app = new VirtualHttpApplication(new VirtualHttpApplication.Config("127.0.0.1", 8080, READY,
                LIMITS, 10000, 8), inputs(store, actors), request -> VirtualHttpApplication.Access.ALLOW,
                () -> { probes.incrementAndGet(); return true; });
        try (var registered = new Registered(app)) {
            var response = registered.get(READY, null);
            assertEquals(200, response.getStatus());
            assertEquals("{\"ready\":true,\"executionMode\":\"VIRTUAL_SIMULATION\",\"productionReady\":false}",
                    response.getContentAsString());
            assertEquals("no-store", response.getHeader("Cache-Control"));
            assertEquals(1, probes.get()); assertEquals(0, actors.get()); assertTrue(store.snapshot().isEmpty());
        }
    }
}
