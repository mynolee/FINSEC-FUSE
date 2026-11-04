package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.http.PublicHttpAdvice;
import com.finsec.fuse.reimplementation.http.PublicHttpErrors;
import com.finsec.fuse.reimplementation.simulation.SimulationApiController;
import com.finsec.fuse.reimplementation.simulation.VirtualProductAssembly;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.Objects;
import java.util.function.BooleanSupplier;
import org.springframework.context.annotation.AnnotatedBeanDefinitionReader;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/** Explicit virtual MVC registration only. Neither construction nor registration opens a listener. */
public final class VirtualHttpApplication {
    public record Config(String bindAddress, int port, String readinessPath, HttpLimits httpLimits,
                         int requestReadTimeoutMillis, int maxConcurrentRequests) {
        public Config {
            if (!"127.0.0.1".equals(bindAddress) || port < 1024 || port > 65535
                    || readinessPath == null || !readinessPath.matches("/internal/[A-Za-z0-9/_-]+")
                    || readinessPath.endsWith("/") || readinessPath.contains("//")
                    || requestReadTimeoutMillis <= 0 || maxConcurrentRequests <= 0)
                throw new IllegalArgumentException("Explicit local virtual transport configuration is required");
            Objects.requireNonNull(httpLimits);
        }
    }
    public enum Access { ALLOW, UNAUTHENTICATED, FORBIDDEN }
    @FunctionalInterface public interface ReadinessAuthorization {
        Access authorize(HttpServletRequest request);
    }
    @FunctionalInterface public interface ContainerBinding {
        /** Must verify actual listener address/port, transport bounds and request admission; never start it here. */
        void verify(Config required);
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    public static class ExplicitMvc {}

    private final Config config;
    private final VirtualProductAssembly product;
    private final HttpServlet readiness;
    private boolean registrationAttempted;

    public VirtualHttpApplication(Config config, VirtualProductAssembly.Inputs inputs,
                                  ReadinessAuthorization authorization, BooleanSupplier dependenciesAvailable) {
        this(config, inputs, null, authorization, dependenciesAvailable, false);
    }
    public VirtualHttpApplication(Config config, VirtualProductAssembly.Inputs inputs,
            VirtualProductAssembly.DeliveryInputs delivery, ReadinessAuthorization authorization,
            BooleanSupplier dependenciesAvailable) {
        this(config, inputs, Objects.requireNonNull(delivery), authorization, dependenciesAvailable, true);
    }
    private VirtualHttpApplication(Config config, VirtualProductAssembly.Inputs inputs,
            VirtualProductAssembly.DeliveryInputs delivery, ReadinessAuthorization authorization,
            BooleanSupplier dependenciesAvailable, boolean deliveryEnabled) {
        this.config = Objects.requireNonNull(config);
        Objects.requireNonNull(inputs);
        if (!config.httpLimits().equals(inputs.httpLimits()))
            throw new IllegalArgumentException("HTTP limits must match the explicit graph");
        readiness = readinessServlet(authorization, dependenciesAvailable);
        product = !deliveryEnabled ? VirtualProductAssembly.compose(inputs)
                : VirtualProductAssembly.composeWithDelivery(inputs, delivery);
    }

    public Config config() { return config; }
    public VirtualProductAssembly product() { return product; }

    /** Caller owns an unstarted servlet container. On failure discard that context; no retry or widening. */
    public synchronized void register(ServletContext container, ContainerBinding binding) {
        Objects.requireNonNull(container); Objects.requireNonNull(binding);
        if (registrationAttempted) throw new IllegalStateException("Registration has already been attempted");
        registrationAttempted = true;
        binding.verify(config);
        if (!container.getServletRegistrations().isEmpty() || !container.getFilterRegistrations().isEmpty())
            throw new IllegalArgumentException("A dedicated empty servlet context is required");
        var context = new GenericWebApplicationContext();
        context.setServletContext(container);
        new AnnotatedBeanDefinitionReader(context).register(ExplicitMvc.class);
        var bundle = product.http();
        context.registerBean("workflowController", WorkflowHttpController.class, bundle::workflowController);
        context.registerBean("simulationController", SimulationApiController.class, bundle::apiController);
        context.registerBean("publicHttpAdvice", PublicHttpAdvice.class, bundle::publicErrors);
        var ready = Objects.requireNonNull(container.addServlet("fuseVirtualReadiness", readiness));
        if (!ready.addMapping(config.readinessPath()).isEmpty())
            throw new IllegalStateException("Readiness registration conflict");
        var dispatcher = Objects.requireNonNull(container.addServlet("fuseVirtualMvc", new DispatcherServlet(context)));
        if (!dispatcher.addMapping("/").isEmpty()) throw new IllegalStateException("MVC registration conflict");
        dispatcher.setLoadOnStartup(1);
        var filters = bundle.orderedFilters();
        for (int index = 0; index < filters.length; index++) {
            var filter = Objects.requireNonNull(container.addFilter("fuseVirtualFilter" + index, filters[index]));
            filter.setAsyncSupported(false);
            filter.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), true, "/*");
        }
    }

    /** Independent servlet for explicit registration and synthetic boundary checks. No default authority. */
    public static HttpServlet readinessServlet(ReadinessAuthorization authorization, BooleanSupplier available) {
        Objects.requireNonNull(authorization); Objects.requireNonNull(available);
        return new HttpServlet() {
            @Override protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
                response.setHeader("Cache-Control", "no-store");
                response.setHeader("X-Content-Type-Options", "nosniff");
                response.setHeader("X-Fuse-Execution-Mode", "VIRTUAL_SIMULATION");
                var errors = new PublicHttpErrors();
                try {
                    Access access = authorization.authorize(request);
                    if (access != Access.ALLOW) {
                        errors.write(response, access == Access.FORBIDDEN ? PublicHttpErrors.Error.FORBIDDEN
                                : PublicHttpErrors.Error.UNAUTHENTICATED);
                    } else if (!"GET".equals(request.getMethod())) {
                        response.setHeader("Allow", "GET");
                        errors.write(response, PublicHttpErrors.Error.METHOD_NOT_ALLOWED);
                    } else if (request.getQueryString() != null || request.getContentLengthLong() > 0
                            || request.getHeader("Transfer-Encoding") != null) {
                        errors.write(response, PublicHttpErrors.Error.INVALID_REQUEST);
                    } else if (!available.getAsBoolean()) {
                        errors.write(response, PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE);
                    } else {
                        byte[] body = ("{\"ready\":true,\"executionMode\":\"VIRTUAL_SIMULATION\","
                                + "\"productionReady\":false}").getBytes(StandardCharsets.UTF_8);
                        response.setStatus(200); response.setContentType("application/json");
                        response.setCharacterEncoding("UTF-8"); response.setContentLength(body.length);
                        response.getOutputStream().write(body);
                    }
                } catch (RuntimeException unavailable) {
                    errors.write(response, PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE);
                }
            }
        };
    }
}
