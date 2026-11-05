package com.finsec.fuse.reimplementation.http;

import com.finsec.fuse.reimplementation.auth.LocalVirtualAdmissionContext;
import com.finsec.fuse.reimplementation.auth.LocalVirtualTokenRegistry;
import com.finsec.fuse.reimplementation.simulation.SimulationFailure;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.time.Clock;
import java.util.Objects;

/** Explicit synchronous request registration only; no default registry, role or automatic activation. */
public final class LocalVirtualAuthenticationFilter implements Filter {
    private final LocalVirtualTokenRegistry registry;
    private final LocalVirtualAdmissionContext context;
    private final Clock clock;
    private final PublicHttpErrors errors;
    public LocalVirtualAuthenticationFilter(LocalVirtualTokenRegistry registry,LocalVirtualAdmissionContext context,
            Clock clock,PublicHttpErrors errors) {
        this.registry=Objects.requireNonNull(registry);this.context=Objects.requireNonNull(context);
        this.clock=Objects.requireNonNull(clock);this.errors=Objects.requireNonNull(errors);
    }
    @Override public void doFilter(ServletRequest request,ServletResponse response,FilterChain chain)
            throws IOException,ServletException {
        if(!(response instanceof HttpServletResponse out))throw new ServletException("HTTP response required");
        if(!(request instanceof HttpServletRequest in)||in.getDispatcherType()!=DispatcherType.REQUEST||in.isAsyncStarted()) {
            errors.write(out,PublicHttpErrors.Error.INVALID_REQUEST);return;
        }
        try {
            var now=clock.instant();
            var evidence=registry.admitCanonical(LocalVirtualBearerHeader.canonical(in),now);
            if(evidence==null)throw SimulationFailure.unauthenticated();
            try(var admission=context.openRequest(evidence,now)) {
                chain.doFilter(new BoundRequest(in,context,admission),out);
            }
        } catch(LocalVirtualAdmissionContext.Failure failure) {
            errors.write(out,switch(failure.code()) {
                case UNAUTHENTICATED -> PublicHttpErrors.Error.UNAUTHENTICATED;
                case FORBIDDEN -> PublicHttpErrors.Error.FORBIDDEN;
                case UNAVAILABLE -> PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE;
            });
        } catch(SimulationFailure fixed) {errors.write(out,PublicHttpErrors.forStatus(fixed.status()));}
        catch(PublicHttpErrors.Rejected rejected) {errors.write(out,rejected.error());}
        catch(IOException|ServletException|RuntimeException unavailable) {errors.write(out,PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE);}
    }
    static LocalVirtualAdmissionContext.Admission admission(HttpServletRequest request,LocalVirtualAdmissionContext expected) {
        if(!(request instanceof BoundRequest bound)||bound.context!=expected||expected.current()!=bound.admission)
            throw SimulationFailure.unauthenticated();
        return bound.admission;
    }
    private static final class BoundRequest extends HttpServletRequestWrapper {
        private final LocalVirtualAdmissionContext context;
        private final LocalVirtualAdmissionContext.Admission admission;
        private BoundRequest(HttpServletRequest request,LocalVirtualAdmissionContext context,LocalVirtualAdmissionContext.Admission admission) {
            super(request);this.context=context;this.admission=admission;
        }
        @Override public boolean isAsyncSupported(){return false;}
        @Override public AsyncContext startAsync(){throw new IllegalStateException("ASYNCHRONOUS_REQUEST_UNSUPPORTED");}
        @Override public AsyncContext startAsync(ServletRequest request,ServletResponse response){throw new IllegalStateException("ASYNCHRONOUS_REQUEST_UNSUPPORTED");}
    }
}
