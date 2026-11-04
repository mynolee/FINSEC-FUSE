package com.finsec.fuse.reimplementation.http;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

/** Explicit manual registration before MVC; synchronous HTTP requests only. No authority decisions. */
public final class BoundedRequestFilter implements Filter {
    private final RequestGuard guard;
    private final PublicHttpErrors errors;

    public BoundedRequestFilter(RequestGuard guard, PublicHttpErrors errors) {
        this.guard = Objects.requireNonNull(guard);
        this.errors = Objects.requireNonNull(errors);
    }

    @Override public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(response instanceof HttpServletResponse httpResponse)) {
            throw new ServletException("HTTP response required");
        }
        if (!(request instanceof HttpServletRequest httpRequest)) {
            errors.write(httpResponse, PublicHttpErrors.Error.INVALID_REQUEST);
            return;
        }
        try {
            chain.doFilter(guard.inspect(httpRequest), httpResponse);
        } catch (PublicHttpErrors.Rejected rejected) {
            errors.write(httpResponse, rejected.error());
        } catch (IOException | ServletException | RuntimeException unavailable) {
            errors.write(httpResponse, PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE);
        }
    }
}
