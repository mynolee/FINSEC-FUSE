package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/** Response metadata only. Never installs a container or changes operating configuration. */
public final class SimulationModeFilter implements Filter {
    @Override public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (response instanceof HttpServletResponse http)
            http.setHeader("X-Fuse-Execution-Mode", VirtualTransactionalStore.MODE);
        chain.doFilter(request, response);
    }
}
