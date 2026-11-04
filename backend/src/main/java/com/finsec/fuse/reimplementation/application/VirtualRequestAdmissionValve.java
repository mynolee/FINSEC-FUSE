package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.http.PublicHttpErrors;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import java.util.function.BooleanSupplier;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;

/** Dispatch admission after connector/executor intake, not a global no-queue guarantee. */
public final class VirtualRequestAdmissionValve extends ValveBase {
    private final Semaphore permits;
    private final BooleanSupplier bindingVerified;

    public VirtualRequestAdmissionValve(int maximum, BooleanSupplier bindingVerified) {
        super(false);
        if (maximum <= 0) throw new IllegalArgumentException("INVALID_VIRTUAL_LISTENER_INPUT");
        this.permits = new Semaphore(maximum);
        this.bindingVerified = Objects.requireNonNull(bindingVerified);
    }

    @Override public void invoke(Request request, Response response) throws IOException, ServletException {
        if (!ready()) { reject(response); return; }
        if (!permits.tryAcquire()) { reject(response); return; }
        try {
            // A concurrent stop may close the gate after permit acquisition.
            if (!ready()) { reject(response); return; }
            getNext().invoke(request, response);
        } finally {
            permits.release();
        }
    }

    private boolean ready() {
        try { return bindingVerified.getAsBoolean(); }
        catch (RuntimeException unavailable) { return false; }
    }

    private static void reject(Response response) throws IOException {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Fuse-Execution-Mode", "VIRTUAL_SIMULATION");
        new PublicHttpErrors().write(response.getResponse(), PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE);
    }
}
