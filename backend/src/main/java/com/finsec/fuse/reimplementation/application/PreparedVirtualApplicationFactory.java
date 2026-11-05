package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.simulation.VirtualProductAssembly;
import java.util.Objects;
import java.util.function.BooleanSupplier;

/** Trusted packaged-server SPI for already prepared inputs; never a request-supplied provider or authority. */
public interface PreparedVirtualApplicationFactory {
    /** Implementations return explicit prepared data/resources; no default roles, settings, I/O or remote acquisition. */
    Prepared prepare();

    record Prepared(VirtualLoopbackListener.Settings settings, VirtualProductAssembly.Inputs inputs,
            VirtualProductAssembly.DeliveryInputs delivery, VirtualHttpApplication.ReadinessAuthorization authorization,
            BooleanSupplier dependenciesAvailable, ConfiguredVirtualApplicationHost.DeliveryOwnership ownership) {
        public Prepared {
            Objects.requireNonNull(settings); Objects.requireNonNull(inputs); Objects.requireNonNull(delivery);
            Objects.requireNonNull(authorization); Objects.requireNonNull(dependenciesAvailable); Objects.requireNonNull(ownership);
        }
        @Override public String toString() { return "PreparedVirtualApplication[REDACTED]"; }
    }
}
