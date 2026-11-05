package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.simulation.VirtualProductAssembly;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

/** Explicit configured listener and delivery-resource ownership; never an automatic bootstrap. */
public final class ConfiguredVirtualApplicationHost implements AutoCloseable {
    public sealed interface DeliveryOwnership permits BorrowedDelivery, OwnedExecutor { }
    public record BorrowedDelivery() implements DeliveryOwnership { }
    /** Ownership is transferred explicitly; no pool is allocated by this host. */
    public record OwnedExecutor(ExecutorService executor, long shutdownWaitMillis) implements DeliveryOwnership {
        public OwnedExecutor {
            Objects.requireNonNull(executor);
            if (shutdownWaitMillis < 1) throw invalid();
        }
        @Override public String toString() { return "OwnedDeliveryExecutor[REDACTED]"; }
    }
    public enum State { PREPARED, STARTING, RUNNING, START_FAILED, STOPPED_OWNED_RESOURCES,
        EXTERNAL_DELIVERY_UNCONFIRMED, RESIDUAL_UNCONFIRMED }
    public enum StopStatus { OWNED_RESOURCES_ACKNOWLEDGED, EXTERNAL_DELIVERY_UNCONFIRMED, UNCONFIRMED }
    /** Provider resources have no close contract and are never claimed closed. */
    public record StopReport(StopStatus status, boolean listenerAcknowledged,
            boolean ownedExecutorTerminated, boolean deliveryExternallyOwned) {
        public boolean providerResourcesClosed() { return false; }
        public boolean executionAuthorityGranted() { return false; }
    }
    private final VirtualLoopbackListener listener;
    private final DeliveryOwnership ownership;
    private State state = State.PREPARED;
    private StopReport stopped;

    private ConfiguredVirtualApplicationHost(VirtualLoopbackListener listener, DeliveryOwnership ownership) {
        this.listener = listener; this.ownership = ownership;
    }
    /** Prepared references only: no environment lookup, filesystem preparation, start or executor submission. */
    public static ConfiguredVirtualApplicationHost prepare(VirtualLoopbackListener.Settings settings,
            VirtualProductAssembly.Inputs inputs, VirtualProductAssembly.DeliveryInputs delivery,
            VirtualHttpApplication.ReadinessAuthorization authorization, BooleanSupplier available,
            DeliveryOwnership ownership) {
        Objects.requireNonNull(settings); Objects.requireNonNull(inputs); Objects.requireNonNull(delivery);
        Objects.requireNonNull(authorization); Objects.requireNonNull(available); Objects.requireNonNull(ownership);
        if (!settings.application().httpLimits().equals(inputs.httpLimits())) throw invalid();
        if (ownership instanceof OwnedExecutor owned && owned.executor() != delivery.executor()) throw invalid();
        return new ConfiguredVirtualApplicationHost(
                VirtualLoopbackListener.prepare(settings, inputs, delivery, authorization, available), ownership);
    }
    public synchronized State state() { return state; }
    /** Borrowed diagnostic handle; callers must not independently drive its lifecycle. */
    public VirtualLoopbackListener listener() { return listener; }
    public DeliveryOwnership deliveryOwnership() { return ownership; }

    public synchronized VirtualLoopbackListener.StartResult start() {
        if (state != State.PREPARED) throw new IllegalStateException("CONFIGURED_HOST_START_ALREADY_ATTEMPTED");
        state = State.STARTING;
        try {
            var result = listener.start();
            state = result == VirtualLoopbackListener.StartResult.STARTED ? State.RUNNING
                    : result == VirtualLoopbackListener.StartResult.START_FAILED_CLEANUP_ACKNOWLEDGED
                        ? State.START_FAILED : State.RESIDUAL_UNCONFIRMED;
            return result;
        } catch (RuntimeException failure) {
            state = State.RESIDUAL_UNCONFIRMED;
            throw new IllegalStateException("CONFIGURED_HOST_START_UNCONFIRMED");
        }
    }

    /** One explicit stop attempt; uncertain tasks are not interrupted, reset or silently retried. */
    public synchronized StopReport stop() {
        if (stopped != null) return stopped;
        boolean listenerAck = false, terminated = false;
        try { listenerAck = listener.stop() == VirtualLoopbackListener.StopResult.STOP_ACKNOWLEDGED; }
        catch (RuntimeException uncertain) { listenerAck = false; }
        if (ownership instanceof OwnedExecutor owned) {
            try {
                owned.executor().shutdown();
                terminated = owned.executor().awaitTermination(owned.shutdownWaitMillis(), TimeUnit.MILLISECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException uncertain) { terminated = false; }
            var status = listenerAck && terminated ? StopStatus.OWNED_RESOURCES_ACKNOWLEDGED : StopStatus.UNCONFIRMED;
            stopped = new StopReport(status, listenerAck, terminated, false);
            state = status == StopStatus.OWNED_RESOURCES_ACKNOWLEDGED
                    ? State.STOPPED_OWNED_RESOURCES : State.RESIDUAL_UNCONFIRMED;
        } else {
            var status = listenerAck ? StopStatus.EXTERNAL_DELIVERY_UNCONFIRMED : StopStatus.UNCONFIRMED;
            stopped = new StopReport(status, listenerAck, false, true);
            state = listenerAck ? State.EXTERNAL_DELIVERY_UNCONFIRMED : State.RESIDUAL_UNCONFIRMED;
        }
        return stopped;
    }
    @Override public void close() { stop(); }
    @Override public String toString() { return "ConfiguredVirtualApplicationHost[REDACTED]"; }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_CONFIGURED_HOST_INPUTS"); }
}
