package com.finsec.fuse;

import com.finsec.fuse.reimplementation.application.ConfiguredVirtualApplicationHost;
import com.finsec.fuse.reimplementation.application.PreparedVirtualApplicationFactory;
import com.finsec.fuse.reimplementation.application.VirtualLoopbackListener;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.function.Supplier;
import java.util.concurrent.atomic.AtomicBoolean;

/** Packaged virtual entry point. An explicit trusted classpath factory is required; construction grants no authority. */
public final class FuseApplication {
    private FuseApplication() { }
    private static final AtomicBoolean MAIN_ATTEMPTED = new AtomicBoolean();
    public enum Status { STARTED, CONFIGURATION_REQUIRED, HOOK_REGISTRATION_FAILED,
        STOPPED_BEFORE_START, STOPPED_DURING_START, START_FAILED, START_UNCONFIRMED }
    public enum HookStatus { NOT_ATTEMPTED, REGISTERED, UNCONFIRMED }
    public enum CleanupKnowledge { NO_FACTORY_ATTEMPT, UNCONFIRMED_WITHOUT_HANDLE, NOT_REQUESTED, STOP_REPORT_AVAILABLE }
    public record LaunchResult(Status status, boolean factoryInstantiationAttempted,
            boolean hostPreparationAttempted, boolean startAttempted, HookStatus hookStatus,
            ConfiguredVirtualApplicationHost.StopReport stopReport) {
        public boolean executionAuthorityGranted() { return false; }
        public boolean productionReady() { return false; }
        public CleanupKnowledge cleanupKnowledge() {
            if (stopReport != null) return CleanupKnowledge.STOP_REPORT_AVAILABLE;
            if (status == Status.STARTED) return CleanupKnowledge.NOT_REQUESTED;
            return factoryInstantiationAttempted ? CleanupKnowledge.UNCONFIRMED_WITHOUT_HANDLE : CleanupKnowledge.NO_FACTORY_ATTEMPT;
        }
    }
    @FunctionalInterface public interface FactoryResolver {
        /** Descriptor suppliers only; do not instantiate a factory while enumerating. */
        Iterable<? extends Supplier<PreparedVirtualApplicationFactory>> descriptors();
    }
    @FunctionalInterface public interface HookRegistrar { void register(Runnable ownedStop); }
    public interface Host {
        VirtualLoopbackListener.StartResult start();
        ConfiguredVirtualApplicationHost.StopReport stop();
    }
    @FunctionalInterface public interface HostFactory { Host prepare(PreparedVirtualApplicationFactory.Prepared prepared); }

    /** No supplied path, classname, environment fallback, fixture population or operating default is accepted. */
    public static void main(String[] args) {
        if (!MAIN_ATTEMPTED.compareAndSet(false, true)) throw new StartupFailure(Status.CONFIGURATION_REQUIRED);
        var result = launch(args, FuseApplication::classpathDescriptors,
                stop -> Runtime.getRuntime().addShutdownHook(new Thread(stop, "fuse-virtual-owned-stop")),
                FuseApplication::configuredHost);
        if (result.status() != Status.STARTED) throw new StartupFailure(result.status());
    }
    private static Iterable<? extends Supplier<PreparedVirtualApplicationFactory>> classpathDescriptors() {
        // Provider handles are collected before any Provider.get() is invoked. Defining loader, not request/TCCL input.
        return ServiceLoader.load(PreparedVirtualApplicationFactory.class,
                PreparedVirtualApplicationFactory.class.getClassLoader()).stream().limit(2)
                .map(provider -> (Supplier<PreparedVirtualApplicationFactory>) provider::get).toList();
    }
    private static Host configuredHost(PreparedVirtualApplicationFactory.Prepared prepared) {
        var host = ConfiguredVirtualApplicationHost.prepare(prepared.settings(), prepared.inputs(), prepared.delivery(),
                prepared.authorization(), prepared.dependenciesAvailable(), prepared.ownership());
        return new Host() {
            @Override public VirtualLoopbackListener.StartResult start() { return host.start(); }
            @Override public ConfiguredVirtualApplicationHost.StopReport stop() { return host.stop(); }
            @Override public String toString() { return "ConfiguredHostHandle[REDACTED]"; }
        };
    }

    /** Test seam: fake descriptor, hook and host implementations need not load services, register JVM hooks or start Tomcat. */
    public static LaunchResult launch(String[] args, FactoryResolver resolver, HookRegistrar hooks, HostFactory hostFactory) {
        boolean factoryAttempted = false, preparationAttempted = false;
        if (args == null || args.length != 0 || resolver == null || hooks == null || hostFactory == null)
            return result(Status.CONFIGURATION_REQUIRED, false, false, false, HookStatus.NOT_ATTEMPTED, null);
        Lifecycle lifecycle;
        try {
            var descriptors = Objects.requireNonNull(resolver.descriptors()).iterator();
            if (!descriptors.hasNext()) return result(Status.CONFIGURATION_REQUIRED, false, false, false, HookStatus.NOT_ATTEMPTED, null);
            var only = Objects.requireNonNull(descriptors.next());
            if (descriptors.hasNext()) return result(Status.CONFIGURATION_REQUIRED, false, false, false, HookStatus.NOT_ATTEMPTED, null);
            factoryAttempted = true;
            var factory = Objects.requireNonNull(only.get());
            var prepared = Objects.requireNonNull(factory.prepare());
            preparationAttempted = true;
            var host = Objects.requireNonNull(hostFactory.prepare(prepared));
            lifecycle = new Lifecycle(host, prepared.ownership() instanceof ConfiguredVirtualApplicationHost.BorrowedDelivery);
        } catch (Throwable unavailable) {
            restoreInterrupt(unavailable);
            return result(Status.CONFIGURATION_REQUIRED, factoryAttempted, preparationAttempted, false, HookStatus.NOT_ATTEMPTED, null);
        }
        try { hooks.register(lifecycle::stop); }
        catch (Throwable unavailable) {
            restoreInterrupt(unavailable);
            return result(Status.HOOK_REGISTRATION_FAILED, factoryAttempted, preparationAttempted, false,
                    HookStatus.UNCONFIRMED, lifecycle.stop());
        }
        try {
            var started = lifecycle.start();
            if (!lifecycle.startAttempted())
                return result(Status.STOPPED_BEFORE_START, factoryAttempted, preparationAttempted, false, HookStatus.REGISTERED, lifecycle.stop());
            if (lifecycle.stopAttempted())
                return result(Status.STOPPED_DURING_START, factoryAttempted, preparationAttempted, true, HookStatus.REGISTERED, lifecycle.stop());
            if (started == VirtualLoopbackListener.StartResult.STARTED)
                return result(Status.STARTED, factoryAttempted, preparationAttempted, true, HookStatus.REGISTERED, null);
            var status = started == VirtualLoopbackListener.StartResult.START_FAILED_CLEANUP_ACKNOWLEDGED
                    ? Status.START_FAILED : Status.START_UNCONFIRMED;
            return result(status, factoryAttempted, preparationAttempted, true, HookStatus.REGISTERED, lifecycle.stop());
        } catch (Throwable unavailable) {
            restoreInterrupt(unavailable);
            return result(Status.START_UNCONFIRMED, factoryAttempted, preparationAttempted, lifecycle.startAttempted(),
                    HookStatus.REGISTERED, lifecycle.stop());
        }
    }
    private static LaunchResult result(Status status, boolean factory, boolean prepared, boolean started,
            HookStatus hook, ConfiguredVirtualApplicationHost.StopReport stopped) {
        return new LaunchResult(status, factory, prepared, started, hook, stopped);
    }
    private static final class Lifecycle {
        private final Host host;
        private final boolean externalDelivery;
        private boolean startAttempted, stopAttempted;
        private ConfiguredVirtualApplicationHost.StopReport stopped;
        private Lifecycle(Host host, boolean externalDelivery) { this.host = host; this.externalDelivery = externalDelivery; }
        private synchronized VirtualLoopbackListener.StartResult start() {
            if (stopAttempted) return null;
            if (startAttempted) throw new IllegalStateException("START_ALREADY_ATTEMPTED");
            startAttempted = true; return host.start();
        }
        private synchronized boolean startAttempted() { return startAttempted; }
        private synchronized boolean stopAttempted() { return stopAttempted; }
        private synchronized ConfiguredVirtualApplicationHost.StopReport stop() {
            if (stopAttempted) return stopped;
            stopAttempted = true;
            try { stopped = Objects.requireNonNull(host.stop()); }
            catch (Throwable unavailable) {
                restoreInterrupt(unavailable);
                stopped = new ConfiguredVirtualApplicationHost.StopReport(ConfiguredVirtualApplicationHost.StopStatus.UNCONFIRMED,
                        false, false, externalDelivery);
            }
            return stopped;
        }
    }
    private static void restoreInterrupt(Throwable failure) {
        if (failure instanceof InterruptedException) Thread.currentThread().interrupt();
    }
    /** Fixed cause-free and stack-free process failure; no factory exception or prepared data is printed. */
    private static final class StartupFailure extends RuntimeException {
        private StartupFailure(Status status) { super(status.name(), null, false, false); }
    }
}
