package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.simulation.VirtualProductAssembly;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.Objects;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.core.StandardHost;
import org.apache.catalina.core.StandardServer;
import org.apache.catalina.session.StandardManager;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.valves.ErrorReportValve;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.JarScanFilter;
import org.apache.tomcat.JarScanType;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.scan.StandardJarScanner;

/** Explicit synthetic host source, not a main/Bean, production authority or OS sandbox.
 * prepare creates no container, listener, worker or directory. start is explicit.
 * Internal library classloading/system-property/log/file access is not suppressed.
 * Only Exception paths have fixed results. Error is not swallowed/redacted or
 * guaranteed cleanup; its propagation does not prove no side effects or safe retry.
 */
public final class VirtualLoopbackListener implements AutoCloseable {
    public record Settings(VirtualHttpApplication.Config application, Path baseDirectory,
            Path docBase, Path workDirectory, long expectedOwnerUid, int maxConnections,
            int acceptBacklog, int maxKeepAliveRequests, int maxWorkerThreads,
            int minSpareThreads, int maxQueuedTasks, long workerIdleMillis,
            int utilityThreads, long workerShutdownWaitMillis) {
        public Settings {
            if (application == null || !path(baseDirectory) || !path(docBase) || !path(workDirectory)
                    || !baseDirectory.equals(docBase.getParent()) || !baseDirectory.equals(workDirectory.getParent())
                    || docBase.equals(workDirectory) || expectedOwnerUid < 0 || maxConnections <= 0
                    || acceptBacklog <= 0 || maxKeepAliveRequests != 1 || maxWorkerThreads <= 0
                    || minSpareThreads < 0 || minSpareThreads > maxWorkerThreads || maxQueuedTasks <= 0
                    || workerIdleMillis <= 0 || utilityThreads < 2 || workerShutdownWaitMillis <= 0
                    || application.httpLimits().maxHeaderBytes() > Integer.MAX_VALUE) throw invalid();
        }
        @Override public String toString() { return "VirtualListenerSettings[REDACTED]"; }
    }

    public enum State { PREPARED, STARTING, RUNNING, STOPPED, START_FAILED, RESIDUAL_UNCONFIRMED }
    public enum StartResult { STARTED, START_FAILED_CLEANUP_ACKNOWLEDGED, START_FAILED_RESIDUAL_UNCONFIRMED }
    public enum StopResult { STOP_ACKNOWLEDGED, STOP_UNCONFIRMED }

    interface Runtime {
        void configure(Settings settings, VirtualProductAssembly.Inputs inputs,
                VirtualHttpApplication.ReadinessAuthorization auth, BooleanSupplier available,
                AtomicBoolean verified, ThreadPoolExecutor workers) throws Exception;
        void start() throws Exception;
        void verifyRequiredServletInitialization() throws Exception;
        InetSocketAddress boundAddress() throws Exception;
        void stop() throws Exception;
        void destroy() throws Exception;
    }
    @FunctionalInterface interface RuntimeFactory { Runtime create(); }

    private final Settings settings;
    private final VirtualProductAssembly.Inputs inputs;
    private final VirtualHttpApplication.ReadinessAuthorization authorization;
    private final BooleanSupplier available;
    private final RuntimeFactory factory;
    private final AtomicBoolean verified = new AtomicBoolean();
    private Runtime runtime;
    private ThreadPoolExecutor workers;
    private State state = State.PREPARED;
    private boolean cleanupAttempted;
    private boolean cleanupAcknowledged;

    private VirtualLoopbackListener(Settings settings, VirtualProductAssembly.Inputs inputs,
            VirtualHttpApplication.ReadinessAuthorization authorization, BooleanSupplier available,
            RuntimeFactory factory) {
        if (settings == null || inputs == null || authorization == null || available == null || factory == null) throw invalid();
        this.settings = settings; this.inputs = inputs; this.authorization = authorization;
        this.available = available; this.factory = factory;
    }

    public static VirtualLoopbackListener prepare(Settings settings, VirtualProductAssembly.Inputs inputs,
            VirtualHttpApplication.ReadinessAuthorization authorization, BooleanSupplier available) {
        return new VirtualLoopbackListener(settings, inputs, authorization, available, TomcatRuntime::new);
    }
    /** Explicit configured delivery path; does not allocate or start the supplied executor. */
    public static VirtualLoopbackListener prepare(Settings settings, VirtualProductAssembly.Inputs inputs,
            VirtualProductAssembly.DeliveryInputs delivery,
            VirtualHttpApplication.ReadinessAuthorization authorization, BooleanSupplier available) {
        return prepare(settings,inputs,delivery,authorization,available,null);
    }
    public static VirtualLoopbackListener prepare(Settings settings,VirtualProductAssembly.Inputs inputs,
            VirtualProductAssembly.DeliveryInputs delivery,VirtualHttpApplication.ReadinessAuthorization authorization,
            BooleanSupplier available,PreparedTypedInputs typed){
        Objects.requireNonNull(delivery);
        if(typed!=null)typed.requireBindings(inputs);
        return new VirtualLoopbackListener(settings, inputs, authorization, available, () -> new TomcatRuntime(delivery,typed));
    }
    static VirtualLoopbackListener forSyntheticProtocol(Settings settings, VirtualProductAssembly.Inputs inputs,
            VirtualHttpApplication.ReadinessAuthorization authorization, BooleanSupplier available, RuntimeFactory factory) {
        return new VirtualLoopbackListener(settings, inputs, authorization, available, factory);
    }
    public synchronized State state() { return state; }

    public synchronized StartResult start() {
        if (state != State.PREPARED) throw new IllegalStateException("VIRTUAL_LISTENER_START_ALREADY_ATTEMPTED");
        state = State.STARTING;
        try {
            preflight(settings);
            workers = new ThreadPoolExecutor(settings.minSpareThreads(), settings.maxWorkerThreads(),
                    settings.workerIdleMillis(), TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<>(settings.maxQueuedTasks()), task -> {
                        Thread thread = new Thread(task, "fuse-virtual-http-worker");
                        thread.setDaemon(false); return thread;
                    }, new ThreadPoolExecutor.AbortPolicy());
            runtime = Objects.requireNonNull(factory.create());
            runtime.configure(settings, inputs, authorization, available, verified, workers);
            runtime.start();
            runtime.verifyRequiredServletInitialization();
            InetSocketAddress observed = runtime.boundAddress();
            if (observed == null || observed.isUnresolved() || observed.getAddress() == null
                    || !"127.0.0.1".equals(observed.getAddress().getHostAddress())
                    || observed.getPort() != settings.application().port()) throw new IOException();
            verified.set(true); state = State.RUNNING;
            return StartResult.STARTED;
        } catch (Exception failure) {
            verified.set(false);
            boolean cleaned = cleanup();
            state = cleaned ? State.START_FAILED : State.RESIDUAL_UNCONFIRMED;
            return cleaned ? StartResult.START_FAILED_CLEANUP_ACKNOWLEDGED : StartResult.START_FAILED_RESIDUAL_UNCONFIRMED;
        }
    }

    public synchronized StopResult stop() {
        verified.set(false);
        boolean cleaned = cleanup();
        state = cleaned ? State.STOPPED : State.RESIDUAL_UNCONFIRMED;
        return cleaned ? StopResult.STOP_ACKNOWLEDGED : StopResult.STOP_UNCONFIRMED;
    }

    private boolean cleanup() {
        if (cleanupAttempted) return cleanupAcknowledged;
        cleanupAttempted = true;
        boolean result = true;
        if (runtime != null) {
            try { runtime.stop(); } catch (Exception failure) { result = false; }
            try { runtime.destroy(); } catch (Exception failure) { result = false; }
        }
        if (workers != null) {
            try {
                workers.shutdown();
                if (!workers.awaitTermination(settings.workerShutdownWaitMillis(), TimeUnit.MILLISECONDS)) result = false;
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt(); result = false;
            } catch (RuntimeException failure) { result = false; }
        }
        cleanupAcknowledged = result;
        return result;
    }

    @Override public void close() { stop(); }

    private static boolean path(Path value) {
        return value != null && value.isAbsolute() && value.normalize().equals(value)
                && value.getFileSystem().equals(java.nio.file.FileSystems.getDefault());
    }

    private static void preflight(Settings settings) throws IOException {
        Set<PosixFilePermission> privateMode = Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
        for (Path directory : new Path[] {settings.baseDirectory(), settings.docBase(), settings.workDirectory()}) {
            for (Path ancestor = directory; ancestor != null; ancestor = ancestor.getParent()) {
                if (Files.isSymbolicLink(ancestor) || !Files.isDirectory(ancestor, LinkOption.NOFOLLOW_LINKS)) throw new IOException();
            }
            Object uid = Files.getAttribute(directory, "unix:uid", LinkOption.NOFOLLOW_LINKS);
            if (!(uid instanceof Number number) || number.longValue() != settings.expectedOwnerUid()
                    || !Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS).equals(privateMode)) throw new IOException();
        }
        try (var entries = Files.list(settings.baseDirectory())) {
            if (!entries.collect(java.util.stream.Collectors.toSet()).equals(Set.of(settings.docBase(), settings.workDirectory()))) throw new IOException();
        }
        for (Path empty : new Path[] {settings.docBase(), settings.workDirectory()}) {
            try (var entries = Files.list(empty)) { if (entries.findAny().isPresent()) throw new IOException(); }
        }
        // Point-in-time checks are not protection against a hostile same-UID path race.
    }

    /** Differently named method: inherited getLocalAddress is protected final. */
    private static final class OwnedNioEndpoint extends NioEndpoint {
        public InetSocketAddress observedBoundAddress() throws IOException { return super.getLocalAddress(); }
    }

    private static final class TomcatRuntime implements Runtime {
        private final VirtualProductAssembly.DeliveryInputs delivery;
        private TomcatRuntime() { this(null); }
        private final PreparedTypedInputs typed;
        private TomcatRuntime(VirtualProductAssembly.DeliveryInputs delivery) { this(delivery,null); }
        private TomcatRuntime(VirtualProductAssembly.DeliveryInputs delivery,PreparedTypedInputs typed) { this.delivery = delivery;this.typed=typed; }
        private Tomcat tomcat;
        private OwnedNioEndpoint endpoint;
        private Http11NioProtocol protocol;
        private Connector connector;
        private StandardContext context;

        @Override public void configure(Settings settings, VirtualProductAssembly.Inputs inputs,
                VirtualHttpApplication.ReadinessAuthorization auth, BooleanSupplier available,
                AtomicBoolean verified, ThreadPoolExecutor workers) throws Exception {
            tomcat = new Tomcat();
            tomcat.setBaseDir(settings.baseDirectory().toString());
            StandardServer server = (StandardServer) tomcat.getServer();
            server.setPort(-1); // Disable shutdown socket; await() is never invoked.
            server.setUtilityThreads(settings.utilityThreads()); server.setPeriodicEventDelay(0);
            if (server.getUtilityThreads() != settings.utilityThreads() || server.getPeriodicEventDelay() != 0) throw new IOException();
            StandardHost host = (StandardHost) tomcat.getHost();
            host.setAppBase(settings.baseDirectory().toString()); host.setAutoDeploy(false);
            host.setDeployOnStartup(false); host.setDeployXML(false); host.setCreateDirs(false);
            host.setErrorReportValveClass(null);
            ErrorReportValve reports = new ErrorReportValve();
            reports.setShowReport(false); reports.setShowServerInfo(false);
            host.getPipeline().addValve(reports);
            endpoint = new OwnedNioEndpoint(); protocol = new Http11NioProtocol(endpoint);
            protocol.setAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}));
            protocol.setExecutor(workers);
            protocol.setMaxConnections(settings.maxConnections()); protocol.setAcceptCount(settings.acceptBacklog());
            protocol.setConnectionTimeout(settings.application().requestReadTimeoutMillis());
            protocol.setKeepAliveTimeout(settings.application().requestReadTimeoutMillis());
            protocol.setMaxKeepAliveRequests(settings.maxKeepAliveRequests());
            protocol.setMaxHttpRequestHeaderSize((int) settings.application().httpLimits().maxHeaderBytes());
            protocol.setDisableUploadTimeout(false);
            protocol.setConnectionUploadTimeout(settings.application().requestReadTimeoutMillis());
            connector = new Connector(protocol); connector.setThrowOnFailure(true);
            connector.setPort(settings.application().port());
            if (!connector.setProperty("bindOnInit", "false")) throw new IOException();
            tomcat.setConnector(connector);
            context = (StandardContext) tomcat.addContext("", settings.docBase().toString());
            context.setFailCtxIfServletStartFails(Boolean.TRUE);
            if (!Boolean.TRUE.equals(context.getFailCtxIfServletStartFails())) throw new IOException();
            context.setWorkDir(settings.workDirectory().toString()); context.setAddWebinfClassesResources(false);
            context.setMetadataComplete(true); context.setIgnoreAnnotations(true);
            StandardJarScanner scanner = new StandardJarScanner();
            scanner.setJarScanFilter(new JarScanFilter() {
                @Override public boolean check(JarScanType type, String name) { return false; }
                @Override public boolean isSkipAll() { return true; }
            });
            context.setJarScanner(scanner);
            StandardManager manager = new StandardManager(); manager.setPathname(null); manager.setMaxActiveSessions(0);
            context.setManager(manager);
            context.getPipeline().addValve(new VirtualRequestAdmissionValve(settings.application().maxConcurrentRequests(), verified::get));
            VirtualHttpApplication application = delivery == null
                    ? new VirtualHttpApplication(settings.application(), inputs, auth, () -> verified.get() && available.getAsBoolean())
                    : new VirtualHttpApplication(settings.application(), inputs, delivery, auth, () -> verified.get() && available.getAsBoolean(),typed);
            context.addServletContainerInitializer((classes, servletContext) -> {
                servletContext.setSessionTrackingModes(Set.of());
                application.register(servletContext, required -> verifyConfigured(settings, required, workers));
            }, Set.of());
        }

        private void verifyConfigured(Settings settings, VirtualHttpApplication.Config required, ThreadPoolExecutor workers) {
            Object bindOnInit = connector.getProperty("bindOnInit");
            if (!required.equals(settings.application()) || connector.getProtocolHandler() != protocol
                    || tomcat.getService().findConnectors().length != 1
                    || tomcat.getService().findConnectors()[0] != connector
                    || connector.getPort() != required.port() || protocol.getExecutor() != workers
                    || !"127.0.0.1".equals(protocol.getAddress().getHostAddress())
                    || !(Boolean.FALSE.equals(bindOnInit) || "false".equals(bindOnInit))
                    || protocol.getMaxConnections() != settings.maxConnections() || protocol.getAcceptCount() != settings.acceptBacklog()
                    || protocol.getConnectionTimeout() != required.requestReadTimeoutMillis()
                    || protocol.getKeepAliveTimeout() != required.requestReadTimeoutMillis()
                    || protocol.getMaxKeepAliveRequests() != 1
                    || protocol.getMaxHttpRequestHeaderSize() != required.httpLimits().maxHeaderBytes()
                    || protocol.getDisableUploadTimeout() || protocol.getConnectionUploadTimeout() != required.requestReadTimeoutMillis()) {
                throw new IllegalStateException("VIRTUAL_LISTENER_CONFIGURATION_UNCONFIRMED");
            }
        }

        @Override public void start() throws Exception { tomcat.start(); }
        @Override public void verifyRequiredServletInitialization() throws Exception {
            // Existing owned registration fixes fuseVirtualMvc loadOnStartup(1).
            // With explicit failure policy, its ServletException makes this context non-STARTED,
            // even when Tomcat.start returns normally after controlled failure cleanup.
            if (context == null || !Boolean.TRUE.equals(context.getFailCtxIfServletStartFails())
                    || context.getState() != LifecycleState.STARTED) throw new IOException();
        }
        @Override public InetSocketAddress boundAddress() throws IOException { return endpoint.observedBoundAddress(); }
        @Override public void stop() throws Exception { if (tomcat != null) tomcat.stop(); }
        @Override public void destroy() throws Exception { if (tomcat != null) tomcat.destroy(); }
    }

    private static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_VIRTUAL_LISTENER_INPUT"); }
    @Override public String toString() { return "VirtualLoopbackListener[REDACTED]"; }
}
