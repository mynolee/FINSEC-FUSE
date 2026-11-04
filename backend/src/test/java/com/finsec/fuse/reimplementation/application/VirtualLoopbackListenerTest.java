package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualExperimentService;
import com.finsec.fuse.reimplementation.simulation.VirtualProductAssembly;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.application.VirtualLoopbackListener.*;

/** Fake lifecycle and temporary directory metadata only; no real container or listener. */
class VirtualLoopbackListenerTest {
    @TempDir Path temporary;
    private final HttpLimits limits = new HttpLimits(4096, 8192, 16);

    private Settings settings() throws Exception {
        Path base = temporary.toRealPath();
        Path doc = Files.createDirectory(base.resolve("synthetic-doc"));
        Path work = Files.createDirectory(base.resolve("synthetic-work"));
        var mode = Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
        for (Path directory : List.of(base, doc, work)) Files.setPosixFilePermissions(directory, mode);
        long uid = ((Number) Files.getAttribute(base, "unix:uid")).longValue();
        return new Settings(new VirtualHttpApplication.Config("127.0.0.1", 18080, "/internal/v1/ready",
                limits, 1000, 1), base, doc, work, uid, 2, 1, 1, 1, 0, 1, 1000, 2, 1000);
    }

    private VirtualProductAssembly.Inputs inputs() {
        return new VirtualProductAssembly.Inputs(new VirtualTransactionalStore(),
                new SimulationSpec.Catalog(List.of(), List.of()),
                new SimulationSpec.RiskTerms("SYNTHETIC-ONLY", 1, 2, 3, 10, 2, 1, Duration.ofMinutes(1)),
                (actor, operation, workflow, customer) -> false, (actor, target, remediation) -> false,
                List.of(), new VirtualExperimentService.PairEvaluator() {
                    public String mode() { return VirtualTransactionalStore.MODE; }
                    public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                            String caseId, int repeat, Map<String, Object> shared) {
                        throw new AssertionError("Synthetic evaluator must not run");
                    }
                }, Clock.fixed(Instant.parse("2000-01-01T00:00:00Z"), ZoneOffset.UTC),
                () -> { throw new AssertionError("No seed or identifiers"); },
                (request, operation, workflow, customer) -> null, (request, operation, workflow) -> null, limits);
    }

    private static final class FakeRuntime implements VirtualLoopbackListener.Runtime {
        int configured, started, observed, stopped, destroyed;
        boolean configureFails, startFails, stopFails, fatalStart, requiredServletFailed;
        int initializationChecks;
        InetSocketAddress address;
        AtomicBoolean gate;
        ThreadPoolExecutor executor;
        public void configure(Settings settings, VirtualProductAssembly.Inputs inputs,
                VirtualHttpApplication.ReadinessAuthorization auth, BooleanSupplier available,
                AtomicBoolean verified, ThreadPoolExecutor workers) throws Exception {
            configured++; gate = verified; executor = workers;
            assertFalse(verified.get()); assertEquals(0, workers.getPoolSize());
            if (configureFails) throw new IOException("SYNTHETIC_PRIVATE_CONFIG");
        }
        public void start() throws Exception {
            started++; assertFalse(gate.get());
            if (fatalStart) throw new AssertionError("SYNTHETIC_FATAL");
            if (startFails) throw new IOException("SYNTHETIC_PRIVATE_START");
        }
        public void verifyRequiredServletInitialization() throws Exception {
            initializationChecks++; assertFalse(gate.get());
            if (requiredServletFailed) throw new IOException("SYNTHETIC_REQUIRED_SERVLET_INIT_FAILURE");
        }
        public InetSocketAddress boundAddress() { observed++; assertFalse(gate.get()); return address; }
        public void stop() throws Exception { stopped++; if (stopFails) throw new IOException("SYNTHETIC_PRIVATE_STOP"); }
        public void destroy() { destroyed++; }
    }

    private VirtualLoopbackListener listener(Settings settings, FakeRuntime runtime, AtomicInteger factories) {
        return VirtualLoopbackListener.forSyntheticProtocol(settings, inputs(),
                request -> VirtualHttpApplication.Access.UNAUTHENTICATED,
                () -> { throw new AssertionError("No readiness callback in fake lifecycle"); },
                () -> { factories.incrementAndGet(); return runtime; });
    }

    private static InetSocketAddress address(byte[] ip, int port) throws Exception {
        return new InetSocketAddress(InetAddress.getByAddress(ip), port);
    }

    @Test void prepareDoesNotCreateContainerWorkersFilesOrInvokeCallbacks() throws Exception {
        Settings settings = settings(); FakeRuntime runtime = new FakeRuntime(); var count = new AtomicInteger();
        var listener = listener(settings, runtime, count);
        assertEquals(State.PREPARED, listener.state()); assertEquals(0, count.get());
        assertEquals(0, runtime.configured); assertEquals(0, runtime.started);
        try (var files = Files.list(settings.workDirectory())) { assertEquals(0L, files.count()); }
        assertEquals("VirtualLoopbackListener[REDACTED]", listener.toString());
        assertEquals("VirtualListenerSettings[REDACTED]", settings.toString());
    }

    @Test void actualAddressGatePrecedesStartedAndStopOnlyTouchesOwnedResourcesOnce() throws Exception {
        Settings settings = settings(); FakeRuntime runtime = new FakeRuntime(); var count = new AtomicInteger();
        runtime.address = address(new byte[] {127, 0, 0, 1}, settings.application().port());
        var listener = listener(settings, runtime, count);
        assertEquals(StartResult.STARTED, listener.start()); assertEquals(State.RUNNING, listener.state());
        assertTrue(runtime.gate.get()); assertEquals(1, runtime.observed);
        assertEquals(StopResult.STOP_ACKNOWLEDGED, listener.stop()); assertFalse(runtime.gate.get());
        assertTrue(runtime.executor.isShutdown());
        listener.close(); assertEquals(1, runtime.stopped); assertEquals(1, runtime.destroyed);
        assertThrows(IllegalStateException.class, listener::start); assertEquals(1, count.get());
    }

    @Test void wrongActualAddressFailsSingleAttemptWithoutPortHoppingOrReadiness() throws Exception {
        Settings settings = settings(); FakeRuntime runtime = new FakeRuntime(); var count = new AtomicInteger();
        runtime.address = address(new byte[] {0, 0, 0, 0}, settings.application().port());
        var listener = listener(settings, runtime, count);
        assertEquals(StartResult.START_FAILED_CLEANUP_ACKNOWLEDGED, listener.start());
        assertFalse(runtime.gate.get()); assertEquals(1, runtime.started); assertEquals(1, runtime.stopped);
        assertThrows(IllegalStateException.class, listener::start); assertEquals(1, count.get());
    }

    @Test void normalStartReturnWithFailedRequiredServletNeverPublishesOrObservesBind() throws Exception {
        Settings settings = settings(); FakeRuntime runtime = new FakeRuntime(); var count = new AtomicInteger();
        runtime.requiredServletFailed = true; var listener = listener(settings, runtime, count);
        assertEquals(StartResult.START_FAILED_CLEANUP_ACKNOWLEDGED, listener.start());
        assertEquals(1, runtime.started); assertEquals(1, runtime.initializationChecks);
        assertEquals(0, runtime.observed); assertFalse(runtime.gate.get());
        assertEquals(1, runtime.stopped); assertEquals(1, runtime.destroyed);
        assertTrue(runtime.executor.isShutdown());
        assertThrows(IllegalStateException.class, listener::start);
        listener.stop(); assertEquals(1, runtime.stopped); assertEquals(1, count.get());
    }

    @Test void startupAndCleanupExceptionsProduceFixedResidualStateWithoutAutomaticRetry() throws Exception {
        Settings settings = settings(); FakeRuntime runtime = new FakeRuntime(); var count = new AtomicInteger();
        runtime.startFails = true; runtime.stopFails = true;
        var listener = listener(settings, runtime, count);
        assertEquals(StartResult.START_FAILED_RESIDUAL_UNCONFIRMED, listener.start());
        assertEquals(State.RESIDUAL_UNCONFIRMED, listener.state());
        assertEquals(StopResult.STOP_UNCONFIRMED, listener.stop());
        assertEquals(1, runtime.stopped); assertEquals(1, runtime.destroyed); assertTrue(runtime.executor.isShutdown());
        assertThrows(IllegalStateException.class, listener::start);
    }

    @Test void nonemptyDedicatedWorkDirectoryFailsBeforeAnyRuntimeOrWorkerCreation() throws Exception {
        Settings settings = settings(); Files.writeString(settings.workDirectory().resolve("synthetic-only"), "fixture");
        FakeRuntime runtime = new FakeRuntime(); var count = new AtomicInteger(); var listener = listener(settings, runtime, count);
        assertEquals(StartResult.START_FAILED_CLEANUP_ACKNOWLEDGED, listener.start());
        assertEquals(0, count.get()); assertEquals(0, runtime.configured); assertEquals(0, runtime.started);
    }

    @Test void explicitSettingsRejectWrongPathRelationsAndSilentKeepaliveOrUtilityDefaults() throws Exception {
        Settings s = settings();
        assertThrows(IllegalArgumentException.class, () -> new Settings(s.application(), s.baseDirectory(),
                s.docBase(), s.docBase(), s.expectedOwnerUid(), 2, 1, 1, 1, 0, 1, 1000, 2, 1000));
        assertThrows(IllegalArgumentException.class, () -> new Settings(s.application(), s.baseDirectory(),
                s.docBase(), s.workDirectory(), s.expectedOwnerUid(), 2, 1, 2, 1, 0, 1, 1000, 2, 1000));
        assertThrows(IllegalArgumentException.class, () -> new Settings(s.application(), s.baseDirectory(),
                s.docBase(), s.workDirectory(), s.expectedOwnerUid(), 2, 1, 1, 1, 0, 1, 1000, 0, 1000));
        assertThrows(IllegalArgumentException.class, () -> VirtualLoopbackListener.prepare(s, inputs(), null, () -> true));
    }

    @Test void fatalLifecycleErrorPropagatesWithoutClaimingTypedCleanupOrNoMutation() throws Exception {
        Settings settings = settings(); FakeRuntime runtime = new FakeRuntime(); var count = new AtomicInteger();
        runtime.fatalStart = true; var listener = listener(settings, runtime, count);
        assertThrows(AssertionError.class, listener::start); assertFalse(runtime.gate.get());
        // Explicit cleanup for this fake fixture only; no universal fatal Error recovery is asserted.
        assertEquals(StopResult.STOP_ACKNOWLEDGED, listener.stop());
    }
}
