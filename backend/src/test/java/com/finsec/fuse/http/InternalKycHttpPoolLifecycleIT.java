package com.finsec.fuse.http;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.junit.jupiter.api.Assertions.*;

/** Real loopback transport only. Four held requests are not Apache leased/pending
 * statistics: the production executor also caps concurrency at four. This test
 * does not exercise the two-second connection-acquisition deadline or repeat the
 * separately verified default 30-second deadline. All accepted observations
 * precede that deadline, client close, and fixture shutdown. */
class InternalKycHttpPoolLifecycleIT {
    private static final String PATH = "/internal/v1/kyc/evaluations";
    private static final long ACCEPTANCE_NANOS = TimeUnit.SECONDS.toNanos(25);

    @Test
    @Timeout(45)
    void interruptingFourHeldRequestsRecoversSameClientCapacityAndReusesHealthyConnection() throws Exception {
        var policy = InternalKycHttpClient.policy(new Json(new JsonConfiguration().jsonMapper()));
        assertEquals(4, policy.modelConcurrency());
        Set<Thread> baseline = httpThreads();
        Set<Thread> owned = new HashSet<>();
        List<Call> callers = new ArrayList<>();
        var fixture = new WireFixture();
        InternalKycHttpClient client = null;
        Throwable primaryFailure = null;
        try {
            client = new InternalKycHttpClient(fixture.url(), policy);
            long deadline = System.nanoTime() + ACCEPTANCE_NANOS;
            for (int i = 0; i < 4; i++) callers.add(start(client, "cancel-" + i));
            await(() -> fixture.requests.size() == 4, deadline, fixture);
            await(() -> fixture.prefixes.getCount() == 0, deadline, fixture);
            assertEquals(4, fixture.accepted.get());
            assertEquals(4, fixture.connectionsFor("cancel-", 4).size());
            assertEquals(4, fixture.held.get());
            assertTrue(callers.stream().allMatch(c -> c.thread.isAlive()));
            owned.addAll(httpThreads());
            owned.removeAll(baseline);
            assertEquals(4, owned.size(), "Owned HTTP worker identification must be unambiguous");

            // Interrupt the actual post caller; Future.cancel alone is not completion.
            callers.get(0).thread.interrupt();
            join(callers.get(0).thread, deadline);
            assertInstanceOf(InterruptedException.class, callers.get(0).failure.get());
            assertNull(callers.get(0).result.get());
            fixture.joinCancelled("cancel-0", deadline);
            fixture.check();
            assertEquals(Set.of("cancel-0"), fixture.cancelled);
            assertEquals(3, fixture.held.get());
            assertTrue(callers.subList(1, 4).stream().allMatch(c -> c.thread.isAlive()));

            Call independent = start(client, "independent"); callers.add(independent);
            assertSuccess(independent, deadline, fixture);
            int healthy = fixture.requests.get("independent").id;
            assertFalse(fixture.connectionsFor("cancel-", 4).contains(healthy));
            assertEquals(5, fixture.accepted.get());
            assertEquals(3, fixture.held.get(), "Independent completion must precede survivor release");
            assertTrue(callers.subList(1, 4).stream().allMatch(c -> c.thread.isAlive()));

            Call reused = start(client, "reused"); callers.add(reused);
            assertSuccess(reused, deadline, fixture);
            assertEquals(healthy, fixture.requests.get("reused").id,
                "A fully consumed healthy connection, not the cancelled socket, must be reused");
            assertEquals(5, fixture.accepted.get());
            assertEquals(3, fixture.held.get());
            assertTrue(callers.subList(1, 4).stream().allMatch(c -> c.thread.isAlive()));

            for (int i = 1; i < 4; i++) callers.get(i).thread.interrupt();
            for (int i = 1; i < 4; i++) {
                join(callers.get(i).thread, deadline);
                assertInstanceOf(InterruptedException.class, callers.get(i).failure.get());
                assertNull(callers.get(i).result.get());
                fixture.joinCancelled("cancel-" + i, deadline);
            }
            assertEquals(Set.of("cancel-0", "cancel-1", "cancel-2", "cancel-3"), fixture.cancelled);
            assertEquals(0, fixture.held.get());
            fixture.check();

            List<Call> recovered = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                Call call = start(client, "wave-" + i);
                recovered.add(call); callers.add(call);
            }
            await(() -> fixture.waveEntered.getCount() == 0, deadline, fixture);
            assertEquals(4, fixture.connectionsFor("wave-", 4).size());
            assertEquals(4, fixture.held.get(), "All recovered slots must be occupied before any release");
            assertEquals(1L, fixture.releaseWave.getCount());
            assertTrue(recovered.stream().allMatch(c -> c.thread.isAlive()));
            fixture.releaseWave.countDown();
            for (Call call : recovered) assertSuccess(call, deadline, fixture);
            await(() -> fixture.held.get() == 0, deadline, fixture);
            assertEquals(10, fixture.requests.size());
            assertEquals(10, fixture.parsed.get(), "No duplicate, retry, or delayed cancelled request");
            assertEquals(Set.of("cancel-0", "cancel-1", "cancel-2", "cancel-3",
                "independent", "reused", "wave-0", "wave-1", "wave-2", "wave-3"), fixture.requests.keySet());
            Set<Thread> current = httpThreads(); current.removeAll(baseline);
            assertEquals(owned, current, "The same four transport workers must remain reusable");
            assertTrue(owned.stream().allMatch(Thread::isAlive));
            fixture.check();
            remaining(deadline); // Every causal acceptance assertion is before the real 30s deadline.
        } catch (Exception | Error failure) {
            primaryFailure = failure; throw failure;
        } finally {
            // Every cleanup stage runs even if an earlier close or assertion fails.
            // Clear timeout interruption only for bounded joins, then restore it.
            boolean interrupted = Thread.interrupted();
            List<Throwable> failures = new ArrayList<>();
            fixture.closing.set(true);
            fixture.releaseWave.countDown();
            for (Call call : callers) if (call.thread.isAlive()) call.thread.interrupt();
            try { if (client != null) client.close(); } catch (Throwable failure) { failures.add(failure); }
            try { fixture.close(); } catch (Throwable failure) { failures.add(failure); }
            long cleanupDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            for (Call call : callers) {
                try { join(call.thread, cleanupDeadline); } catch (Throwable failure) { failures.add(failure); }
            }
            // Include newly created workers even if setup failed before ownership was captured.
            Set<Thread> remainingWorkers = httpThreads(); remainingWorkers.removeAll(baseline); owned.addAll(remainingWorkers);
            for (Thread thread : owned) {
                try { join(thread, cleanupDeadline); } catch (Throwable failure) { failures.add(failure); }
            }
            if (interrupted) Thread.currentThread().interrupt();
            if (!failures.isEmpty()) {
                var failure = new AssertionError("Transport lifecycle cleanup did not terminate");
                failures.forEach(failure::addSuppressed);
                if (primaryFailure != null) primaryFailure.addSuppressed(failure);
                else throw failure;
            }
        }
    }

    private static Set<Thread> httpThreads() {
        Set<Thread> threads = new HashSet<>();
        for (Thread thread : Thread.getAllStackTraces().keySet())
            if (thread.isAlive() && thread.getName().equals("kyc-http")) threads.add(thread);
        return threads;
    }
    private static long remaining(long deadline) {
        long nanos = deadline - System.nanoTime();
        assertTrue(nanos > 0, "Bounded transport observation window exceeded");
        return nanos;
    }
    private static void join(Thread thread, long deadline) throws InterruptedException {
        if (!thread.isAlive()) return;
        TimeUnit.NANOSECONDS.timedJoin(thread, remaining(deadline));
        assertFalse(thread.isAlive(), "Owned thread must finish inside observation window");
    }
    private static void await(BooleanSupplier condition, long deadline, WireFixture fixture) throws Exception {
        while (!condition.getAsBoolean()) {
            fixture.check();
            TimeUnit.NANOSECONDS.sleep(Math.min(remaining(deadline), TimeUnit.MILLISECONDS.toNanos(5)));
        }
        fixture.check(); remaining(deadline);
    }
    private static byte[] body(String id) {
        return ("{\"id\":\"" + id + "\"}").getBytes(StandardCharsets.US_ASCII);
    }
    private static Call start(InternalKycHttpClient client, String id) {
        Call call = new Call(id);
        call.thread = new Thread(() -> {
            try { call.result.set(client.post(PATH, "synthetic-token", body(id))); }
            catch (Throwable failure) { call.failure.set(failure); }
        }, "fixture-caller-" + id);
        call.thread.setDaemon(true); call.thread.start();
        return call;
    }
    private static void assertSuccess(Call call, long deadline, WireFixture fixture) throws Exception {
        join(call.thread, deadline); fixture.check(); remaining(deadline);
        assertNull(call.failure.get(), "Independent transport call must succeed");
        assertNotNull(call.result.get());
        assertEquals(200, call.result.get().status());
        assertArrayEquals(body(call.id), call.result.get().body());
    }
    private static final class Call {
        final String id;
        final AtomicReference<InternalKycHttpClient.Result> result = new AtomicReference<>();
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread thread;
        Call(String id) { this.id = id; }
    }
    private static final class Connection {
        final int id;
        final Socket socket;
        FutureTask<Void> task;
        Connection(int id, Socket socket) { this.id = id; this.socket = socket; }
    }

    private static final class WireFixture implements AutoCloseable {
        final ServerSocket listener;
        final Thread acceptor;
        final ThreadPoolExecutor handlers;
        final List<Thread> handlerThreads = java.util.Collections.synchronizedList(new ArrayList<>());
        final Map<Integer, Connection> sockets = new ConcurrentHashMap<>();
        final Map<String, Connection> requests = new ConcurrentHashMap<>();
        final Set<String> cancelled = ConcurrentHashMap.newKeySet();
        final AtomicInteger accepted = new AtomicInteger();
        final AtomicInteger parsed = new AtomicInteger();
        final AtomicInteger held = new AtomicInteger();
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final AtomicBoolean closing = new AtomicBoolean();
        final AtomicBoolean watchdog = new AtomicBoolean();
        final CountDownLatch prefixes = new CountDownLatch(4);
        final CountDownLatch waveEntered = new CountDownLatch(4);
        final CountDownLatch releaseWave = new CountDownLatch(1);

        WireFixture() throws IOException {
            listener = new ServerSocket(0, 16, InetAddress.getByAddress(new byte[]{127, 0, 0, 1}));
            handlers = new ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(8), runnable -> {
                Thread thread = new Thread(runnable, "fixture-wire"); thread.setDaemon(true);
                handlerThreads.add(thread); return thread;
            }, new ThreadPoolExecutor.AbortPolicy());
            acceptor = new Thread(() -> {
                try {
                    while (!closing.get()) {
                        Socket socket = listener.accept(); socket.setSoTimeout(35_000);
                        Connection connection = new Connection(accepted.incrementAndGet(), socket);
                        sockets.put(connection.id, connection);
                        connection.task = new FutureTask<>(() -> { serve(connection); return null; });
                        handlers.execute(connection.task);
                    }
                } catch (Throwable problem) { if (!closing.get()) failure.compareAndSet(null, problem); }
            }, "fixture-acceptor");
            acceptor.setDaemon(true); acceptor.start();
        }
        String url() { return "http://127.0.0.1:" + listener.getLocalPort(); }
        Set<Integer> connectionsFor(String prefix, int count) {
            Set<Integer> ids = new HashSet<>();
            for (int i = 0; i < count; i++) {
                Connection connection = requests.get(prefix + i); assertNotNull(connection); ids.add(connection.id);
            }
            return ids;
        }
        void check() {
            assertFalse(closing.get(), "Teardown cannot establish a transport result");
            assertFalse(watchdog.get(), "Fixture timeout cannot establish cancellation");
            assertNull(failure.get(), "Loopback protocol fixture failed");
        }
        void joinCancelled(String id, long deadline) throws Exception {
            Connection connection = requests.get(id); assertNotNull(connection);
            connection.task.get(remaining(deadline), TimeUnit.NANOSECONDS);
            check(); remaining(deadline);
            assertTrue(cancelled.contains(id), "Client EOF/reset must precede fixture close");
        }
        void serve(Connection connection) {
            try (Socket socket = connection.socket) {
                InputStream input = socket.getInputStream();
                while (!closing.get()) {
                    String id = request(input);
                    if (id == null) return;
                    parsed.incrementAndGet();
                    if (requests.putIfAbsent(id, connection) != null) throw new IOException("Duplicate fixture request");
                    byte[] response = body(id);
                    var output = socket.getOutputStream();
                    output.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                        + response.length + "\r\nConnection: keep-alive\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    if (id.startsWith("cancel-")) {
                        held.incrementAndGet();
                        try {
                            output.write(response, 0, 1); output.flush(); prefixes.countDown();
                            // No server-side release, close, or complete body can cause this EOF.
                            boolean ended;
                            try { ended = input.read() == -1; }
                            catch (SocketException reset) {
                                if (closing.get() || socket.isClosed()) throw reset;
                                ended = true;
                            }
                            if (!ended || closing.get()) throw new IOException("Cancellation observation unavailable");
                            cancelled.add(id);
                        } finally { held.decrementAndGet(); }
                        return;
                    }
                    if (id.startsWith("wave-")) {
                        held.incrementAndGet(); waveEntered.countDown();
                        try {
                            if (!releaseWave.await(35, TimeUnit.SECONDS)) {
                                watchdog.set(true); throw new IOException("Fixture release watchdog");
                            }
                            if (closing.get()) return;
                            output.write(response); output.flush();
                        } finally { held.decrementAndGet(); }
                    } else {
                        output.write(response); output.flush();
                    }
                }
            } catch (SocketTimeoutException timeout) {
                if (!closing.get()) { watchdog.set(true); failure.compareAndSet(null, timeout); }
            } catch (Throwable problem) { if (!closing.get()) failure.compareAndSet(null, problem); }
        }
        static String request(InputStream input) throws IOException {
            String first = line(input, 1024);
            if (first == null) return null;
            if (!first.equals("POST " + PATH + " HTTP/1.1")) throw new IOException("Unexpected fixture request line");
            Map<String, String> headers = new HashMap<>(); int total = first.length();
            for (int i = 0; ; i++) {
                if (i >= 32) throw new IOException("Fixture header limit");
                String header = line(input, 1024);
                if (header == null) throw new EOFException();
                total += header.length(); if (total > 8192) throw new IOException("Fixture header limit");
                if (header.isEmpty()) break;
                int separator = header.indexOf(':');
                if (separator <= 0) throw new IOException("Invalid fixture header");
                String name = header.substring(0, separator).toLowerCase(java.util.Locale.ROOT);
                if (headers.putIfAbsent(name, header.substring(separator + 1).trim()) != null)
                    throw new IOException("Ambiguous fixture header");
            }
            String length = headers.get("content-length");
            if (headers.containsKey("transfer-encoding") || headers.containsKey("expect")
                || length == null || !length.matches("[1-9][0-9]{0,2}")) throw new IOException("Fixture framing");
            int count = Integer.parseInt(length);
            if (count > 128) throw new IOException("Fixture body limit");
            byte[] bytes = input.readNBytes(count);
            if (bytes.length != count) throw new EOFException();
            String body = new String(bytes, StandardCharsets.US_ASCII);
            if (!body.matches("\\{\"id\":\"(cancel-[0-3]|wave-[0-3]|independent|reused)\"\\}"))
                throw new IOException("Unexpected fixture body");
            return body.substring(7, body.length() - 2);
        }
        static String line(InputStream input, int limit) throws IOException {
            var bytes = new ByteArrayOutputStream();
            for (int i = 0; i <= limit; i++) {
                int value = input.read();
                if (value == -1) { if (i == 0) return null; throw new EOFException(); }
                if (value == '\r') {
                    if (input.read() != '\n') throw new IOException("Fixture CRLF required");
                    return bytes.toString(StandardCharsets.US_ASCII);
                }
                if (value < 32 || value > 126) throw new IOException("Fixture ASCII header required");
                bytes.write(value);
            }
            throw new IOException("Fixture line limit");
        }
        public void close() throws Exception {
            closing.set(true); releaseWave.countDown();
            List<Throwable> failures = new ArrayList<>();
            try { listener.close(); } catch (Throwable problem) { failures.add(problem); }
            for (Connection connection : sockets.values()) {
                try { connection.socket.close(); } catch (Throwable problem) { failures.add(problem); }
            }
            handlers.shutdownNow();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            try { join(acceptor, deadline); } catch (Throwable problem) { failures.add(problem); }
            // The acceptor can have obtained a socket concurrently with initial shutdown.
            for (Connection connection : sockets.values()) {
                try { connection.socket.close(); } catch (Throwable problem) { failures.add(problem); }
            }
            try { assertTrue(handlers.awaitTermination(remaining(deadline), TimeUnit.NANOSECONDS)); }
            catch (Throwable problem) { failures.add(problem); }
            synchronized (handlerThreads) {
                for (Thread thread : handlerThreads) {
                    try { join(thread, deadline); } catch (Throwable problem) { failures.add(problem); }
                }
            }
            if (!failures.isEmpty()) {
                var error = new AssertionError("Loopback fixture cleanup did not terminate");
                failures.forEach(error::addSuppressed); throw error;
            }
        }
    }
}
