package com.finsec.fuse.testing;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.payment.*;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.workflow.*;
import java.net.URI;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import tools.jackson.databind.json.JsonMapper;

/** Child JVM entry point on the test classpath only. No HTTP control/bypass endpoints. */
public final class ProcessRecoveryServer {
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Actor CUSTOMER = new Actor("customer-102", "CUSTOMER", Set.of("customer-102"));
    private static final Actor REVIEWER = new Actor("staff-01", "LOAN_REVIEWER", Set.of("customer-102"));

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Expected private harness config");
        Map<?, ?> config = JSON.readValue(Files.readString(Path.of(args[0])), Map.class);
        Path work = Path.of(required(config, "work"));
        String phase = required(config, "phase");
        if (!Set.of("prepare", "recover").contains(phase)) throw new IllegalArgumentException("Unknown process phase");
        if (!Set.of("KYC_INFLIGHT", "PAY_CLAIM", "PAY_RESERVED", "PAY_COMMITTED", "DB_UNAVAILABLE").contains(config.get("scenario")))
            throw new IllegalArgumentException("Unknown registered process scenario");
        requireLoopback(required(config, "agentUrl"), "http");
        String databaseUrl = required(config, "databaseUrl");
        if (!databaseUrl.startsWith("jdbc:")) throw new IllegalArgumentException("Expected test JDBC URL");
        requireLoopback(databaseUrl.substring(5), "postgresql");
        var options = new ArrayList<String>(List.of(
            "--spring.profiles.active=test", "--server.address=127.0.0.1", "--server.port=0",
            "--spring.datasource.url=" + required(config, "databaseUrl"),
            "--spring.datasource.username=postgres", "--spring.datasource.password=",
            "--spring.flyway.user=postgres", "--spring.flyway.password=",
            "--spring.datasource.hikari.connection-timeout=1000",
            "--spring.datasource.hikari.validation-timeout=500",
            "--fuse.demo-seed=true", "--fuse.worker-enabled=false", "--fuse.experiments.enabled=false",
            "--fuse.kyc-mode=replay", "--fuse.kyc-base-url=" + required(config, "agentUrl"),
            "--fuse.test-time=" + required(config, "time"),
            "--fuse.signing-key-path=" + required(config, "keyPath"),
            "--fuse.service-token=" + required(config, "token")));
        for (String role : List.of("customer-101", "customer-102", "customer-103", "customer-104", "reviewer", "security", "developer"))
            options.add("--fuse.auth." + role + "-token=" + required(config, role));
        try (var context = new SpringApplication(FuseApplication.class).run(options.toArray(String[]::new))) {
            publish(work.resolve(phase + ".port"), context.getEnvironment().getRequiredProperty("local.server.port"));
            if ("recover".equals(phase)) recover(context, config, work);
            else prepare(context, config, work);
            // Bounded local rendezvous keeps the HTTP server alive until the owning harness stops it.
            await(work.resolve(phase + ".stop"), Duration.ofSeconds(120));
        }
    }

    private static void prepare(ConfigurableApplicationContext context, Map<?, ?> config, Path work) throws Exception {
        var workflows = context.getBean(WorkflowService.class);
        var worker = context.getBean(JobWorker.class);
        var jobs = context.getBean(JobTransactions.class);
        UUID workflowId = (UUID) workflows.start(CUSTOMER, UUID.randomUUID(), new StartWorkflowRequest(
            "APP-DEMO-102-001", "customer-102", 1000000L,
            UUID.fromString("00000000-0000-4000-8000-000000000102"))).get("workflowId");
        publish(work.resolve("workflow.id"), workflowId.toString());
        if (!worker.runOne()) throw new AssertionError("KYC job was not claimed");
        // In the KYC crash scenario, the mock HTTP server never releases this first runOne call.
        if ("KYC_INFLIGHT".equals(config.get("scenario"))) throw new AssertionError("KYC barrier unexpectedly returned");
        if (!worker.runOne()) throw new AssertionError("Loan job was not claimed");
        var approvals = context.getBean(ApprovalService.class);
        var preview = approvals.preview(REVIEWER, workflowId);
        approvals.decide(REVIEWER, workflowId, UUID.randomUUID(), new ApprovalRequest(
            ApprovalRequest.Decision.APPROVE, (String) preview.get("reviewSnapshotHash"), "Synthetic harness review"));
        var pay = jobs.claim().orElseThrow();
        if (!"PAY".equals(pay.phase())) throw new AssertionError("Expected PAY claim");
        String scenario = required(config, "scenario");
        if ("PAY_CLAIM".equals(scenario)) {
            publish(work.resolve("boundary.ready"), "PAY_CLAIM_COMMITTED");
            await(work.resolve("boundary.release"), Duration.ofSeconds(90));
            throw new AssertionError("Claim-only crash barrier unexpectedly released");
        }
        if (!"PAY_COMMITTED".equals(scenario)) {
            context.getBean(PaymentTestHooks.class).onAfterReservation(() -> {
                try {
                    publish(work.resolve("boundary.ready"), "PAY_RESERVATION_COMMITTED");
                    await(work.resolve("boundary.release"), Duration.ofSeconds(90));
                } catch (Exception failure) { throw new IllegalStateException("Reservation barrier failed", failure); }
            });
        }
        // Use the real worker so DB exceptions preserve uncertainty rather than manufacturing a denial.
        worker.execute(pay);
        if ("PAY_COMMITTED".equals(scenario)) {
            publish(work.resolve("boundary.ready"), "PAY_COMMITTED_RECEIPT_NOT_DELIVERED");
            await(work.resolve("boundary.release"), Duration.ofSeconds(90));
            throw new AssertionError("Lost-response crash barrier unexpectedly released");
        }
        publish(work.resolve("execution.returned"), "Worker returned after attempted final commit");
    }

    private static void recover(ConfigurableApplicationContext context, Map<?, ?> config, Path work) throws Exception {
        var db = context.getBean(Db.class);
        var reaper = context.getBean(LeaseReaper.class);
        var worker = context.getBean(JobWorker.class);
        reaper.reap();
        // Repeated recovery/queue polls establish idempotence without waiting for scheduler luck.
        for (int i = 0; i < 3; i++) {
            if (worker.runOne()) throw new AssertionError("Recovery automatically retried an unauthorized job");
            reaper.reap();
        }
        Map<String, Object> replay = Map.of();
        if ("PAY_COMMITTED".equals(config.get("scenario"))) {
            var job = db.required("select id,lease_token from workflow_job where phase='PAY'");
            var payment = context.getBean(PaymentAgentService.class);
            replay = payment.execute((UUID) job.get("id"), (UUID) job.get("lease_token"));
            var second = payment.execute((UUID) job.get("id"), (UUID) job.get("lease_token"));
            if (!Objects.equals(replay.get("paymentId"), second.get("paymentId")))
                throw new AssertionError("Repeated historical action returned another payment ID");
        }
        publish(work.resolve("recovery.ready"), JSON.writeValueAsString(Map.of(
            "reaperPasses", 4, "emptyQueuePolls", 3, "receiptReplay", replay)));
    }

    private static void await(Path path, Duration timeout) throws Exception {
        if (Files.exists(path)) return;
        try (var watcher = path.getFileSystem().newWatchService()) {
            path.getParent().register(watcher, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);
            long deadline = System.nanoTime() + timeout.toNanos();
            while (!Files.exists(path)) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) throw new IllegalStateException("Timed out at test barrier " + path.getFileName());
                var key = watcher.poll(remaining, java.util.concurrent.TimeUnit.NANOSECONDS);
                if (key == null) throw new IllegalStateException("Timed out at test barrier " + path.getFileName());
                key.pollEvents();
                if (!key.reset()) throw new IllegalStateException("Test barrier directory disappeared");
            }
        }
    }

    static void publish(Path path, String value) throws Exception {
        Path pending = path.resolveSibling(path.getFileName() + ".pending");
        Files.writeString(pending, value);
        Files.move(pending, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    private static String required(Map<?, ?> config, String name) {
        if (config.get(name) instanceof String value && !value.isBlank()) return value;
        throw new IllegalArgumentException("Missing harness field " + name);
    }

    private static void requireLoopback(String value, String scheme) {
        URI uri = URI.create(value);
        if (!scheme.equals(uri.getScheme()) || !Set.of("127.0.0.1", "localhost").contains(uri.getHost())
            || uri.getPort() < 1 || uri.getPort() > 65535 || uri.getUserInfo() != null || uri.getFragment() != null)
            throw new IllegalArgumentException("Process harness endpoints must use local owned services");
    }
}
