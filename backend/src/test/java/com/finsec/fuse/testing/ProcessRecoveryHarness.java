package com.finsec.fuse.testing;

import com.finsec.fuse.workflow.KycContract;
import com.sun.net.httpserver.HttpServer;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import tools.jackson.databind.json.JsonMapper;

/** Real child-JVM crashes and PostgreSQL outages. Only fresh, owned DB directories are accepted. */
public final class ProcessRecoveryHarness {
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Instant T0 = Instant.parse("2026-10-09T04:00:00Z");
    private static final List<String> SCENARIOS = List.of("KYC_INFLIGHT", "PAY_CLAIM", "PAY_RESERVED", "PAY_COMMITTED", "DB_UNAVAILABLE");
    private final Path root;
    private final Path report;
    private final List<Map<String, Object>> results = new ArrayList<>();
    private final List<Process> children = new CopyOnWriteArrayList<>();
    private final List<Process> databaseProcesses = new CopyOnWriteArrayList<>();
    private final Set<Integer> ownedPorts = new HashSet<>();
    private volatile EmbeddedPostgres pg;
    private volatile HttpServer agent;
    private volatile ExecutorService agentExecutor;

    private ProcessRecoveryHarness(Path root, Path report) { this.root = root; this.report = report; }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("Expected empty temporary work directory and report path");
        Path work = Path.of(args[0]).toRealPath();
        try (var entries = Files.list(work)) {
            if (entries.findAny().isPresent()) throw new IllegalArgumentException("Refusing a nonempty work directory");
        }
        var harness = new ProcessRecoveryHarness(work, Path.of(args[1]).toAbsolutePath());
        Thread shutdown = new Thread(harness::cleanup, "owned-recovery-process-cleanup");
        Runtime.getRuntime().addShutdownHook(shutdown);
        boolean passed = false;
        try {
            for (String scenario : SCENARIOS) harness.scenario(scenario);
            passed = true;
        } finally {
            harness.cleanup();
            harness.writeReport(passed);
            Runtime.getRuntime().removeShutdownHook(shutdown);
        }
        System.out.println("PROCESS_RECOVERY_PASS scenarios=" + SCENARIOS.size() + " PostgreSQL=16.15 syntheticReplay=true");
    }

    private void scenario(String scenario) throws Exception {
        Path work = Files.createDirectory(root.resolve(scenario.toLowerCase(Locale.ROOT)));
        var row = new LinkedHashMap<String, Object>();
        row.put("testId", "KYC_INFLIGHT".equals(scenario) ? "FAILURE-6-KYC" : "T12-" + scenario);
        row.put("scenario", scenario);
        row.put("specSections", List.of("12", "17.3"));
        row.put("implementedTestFile", "backend/src/test/java/com/finsec/fuse/testing/ProcessRecoveryHarness.java");
        row.put("verdict", "FAIL");
        row.put("expected", expected(scenario));
        row.put("timeSource", "Shared Spring test TimeSource: T0, then T0+91s at new process startup; OS/SQL clock unchanged");
        row.put("startedAt", Instant.now().toString());
        results.add(row);
        var calls = new AtomicInteger();
        var inflight = new CountDownLatch(1);
        var releaseAgent = new CountDownLatch(1);
        String token = com.finsec.fuse.auth.DevActorRegistry.generateToken();
        var actorTokens = new LinkedHashMap<String, String>();
        for (String role : List.of("customer-101", "customer-102", "customer-103", "customer-104", "reviewer", "security", "developer"))
            actorTokens.put(role, com.finsec.fuse.auth.DevActorRegistry.generateToken());
        try {
            pg = database(work.resolve("database"), 0);
            String databaseUrl = pg.getJdbcUrl("postgres", "postgres");
            row.put("postgresVersion", single(databaseUrl, "show server_version"));
            check("16.15".equals(row.get("postgresVersion")), "Expected PostgreSQL 16.15");
            ownedPorts.add(pg.getPort());
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            Path keyFile = work.resolve("ephemeral-signing-key");
            Files.write(keyFile, key);
            Files.setPosixFilePermissions(keyFile, PosixFilePermissions.fromString("rw-------"));
            Arrays.fill(key, (byte) 0);
            agent = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            agentExecutor = Executors.newVirtualThreadPerTaskExecutor();
            agent.setExecutor(agentExecutor);
            agent.createContext("/internal/v1/kyc/evaluations", exchange -> {
                try (exchange) {
                    if (!"POST".equals(exchange.getRequestMethod()) || !token.equals(exchange.getRequestHeaders().getFirst("X-Fuse-Service-Token"))) {
                        exchange.sendResponseHeaders(403, -1); return;
                    }
                    byte[] bytes = exchange.getRequestBody().readNBytes(65537);
                    if (bytes.length > 65536) { exchange.sendResponseHeaders(413, -1); return; }
                    var input = JSON.readValue(bytes, KycContract.Input.class);
                    calls.incrementAndGet();
                    if ("KYC_INFLIGHT".equals(scenario)) {
                        inflight.countDown();
                        if (!releaseAgent.await(60, TimeUnit.SECONDS)) throw new IllegalStateException("KYC crash barrier timeout");
                    }
                    var response = new KycContract.Response(input.requestId(), input.workflowId(), input.generation(), input.runId(),
                        input.inputSnapshotHash(), new KycContract.Proposal(KycContract.ProposalStatus.VERIFIED,
                        input.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList(), "Synthetic process-recovery replay"),
                        new KycContract.ModelMetadata("replay", "KYC-PROMPT-1"));
                    byte[] body = JSON.writeValueAsBytes(response);
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, body.length);
                    exchange.getResponseBody().write(body);
                } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                catch (Exception failure) {
                    // A killed KYC caller is expected to close the mock HTTP connection.
                    if (!"KYC_INFLIGHT".equals(scenario)) throw new IllegalStateException("Mock KYC failed", failure);
                }
            });
            agent.start();
            ownedPorts.add(agent.getAddress().getPort());
            var config = new LinkedHashMap<String, Object>(Map.of(
                "scenario", scenario, "phase", "prepare", "work", work.toString(), "databaseUrl", databaseUrl,
                "agentUrl", "http://127.0.0.1:" + agent.getAddress().getPort(), "time", T0.toString(),
                "keyPath", keyFile.toString(), "token", token));
            config.putAll(actorTokens);
            Process child = launch(work, config);
            row.put("killedProcessId", child.pid());
            awaitFile(work.resolve("prepare.port"), child, 60);
            int backendPort = Integer.parseInt(Files.readString(work.resolve("prepare.port")));
            ownedPorts.add(backendPort);
            awaitFile(work.resolve("workflow.id"), child, 30);
            if ("KYC_INFLIGHT".equals(scenario)) {
                check(inflight.await(30, TimeUnit.SECONDS), "Actual KYC HTTP request never reached barrier");
                row.put("injectionBoundary", "Actual KYC HTTP request accepted; no response delivered");
            } else {
                awaitFile(work.resolve("boundary.ready"), child, 30);
                row.put("injectionBoundary", Files.readString(work.resolve("boundary.ready")));
            }
            var before = snapshot(databaseUrl);
            row.put("beforeFailure", before);
            assertPrepared(scenario, before);
            if ("DB_UNAVAILABLE".equals(scenario)) {
                int port = pg.getPort();
                long databasePid = pg.getProcess().pid();
                pg.close(); pg = null;
                check(!portOpen(port), "PostgreSQL port remained open after requested stop");
                row.put("stoppedDatabaseProcessId", databasePid);
                HttpResponse<String> response = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build().send(
                    HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + backendPort + "/api/v1/workflows/" + Files.readString(work.resolve("workflow.id"))))
                        .timeout(Duration.ofSeconds(15)).header("Authorization", "Bearer " + actorTokens.get("customer-102")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
                var body = JSON.readValue(response.body(), Map.class);
                row.put("outageHttp", Map.of("status", response.statusCode(), "body", body));
                check(response.statusCode() == 503 && "ERROR".equals(body.get("decision"))
                    && List.of("DEPENDENCY_UNAVAILABLE").equals(body.get("reasonCodes")), "Database outage was not an explicit infrastructure error");
                ProcessRecoveryServer.publish(work.resolve("boundary.release"), "Attempt final commit while DB is down");
                awaitFile(work.resolve("execution.returned"), child, 30);
                check(child.isAlive(), "Backend unexpectedly exited during DB outage");
                pg = database(work.resolve("database"), port);
                row.put("restartedDatabaseProcessId", pg.getProcess().pid());
                var restored = snapshot(databaseUrl);
                row.put("afterDatabaseRestoreBeforeReaping", restored);
                check(before.equals(restored), "Failed DB access changed persistent policy/payment state");
            }
            child.destroyForcibly();
            check(child.waitFor(10, TimeUnit.SECONDS), "Child process did not terminate");
            row.put("killedProcessExitCode", child.exitValue());
            check(child.exitValue() != 0, "Abrupt child kill unexpectedly succeeded normally");
            releaseAgent.countDown();
            check(before.equals(snapshot(databaseUrl)), "Committed boundary did not survive actual process kill");
            config.put("phase", "recover");
            config.put("time", T0.plusSeconds(91).toString());
            Process restarted = launch(work, config);
            row.put("restartedProcessId", restarted.pid());
            check(restarted.pid() != child.pid(), "Restart did not create a new process");
            awaitFile(work.resolve("recover.port"), restarted, 60);
            ownedPorts.add(Integer.parseInt(Files.readString(work.resolve("recover.port"))));
            awaitFile(work.resolve("recovery.ready"), restarted, 30);
            var actual = snapshot(databaseUrl);
            row.put("actual", actual);
            row.put("recoveryEvidence", JSON.readValue(Files.readString(work.resolve("recovery.ready")), Map.class));
            row.put("kycHttpCallCount", calls.get());
            assertRecovered(scenario, actual, row);
            check(calls.get() == 1, "Restart repeated the original KYC provider request");
            row.put("verdict", "PASS");
            System.out.println("PROCESS_RECOVERY_CASE_PASS " + scenario);
        } catch (Throwable failure) {
            row.put("failure", failure.getClass().getSimpleName() + ": " + failure.getMessage());
            throw failure;
        } finally {
            releaseAgent.countDown();
            cleanup();
            row.put("completedAt", Instant.now().toString());
            writeReport(false);
        }
    }

    private EmbeddedPostgres database(Path directory, int port) throws Exception {
        var database = EmbeddedPostgres.builder().setDataDirectory(directory).setCleanDataDirectory(false)
            .setRegisterShutdownHook(false).setPort(port).setServerConfig("listen_addresses", "127.0.0.1")
            .setServerConfig("unix_socket_directories", "").start();
        databaseProcesses.add(database.getProcess());
        return database;
    }

    private Process launch(Path work, Map<String, Object> config) throws Exception {
        String phase = config.get("phase").toString();
        Path path = work.resolve(phase + "-config.json");
        Files.writeString(path, JSON.writeValueAsString(config));
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        var command = List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", System.getProperty("java.class.path"), ProcessRecoveryServer.class.getName(), path.toString());
        Process process = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(work.resolve(phase + ".log").toFile()).start();
        children.add(process);
        return process;
    }

    private static void awaitFile(Path path, Process process, int timeoutSeconds) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(timeoutSeconds).toNanos();
        while (!Files.exists(path)) {
            if (!process.isAlive()) throw new AssertionError("Child exited " + process.exitValue() + " before " + path.getFileName());
            if (System.nanoTime() >= deadline) throw new AssertionError("Timed out waiting for " + path.getFileName());
            Thread.sleep(25); // Readiness observation only; crash order is fixed by durable marker + DB read.
        }
    }

    private static Map<String, Object> snapshot(String url) throws Exception {
        var result = new LinkedHashMap<String, Object>();
        try (var connection = DriverManager.getConnection(url, "postgres", "")) {
            result.put("workflow", rows(connection, "select id,state,generation,used_risk,reserved_risk,last_decision,last_reason_code,current_kyc_result_id,current_loan_result_id from workflow"));
            result.put("stages", rows(connection, "select stage,run_count,used_points,reserved_points from workflow_stage order by stage"));
            result.put("jobs", rows(connection, "select id,phase,state,generation,execution_action_id,approval_id,run_id,lease_until,last_error from workflow_job order by phase,id"));
            result.put("runs", rows(connection, "select id,role,run_index,status from agent_run order by role,id"));
            result.put("riskLedger", rows(connection, "select stage,event_type,points,action_id from risk_ledger order by event_type,action_id"));
            result.put("payments", rows(connection, "select id,workflow_id,action_id,amount_krw from mock_payment order by id"));
            result.put("approvals", rows(connection, "select id,status,expires_at from approval order by id"));
            result.put("grants", rows(connection, "select id,status,expires_at,target_run_id from delegation_grant order by id"));
            result.put("reservations", rows(connection, "select id,status,job_id,grant_id,points from payment_reservation order by id"));
            result.put("actions", rows(connection, "select action_id,action_type,payload_hash,status,decision,result_json->>'paymentId' as payment_id from action_request order by action_id"));
            result.put("results", rows(connection, "select id,run_id,generation,status,result_hash from agent_result order by id"));
            result.put("audit", rows(connection, "select event_type,reason_code,created_at from audit_event order by created_at,event_type,id"));
            result.put("quarantineCount", number(connection, "select count(*) from quarantine"));
            result.put("actionCount", number(connection, "select count(*) from action_request"));
        }
        return result;
    }

    private static List<Map<String, Object>> rows(Connection connection, String sql) throws SQLException {
        var rows = new ArrayList<Map<String, Object>>();
        try (var statement = connection.createStatement(); var rs = statement.executeQuery(sql)) {
            var metadata = rs.getMetaData();
            while (rs.next()) {
                var row = new LinkedHashMap<String, Object>();
                for (int column = 1; column <= metadata.getColumnCount(); column++) {
                    Object value = rs.getObject(column);
                    row.put(metadata.getColumnLabel(column), value == null || value instanceof Number || value instanceof Boolean ? value : value.toString());
                }
                rows.add(row);
            }
        }
        return rows;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> list(Map<String, Object> snapshot, String name) { return (List<Map<String, Object>>) snapshot.get(name); }
    private static long number(Connection connection, String sql) throws SQLException {
        try (var statement = connection.createStatement(); var rs = statement.executeQuery(sql)) { rs.next(); return rs.getLong(1); }
    }
    private static String single(String url, String sql) throws SQLException {
        try (var connection = DriverManager.getConnection(url, "postgres", ""); var statement = connection.createStatement(); var rs = statement.executeQuery(sql)) { rs.next(); return rs.getString(1); }
    }
    private static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
    private static long count(Map<String, Object> snapshot, String event) { return list(snapshot, "riskLedger").stream().filter(row -> event.equals(row.get("event_type"))).count(); }

    private static void assertPrepared(String scenario, Map<String, Object> actual) {
        var workflow = list(actual, "workflow").getFirst();
        int used = "KYC_INFLIGHT".equals(scenario) ? 10 : "PAY_COMMITTED".equals(scenario) ? 85 : 35;
        int reserved = Set.of("PAY_RESERVED", "DB_UNAVAILABLE").contains(scenario) ? 50 : 0;
        check(((Number) workflow.get("used_risk")).intValue() == used && ((Number) workflow.get("reserved_risk")).intValue() == reserved, "Wrong committed pre-crash risk totals");
        check(list(actual, "payments").size() == ("PAY_COMMITTED".equals(scenario) ? 1 : 0), "Wrong payment count before crash");
        if (reserved == 50) check("PAYMENT_RESERVED".equals(workflow.get("state")) && count(actual, "RESERVE") == 1, "Reservation was not committed before crash");
        if ("KYC_INFLIGHT".equals(scenario)) check(list(actual, "runs").stream().anyMatch(row -> "KYC".equals(row.get("role")) && "RUNNING".equals(row.get("status"))), "KYC was not actually running");
    }

    @SuppressWarnings("unchecked")
    private static void assertRecovered(String scenario, Map<String, Object> actual, Map<String, Object> report) {
        var workflow = list(actual, "workflow").getFirst();
        boolean kyc = "KYC_INFLIGHT".equals(scenario), paid = "PAY_COMMITTED".equals(scenario), claimed = "PAY_CLAIM".equals(scenario);
        check((kyc ? "ON_HOLD" : paid ? "PAID" : "WAIT_APPROVAL").equals(workflow.get("state")), "Unexpected recovered workflow state");
        check(((Number) workflow.get("used_risk")).intValue() == (kyc ? 10 : paid ? 85 : 35), "Recovery changed consumed risk");
        check(((Number) workflow.get("reserved_risk")).intValue() == 0, "Recovery retained reservation risk");
        int ledgerUsed = list(actual, "riskLedger").stream()
            .filter(row -> Set.of("CHARGE", "CONSUME").contains(row.get("event_type")))
            .mapToInt(row -> ((Number) row.get("points")).intValue()).sum();
        int ledgerReserved = list(actual, "riskLedger").stream().mapToInt(row ->
            ("RESERVE".equals(row.get("event_type")) ? 1 : Set.of("RELEASE", "CONSUME").contains(row.get("event_type")) ? -1 : 0)
                * ((Number) row.get("points")).intValue()).sum();
        check(ledgerUsed == ((Number) workflow.get("used_risk")).intValue() && ledgerReserved == 0,
            "Risk caches diverged from append-only source ledger");
        check(count(actual, "CHARGE") == (kyc ? 1 : 2), "Restart duplicated the stage charges");
        check(list(actual, "stages").stream().mapToInt(row -> ((Number) row.get("used_points")).intValue()).sum() == ledgerUsed
            && list(actual, "stages").stream().allMatch(row -> ((Number) row.get("reserved_points")).intValue() == 0), "Stage and workflow accounting diverged");
        check(list(actual, "payments").size() == (paid ? 1 : 0) && count(actual, "CONSUME") == (paid ? 1 : 0), "Recovery duplicated or guessed a payment");
        check(count(actual, "RELEASE") == (kyc || paid || claimed ? 0 : 1), "Recovery release ledger is incorrect");
        check(((Number) actual.get("quarantineCount")).longValue() == 0, "Technical failure was misclassified as security quarantine");
        check(list(actual, "jobs").stream().noneMatch(row -> Set.of("RUNNING", "PENDING").contains(row.get("state"))), "Recovery left active jobs or auto-enqueued another run");
        check(list(actual, "stages").stream().filter(row -> "KYC".equals(row.get("stage"))).allMatch(row -> ((Number) row.get("run_count")).intValue() == 1), "Recovery repeated KYC execution");
        if (kyc) {
            check("ERROR".equals(workflow.get("last_decision")) && "DEPENDENCY_UNAVAILABLE".equals(workflow.get("last_reason_code")), "KYC crash was not an infrastructure hold");
            check(list(actual, "runs").size() == 1 && list(actual, "approvals").isEmpty(), "KYC crash created a downstream operation");
        } else if (!paid) {
            check("APPROVAL_REQUIRED".equals(workflow.get("last_reason_code")), "Unpaid PAY crash did not require fresh approval");
            check(list(actual, "approvals").size() == 1 && "REVOKED".equals(list(actual, "approvals").getFirst().get("status")), "Old approval was not revoked");
            if (!claimed) {
                var reservation = list(actual, "reservations").getFirst();
                check("RELEASED".equals(reservation.get("status")), "Old reservation was not released");
                check(list(actual, "grants").stream().anyMatch(grant -> grant.get("id").equals(reservation.get("grant_id")) && "EXPIRED".equals(grant.get("status"))), "Old PAY grant was refreshed instead of expired");
            } else check(list(actual, "reservations").isEmpty(), "Claim-only failure invented a reservation");
        } else {
            Map<String, Object> recovery = (Map<String, Object>) report.get("recoveryEvidence");
            Map<String, Object> receipt = (Map<String, Object>) recovery.get("receiptReplay");
            check("PAID".equals(receipt.get("state")) && Objects.equals(receipt.get("paymentId"), list(actual, "payments").getFirst().get("id")), "Lost-response replay did not return the persisted payment ID");
            Map<String, Object> before = (Map<String, Object>) report.get("beforeFailure");
            check(before.equals(actual), "Historical receipt retrieval changed ledger/action/approval state");
        }
    }

    private static Map<String, Object> expected(String scenario) {
        boolean kyc = "KYC_INFLIGHT".equals(scenario), paid = "PAY_COMMITTED".equals(scenario), claim = "PAY_CLAIM".equals(scenario);
        return Map.of("state", kyc ? "ON_HOLD" : paid ? "PAID" : "WAIT_APPROVAL", "usedRisk", kyc ? 10 : paid ? 85 : 35,
            "reservedRisk", 0, "paymentCount", paid ? 1 : 0, "consumeCount", paid ? 1 : 0,
            "releaseCount", kyc || paid || claim ? 0 : 1, "quarantineCount", 0, "kycHttpCallCount", 1);
    }

    private synchronized void cleanup() {
        for (Process process : children) {
            if (process.isAlive()) {
                process.destroy();
                try { if (!process.waitFor(8, TimeUnit.SECONDS)) { process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS); } }
                catch (InterruptedException interrupted) { process.destroyForcibly(); Thread.currentThread().interrupt(); }
            }
        }
        if (agent != null) { agent.stop(0); agent = null; }
        if (agentExecutor != null) { agentExecutor.shutdownNow(); agentExecutor = null; }
        if (pg != null) {
            try { pg.close(); } catch (Exception failure) { System.err.println("Owned PostgreSQL cleanup failed: " + failure.getClass().getSimpleName()); }
            if (pg.getProcess().isAlive()) pg.getProcess().destroyForcibly();
            pg = null;
        }
        // Keep every owned postmaster handle, including a database stopped for outage injection.
        // EmbeddedPostgres.close() logs some pg_ctl failures rather than rethrowing them.
        for (Process process : databaseProcesses) {
            if (process.isAlive()) {
                process.destroyForcibly();
                try { process.waitFor(5, TimeUnit.SECONDS); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            }
        }
    }

    private void writeReport(boolean completed) throws Exception {
        boolean cleaned = children.stream().noneMatch(Process::isAlive)
            && databaseProcesses.stream().noneMatch(Process::isAlive)
            && ownedPorts.stream().noneMatch(ProcessRecoveryHarness::portOpen);
        var document = new LinkedHashMap<String, Object>();
        document.put("schemaVersion", 1);
        document.put("status", completed && cleaned ? "PASS" : "INCOMPLETE_OR_FAILED");
        document.put("resultsSource", "REAL_POSTGRES_CHILD_JVM_CRASH_AND_OUTAGE");
        document.put("syntheticModelOutputs", true);
        document.put("liveRobustnessMeasured", false);
        document.put("scenarios", results);
        document.put("plannedScenarioCount", SCENARIOS.size());
        document.put("passedScenarioCount", results.stream().filter(row -> "PASS".equals(row.get("verdict"))).count());
        document.put("cleanupVerified", cleaned);
        document.put("notCovered", List.of("Whole T12 matrix is not claimed: SQL rollback is covered separately by WorkerRestartIT", "No real financial or external identity provider calls"));
        Files.createDirectories(report.getParent());
        ProcessRecoveryServer.publish(report, JSON.writerWithDefaultPrettyPrinter().writeValueAsString(document) + "\n");
        if (completed) check(cleaned, "Owned process or port remained after cleanup");
    }

    private static boolean portOpen(int port) {
        try (var socket = new Socket()) { socket.connect(new InetSocketAddress("127.0.0.1", port), 200); return true; }
        catch (Exception unavailable) { return false; }
    }
}
