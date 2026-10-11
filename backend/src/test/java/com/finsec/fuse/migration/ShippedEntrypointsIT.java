package com.finsec.fuse.migration;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.jar.*;
import java.util.zip.CRC32;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Invokes the actual packaged entrypoints; @SpringBootTest/test-classpath helpers are not substitutes. */
class ShippedEntrypointsIT {
    @TempDir Path work;
    private record Child(Process process, Path output, Path classes, int port) { }

    private Path artifact(String type) {
        String supplied = System.getProperty("fuse.test." + type + "Jar");
        assertNotNull(supplied, "Shipped artifact must be built by the integration task");
        Path path = Path.of(supplied); assertTrue(Files.isRegularFile(path)); return path;
    }
    private int unusedPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) { return socket.getLocalPort(); }
    }
    private Child launch(Path jar, Map<String, String> inputs, String... args) throws Exception {
        Files.setPosixFilePermissions(work, PosixFilePermissions.fromString("rwx------"));
        String id = UUID.randomUUID().toString();
        Path output = Files.createFile(work.resolve(id + ".log"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Path classes = Files.createFile(work.resolve(id + ".classes"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        int port = unusedPort();
        List<String> command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Xlog:class+load=info:file=" + classes, "-jar", jar.toString()));
        command.addAll(List.of(args));
        var builder = new ProcessBuilder(command);
        builder.environment().clear(); // No inherited database, token, provider or JVM injection environment.
        builder.environment().put("LANG", "C.UTF-8"); builder.environment().putAll(inputs);
        builder.environment().put("PORT", Integer.toString(port));
        builder.redirectErrorStream(true); builder.redirectOutput(output.toFile());
        return new Child(builder.start(), output, classes, port);
    }
    private String finish(Child child, boolean success, String... canaries) throws Exception {
        try {
            long deadline = System.nanoTime() + Duration.ofSeconds(45).toNanos();
            while (child.process().isAlive()) {
                try (Socket probe = new Socket()) {
                    try { probe.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), child.port()), 50); fail("Administrative/rejected process opened HTTP"); }
                    catch (ConnectException | SocketTimeoutException expected) { }
                }
                assertTrue(System.nanoTime() < deadline, "Shipped child did not exit within the test limit");
                child.process().waitFor(25, TimeUnit.MILLISECONDS);
            }
            assertEquals(success, child.process().exitValue() == 0, "Shipped entrypoint verdict differs; private diagnostics withheld");
            String output = Files.readString(child.output());
            for (String canary : canaries) assertFalse(output.contains(canary), "Private connection/configuration canary escaped");
            noServiceClasses(child);
            return output;
        } finally { if (child.process().isAlive()) { child.process().destroyForcibly(); child.process().waitFor(10, TimeUnit.SECONDS); } }
    }
    private void noServiceClasses(Child child) throws IOException {
        String classes = Files.readString(child.classes());
        for (String type : List.of("com.finsec.fuse.workflow.JobWorker ", "com.finsec.fuse.workflow.LeaseReaper ",
                "com.finsec.fuse.config.DemoSeed ", "com.finsec.fuse.experiments.ExperimentService ",
                "com.finsec.fuse.workflow.KycClient "))
            assertFalse(classes.contains(type), "Administrative process loaded an application context/service");
    }
    private void noApplicationClasses(Child child) throws IOException {
        noServiceClasses(child);
        assertFalse(Files.readString(child.classes()).contains("org.springframework.context.support.AbstractApplicationContext "),
                "Administrative process loaded an application context");
    }
    private Map<String, String> webEnvironment(DatabaseMigratorIT.Fixture fixture) throws Exception {
        Path key = Files.createFile(work.resolve(UUID.randomUUID() + ".key"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        byte[] bytes = new byte[32]; new java.security.SecureRandom().nextBytes(bytes); Files.write(key, bytes);
        var environment = new HashMap<String, String>();
        environment.put("SPRING_PROFILES_ACTIVE", "demo");
        environment.put("FUSE_DB_URL", fixture.url); environment.put("FUSE_DB_USERNAME", "fuse_runtime");
        environment.put("FUSE_DB_PASSWORD", fixture.runtimePassword); environment.put("FUSE_MIGRATE", "false");
        environment.put("FUSE_SIGNING_KEY_PATH", key.toString()); environment.put("FUSE_SIGNING_KEY_ID", "synthetic-entry-test");
        environment.put("FUSE_KYC_MODE", "replay"); environment.put("FUSE_KYC_BASE_URL", "http://127.0.0.1:1");
        for (String role : List.of("CUSTOMER_101", "CUSTOMER_102", "CUSTOMER_103", "CUSTOMER_104", "REVIEWER", "SECURITY", "DEVELOPER", "SERVICE"))
            environment.put("FUSE_" + role + "_TOKEN", UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", ""));
        return environment;
    }

    @Test void manifestsSelectSeparateMainsAndZeroArgumentAdminsFailWithoutServices() throws Exception {
        for (var entry : Map.of("web", "com.finsec.fuse.FuseApplication", "migration", "com.finsec.fuse.migration.DatabaseMigrator",
                "tokenAdmin", "com.finsec.fuse.auth.DemoTokenProvisioner").entrySet()) {
            try (JarFile jar = new JarFile(artifact(entry.getKey()).toFile())) {
                assertEquals(entry.getValue(), jar.getManifest().getMainAttributes().getValue("Start-Class"));
                assertEquals("21", jar.getManifest().getMainAttributes().getValue("Build-Jdk-Spec"));
                assertTrue(jar.getManifest().getMainAttributes().getValue("Main-Class").endsWith("JarLauncher"));
            }
        }
        for (String type : List.of("migration", "tokenAdmin")) {
            Child child = launch(artifact(type), Map.of()); finish(child, false); noApplicationClasses(child);
        }
    }

    @Test void shippedMigrationCompletesWithoutApplicationStartupAndConcurrentFreshAttemptRefuses() throws Exception {
        try (var fixture = new DatabaseMigratorIT.Fixture()) {
            Child first = launch(artifact("migration"), fixture.ownerEnvironment(), "migrate-fresh", "--new-install");
            Child second = launch(artifact("migration"), fixture.ownerEnvironment(), "migrate-fresh", "--new-install");
            try {
                // Monitor both live children, rather than probing only after waitFor has reaped them.
                long deadline = System.nanoTime() + Duration.ofSeconds(45).toNanos();
                while (first.process().isAlive() || second.process().isAlive()) {
                    for (Child child : List.of(first, second)) if (child.process().isAlive()) {
                        try (Socket probe = new Socket()) {
                            try { probe.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), child.port()), 50); fail("Migrator opened HTTP"); }
                            catch (ConnectException | SocketTimeoutException expected) { }
                        }
                    }
                    assertTrue(System.nanoTime() < deadline, "Concurrent fresh commands did not finish"); Thread.sleep(20);
                }
                int successful = (first.process().exitValue() == 0 ? 1 : 0) + (second.process().exitValue() == 0 ? 1 : 0);
                assertEquals(1, successful, "Exactly one owned fresh command may complete");
                for (Child child : List.of(first, second)) {
                    String output = finish(child, child.process().exitValue() == 0, fixture.url, fixture.ownerPassword, fixture.runtimePassword);
                    assertEquals(child.process().exitValue() == 0, output.contains("Migration COMPLETE:")); noApplicationClasses(child);
                }
                MigrationContract.validate(fixture.runtimeConfiguration(), "fuse_runtime");
            } finally { first.process().destroyForcibly(); second.process().destroyForcibly(); }
        }
    }

    @Test void shippedWebMainRejectsAbsentSchemaAndOverrideBeforeSeedRecoveryOrHttp() throws Exception {
        try (var fixture = new DatabaseMigratorIT.Fixture()) {
            var environment = webEnvironment(fixture);
            var freshBefore = fixture.snapshot();
            Child absent = launch(artifact("web"), environment);
            finish(absent, false, fixture.url, fixture.runtimePassword, fixture.ownerPassword);
            assertTrue(freshBefore.equals(fixture.snapshot()), "Missing schema must not trigger migration or seed");
            fixture.migrate();
            var before = fixture.snapshot();
            for (String override : List.of("--spring.flyway.enabled=true", "--spring.profiles.active=test",
                    "--spring.datasource.username=fuse_owner", "--spring.datasource.hikari.schema=other",
                    "--spring.sql.init.mode=always", "--spring.sql.init.username=fuse_owner",
                    "--spring.config.location=optional:classpath:/synthetic-missing-config.yml")) {
                Child child = launch(artifact("web"), environment, override);
                finish(child, false, fixture.url, fixture.runtimePassword, fixture.ownerPassword);
                assertTrue(before.equals(fixture.snapshot()), "Rejected main must preserve schema");
                assertUnseeded(fixture);
            }
            // CLI precedence must check the actual later target, not the already-compatible env target.
            try (var alternate = new DatabaseMigratorIT.Fixture()) {
                var alternateBefore = alternate.snapshot();
                Child redirected = launch(artifact("web"), environment, "--spring.datasource.url=" + alternate.url,
                        "--spring.datasource.password=" + alternate.runtimePassword);
                finish(redirected, false, fixture.url, alternate.url, fixture.runtimePassword, alternate.runtimePassword);
                assertTrue(alternateBefore.equals(alternate.snapshot())); assertUnseeded(fixture);
            }
            fixture.sql("UPDATE flyway_schema_history SET checksum=checksum+1 WHERE version='1'");
            Child mismatch = launch(artifact("web"), environment);
            finish(mismatch, false, fixture.url, fixture.runtimePassword, fixture.ownerPassword);
            assertUnseeded(fixture);
        }
    }

    private void assertUnseeded(DatabaseMigratorIT.Fixture fixture) throws SQLException {
        try (Connection c = fixture.owner(); Statement s = c.createStatement(); ResultSet rows = s.executeQuery(
            """
            SELECT (SELECT count(*) FROM mock_profile)=0 AND (SELECT count(*) FROM workflow)=0 \
            AND (SELECT count(*) FROM demo_auth_registry)=0 AND (SELECT count(*) FROM demo_token)=0\
            """)) {
            rows.next(); assertTrue(rows.getBoolean(1), "Rejected startup must not seed or issue authority");
        }
    }

    private void assertGroupedApplicationMigrationRolledBack(DatabaseMigratorIT.Fixture fixture) throws SQLException {
        try (Connection c = fixture.owner(); Statement s = c.createStatement()) {
            try (ResultSet r = s.executeQuery(
                """
                SELECT to_regclass('public.workflow') IS NULL AND to_regclass('public.execution_gate') IS NULL \
                AND to_regclass('public.demo_auth_registry') IS NULL AND to_regclass('public.demo_token') IS NULL\
                """)) {
                r.next(); assertTrue(r.getBoolean(1), "Grouped failed migration left application structures");
            }
            boolean history;
            try (ResultSet r = s.executeQuery("SELECT to_regclass('public.flyway_schema_history') IS NOT NULL")) { r.next(); history = r.getBoolean(1); }
            // Flyway housekeeping may survive; it must not claim a successfully applied migration.
            if (history) try (ResultSet r = s.executeQuery("SELECT count(*) FROM flyway_schema_history WHERE success")) {
                r.next(); assertEquals(0, r.getInt(1));
            }
        }
    }

    /** Owned fault-injection copy of a shipped artifact, never a modified source migration. */
    private Path faultArtifact(String suffix) throws IOException {
        Path destination = work.resolve(UUID.randomUUID() + ".jar");
        try (JarFile source = new JarFile(artifact("migration").toFile()); JarOutputStream output = new JarOutputStream(Files.newOutputStream(destination))) {
            var entries = source.entries(); boolean replaced = false;
            while (entries.hasMoreElements()) {
                var original = entries.nextElement(); byte[] bytes;
                try (InputStream stream = source.getInputStream(original)) { bytes = stream.readAllBytes(); }
                if (original.getName().equals("BOOT-INF/classes/db/migration/V3__immutable_agent_results.sql")) {
                    bytes = (new String(bytes, java.nio.charset.StandardCharsets.UTF_8) + "\n" + suffix + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8); replaced = true;
                }
                var entry = new JarEntry(original); CRC32 crc = new CRC32(); crc.update(bytes);
                entry.setSize(bytes.length); entry.setCrc(crc.getValue());
                if (entry.getMethod() == JarEntry.STORED) entry.setCompressedSize(bytes.length);
                else entry.setCompressedSize(-1);
                output.putNextEntry(entry); output.write(bytes); output.closeEntry();
            }
            assertTrue(replaced, "Controlled fault resource was not found in shipped artifact");
        }
        return destination;
    }
    private void awaitSleep(DatabaseMigratorIT.Fixture fixture) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        while (true) {
            try (Connection c = fixture.owner(); Statement s = c.createStatement(); ResultSet r = s.executeQuery(
                """
                SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname='fuse' \
                AND application_name='FINSEC-MIGRATION-ADMIN' AND state='active' AND query LIKE '%pg_sleep%')\
                """)) {
                r.next(); if (r.getBoolean(1)) return;
            }
            assertTrue(System.nanoTime() < deadline, "Controlled migration barrier was not observed"); Thread.sleep(20);
        }
    }

    @Test void failedMigrationAndKilledProcessNeverReportCompletionOrIssueAuthority() throws Exception {
        try (var fixture = new DatabaseMigratorIT.Fixture()) {
            Child failed = launch(faultArtifact("SELECT 1 / 0;"), fixture.ownerEnvironment(), "migrate-fresh", "--new-install");
            String output = finish(failed, false, fixture.url, fixture.ownerPassword);
            assertFalse(output.contains("Migration COMPLETE:"));
            assertGroupedApplicationMigrationRolledBack(fixture);
        }
        try (var fixture = new DatabaseMigratorIT.Fixture()) {
            Child killed = launch(faultArtifact("SELECT pg_sleep(8);"), fixture.ownerEnvironment(), "migrate-fresh", "--new-install");
            try { awaitSleep(fixture); killed.process().destroyForcibly(); assertTrue(killed.process().waitFor(15, TimeUnit.SECONDS));
                assertFalse(finish(killed, false, fixture.url, fixture.ownerPassword).contains("Migration COMPLETE:"));
                assertGroupedApplicationMigrationRolledBack(fixture);
            } finally { killed.process().destroyForcibly(); }
        }
    }

    @Test void lossOfCooperativeLockIsNotSuccessEvenWhenMigrationCommits() throws Exception {
        try (var fixture = new DatabaseMigratorIT.Fixture()) {
            Child child = launch(faultArtifact("SELECT pg_sleep(4);"), fixture.ownerEnvironment(), "migrate-fresh", "--new-install");
            try {
                awaitSleep(fixture);
                try (Connection c = fixture.owner(); PreparedStatement query = c.prepareStatement(
                        "SELECT pg_terminate_backend(l.pid) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid "
                        + "WHERE l.locktype='advisory' AND l.classid=?::oid AND l.objid=?::oid "
                        + "AND a.datname='fuse' AND a.application_name='FINSEC-MIGRATION-ADMIN'")) {
                    query.setLong(1, 0x46494e53L); query.setLong(2, 0x45430007L);
                    try (ResultSet rows = query.executeQuery()) { assertTrue(rows.next()); assertTrue(rows.getBoolean(1)); assertFalse(rows.next()); }
                }
                String output = finish(child, false, fixture.url, fixture.ownerPassword);
                assertFalse(output.contains("Migration COMPLETE:")); assertUnseeded(fixture);
                try (Connection c = fixture.owner()) { MigrationContract.requireExactHistory(c); }
            } finally { child.process().destroyForcibly(); }
        }
    }
}
