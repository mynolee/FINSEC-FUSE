package com.finsec.fuse.testing;

import com.finsec.fuse.FuseApplication;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.boot.SpringApplication;
import tools.jackson.databind.json.JsonMapper;

/** Test-classpath-only HTTP harness: fresh PostgreSQL 16.15, never an existing DB. */
public final class LocalSmokeServer {
    private LocalSmokeServer() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("Expected temporary config JSON and output port file");
        }
        var config = JsonMapper.builder().build()
            .readValue(Files.readString(Path.of(args[0])), Map.class);
        var agentUrl = URI.create(required(config, "agentBaseUrl"));
        if (!"http".equals(agentUrl.getScheme()) || !"127.0.0.1".equals(agentUrl.getHost())
                || agentUrl.getPort() < 1 || agentUrl.getPort() > 65535
                || agentUrl.getUserInfo() != null || agentUrl.getQuery() != null
                || agentUrl.getFragment() != null || !agentUrl.getPath().isEmpty()) {
            throw new IllegalArgumentException("The smoke KYC endpoint must be loopback HTTP");
        }
        boolean experiments = Boolean.TRUE.equals(config.get("experiments"));
        var options = new ArrayList<String>(List.of(
            "--spring.profiles.active=test", "--server.address=127.0.0.1", "--server.port=0",
            "--spring.datasource.url=" + PostgresSupport.url(),
            "--spring.datasource.username=postgres", "--spring.datasource.password=",
            "--spring.flyway.user=postgres", "--spring.flyway.password=",
            "--spring.flyway.enabled=true", "--fuse.demo-seed=true",
            "--fuse.worker-enabled=true", "--fuse.kyc-base-url=" + agentUrl,
            "--fuse.kyc-mode=replay", "--fuse.experiments.enabled=" + experiments,
            "--fuse.service-token=" + required(config, "service")));
        if (experiments) {
            // A distinct database in this ephemeral server; never the workflow database.
            try (var connection = DriverManager.getConnection(PostgresSupport.url(), "postgres", "");
                 var statement = connection.createStatement()) {
                statement.execute("CREATE DATABASE fuse_smoke_experiments");
            }
            var workflowUri = URI.create(PostgresSupport.url().substring("jdbc:".length()));
            var experimentUri = new URI("postgresql", null, workflowUri.getHost(),
                workflowUri.getPort(), "/fuse_smoke_experiments", null, null);
            options.add("--fuse.experiment-db-url=jdbc:" + experimentUri);
            options.add("--fuse.experiment-db-username=postgres");
            options.add("--fuse.experiment-db-password=");
        }
        for (String role : List.of("customer-101", "customer-102", "customer-103",
                                  "customer-104", "reviewer", "security", "developer")) {
            options.add("--fuse.auth." + role + "-token=" + required(config, role));
        }
        // This process owns a newly created PostgreSQL fixture. Bootstrap once before starting HTTP.
        var owner = new org.springframework.jdbc.datasource.DriverManagerDataSource(PostgresSupport.url(), "postgres", "");
        org.flywaydb.core.Flyway.configure().dataSource(owner).locations("classpath:db/migration").load().migrate();
        var fixtureTokens = new java.util.LinkedHashMap<String, String>();
        for (String role : List.of("customer-101", "customer-102", "customer-103", "customer-104", "reviewer", "security", "developer"))
            fixtureTokens.put(role, required(config, role));
        fixtureTokens.put("kyc-service", required(config, "service"));
        DemoTokenTestFixture.initializeOwned(owner, PostgresSupport.url(), fixtureTokens);
        var context = new SpringApplication(FuseApplication.class).run(options.toArray(String[]::new));
        // Publish only this process's actual bound port; the caller still checks readiness.
        var portFile = Path.of(args[1]);
        var pending = portFile.resolveSibling(portFile.getFileName() + ".pending");
        Files.writeString(pending, context.getEnvironment().getRequiredProperty("local.server.port"));
        Files.move(pending, portFile, StandardCopyOption.ATOMIC_MOVE);
    }

    private static String required(Map<?, ?> config, String key) {
        if (config.get(key) instanceof String value && !value.isBlank()) return value;
        throw new IllegalArgumentException("Missing smoke config field: " + key);
    }
}
