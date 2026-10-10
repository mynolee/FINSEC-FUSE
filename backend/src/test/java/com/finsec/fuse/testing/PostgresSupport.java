package com.finsec.fuse.testing;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import org.springframework.test.context.DynamicPropertyRegistry;

/** A real PostgreSQL 16.15 process, not an in-memory SQL approximation. */
public final class PostgresSupport {
    private static final java.util.Map<String,String> TOKENS = new java.util.HashMap<>();
    private static synchronized String token(String role) { return TOKENS.computeIfAbsent(role, ignored -> com.finsec.fuse.auth.DevActorRegistry.generateToken()); }
    private static final EmbeddedPostgres PG = start();
    private PostgresSupport() {}
    private static EmbeddedPostgres start() {
        try {
            var pg = EmbeddedPostgres.builder().setPort(0).setServerConfig("unix_socket_directories", "").start();
            try (Connection c=pg.getPostgresDatabase().getConnection();
                 ResultSet rs=c.createStatement().executeQuery("SHOW server_version")) {
                rs.next();
                if(!rs.getString(1).startsWith("16.15")) throw new IllegalStateException("PostgreSQL 16.15 required, got "+rs.getString(1));
            }
            Runtime.getRuntime().addShutdownHook(new Thread(()->{try {pg.close();}catch(IOException ignored){}}));
            return pg;
        } catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }
    public static String url() { return PG.getJdbcUrl("postgres","postgres"); }
    public static void initializeAuth(javax.sql.DataSource dataSource, org.springframework.core.env.Environment environment) {
        DemoTokenTestFixture.initializeOwned(dataSource, url(), environment);
    }
    public static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", PostgresSupport::url);
        registry.add("spring.datasource.username", ()->"postgres");
        registry.add("spring.datasource.password", ()->"");
        registry.add("spring.flyway.user", ()->"postgres");
        registry.add("spring.flyway.password", ()->"");
        registry.add("fuse.worker-enabled", ()->"false");
        registry.add("fuse.experiments.enabled", ()->"false");
        // Override every alias the registry reads; inherited development credentials are never fixtures.
        for(String role:java.util.List.of("customer-101","customer-102","customer-103","customer-104","reviewer","security","developer")) {
            String suffix=role.toUpperCase(java.util.Locale.ROOT).replace('-','_');
            registry.add("fuse.auth."+role+"-token", ()->token(role));
            registry.add("FUSE_DEV_"+suffix+"_TOKEN", ()->token(role));
            registry.add("FUSE_"+suffix+"_TOKEN", ()->token(role));
        }
        registry.add("FUSE_REVIEWER_CUSTOMERS", ()->"customer-101,customer-102,customer-103,customer-104");
        registry.add("FUSE_SECURITY_CUSTOMERS", ()->"customer-101,customer-102,customer-103,customer-104");
        registry.add("fuse.service-token", ()->token("kyc-service"));
        registry.add("FUSE_SERVICE_TOKEN", ()->token("kyc-service"));
    }
}
