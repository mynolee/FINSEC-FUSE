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
    public static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", PostgresSupport::url);
        registry.add("spring.datasource.username", ()->"postgres");
        registry.add("spring.datasource.password", ()->"");
        registry.add("spring.flyway.user", ()->"postgres");
        registry.add("spring.flyway.password", ()->"");
        registry.add("fuse.worker-enabled", ()->"false");
        registry.add("fuse.experiments.enabled", ()->"false");
        registry.add("fuse.auth.customer-101-token", ()->token("customer-101"));
        registry.add("fuse.auth.customer-102-token", ()->token("customer-102"));
        registry.add("fuse.auth.reviewer-token", ()->token("reviewer"));
        registry.add("fuse.auth.security-token", ()->token("security"));
        registry.add("fuse.auth.developer-token", ()->token("developer"));
        registry.add("fuse.service-token", ()->token("kyc-service"));
    }
}
