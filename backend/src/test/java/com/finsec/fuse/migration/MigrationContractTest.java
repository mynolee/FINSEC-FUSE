package com.finsec.fuse.migration;

import com.finsec.fuse.config.RuntimeSchemaAdmission;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import static org.junit.jupiter.api.Assertions.*;

/** Configuration-only tests. No driver connection or application context is started. */
class MigrationContractTest {
    private static final String SYNTHETIC = "synthetic-unit-canary-" + "x".repeat(48);
    private static Map<String, Object> defaults() {
        var values = new HashMap<String, Object>();
        values.put("spring.datasource.url", "jdbc:postgresql://127.0.0.1:5432/fuse");
        values.put("spring.datasource.username", "fuse_runtime");
        values.put("spring.datasource.password", SYNTHETIC);
        values.put("spring.flyway.enabled", "false");
        values.put("spring.sql.init.mode", "never");
        values.put("spring.datasource.hikari.maximum-pool-size", "12");
        values.put("spring.datasource.hikari.connection-timeout", "5000");
        values.put("spring.datasource.hikari.connection-init-sql", "SET lock_timeout = '2s'; SET statement_timeout = '5s'");
        return values;
    }
    private static StandardEnvironment environment(Map<String, Object> values) {
        var environment = new StandardEnvironment();
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        environment.getPropertySources().addFirst(new MapPropertySource("synthetic", values));
        return environment;
    }

    @Test void canonicalEffectiveRuntimeConfigurationIsPrivateAndHasNoFallback() {
        var configuration = RuntimeSchemaAdmission.configuration(environment(defaults()));
        assertEquals("fuse_runtime", configuration.username());
        assertEquals("fuse", configuration.database());
        assertFalse(configuration.toString().contains(SYNTHETIC));
        assertFalse(configuration.toString().contains("127.0.0.1"));
        for (String key : new String[]{"spring.datasource.url", "spring.datasource.username", "spring.datasource.password",
                "spring.flyway.enabled", "spring.sql.init.mode", "spring.datasource.hikari.connection-init-sql"}) {
            var values = defaults(); values.remove(key);
            assertThrows(IllegalArgumentException.class, () -> RuntimeSchemaAdmission.configuration(environment(values)));
        }
    }

    @Test void migrationsSqlInitializersAndAlternateTargetsCannotBypassTheMainGate() {
        var attempts = Map.ofEntries(
                Map.entry("spring.flyway.enabled", "true"), Map.entry("spring.flyway.user", "fuse_owner"),
                Map.entry("FUSE_MIGRATE", "true"), Map.entry("FUSE_MIGRATION_PASSWORD", SYNTHETIC),
                Map.entry("FUSE_DB_OWNER_PASSWORD", SYNTHETIC), Map.entry("spring.datasource.username", "fuse_owner"),
                Map.entry("spring.datasource.jndi-name", "java:synthetic"), Map.entry("spring.datasource.type", "synthetic.Override"),
                Map.entry("spring.datasource.hikari.jdbc-url", "jdbc:postgresql://127.0.0.1:5432/other"),
                Map.entry("spring.datasource.hikari.username", "fuse_owner"), Map.entry("spring.datasource.hikari.schema", "other"),
                Map.entry("spring.datasource.hikari.data-source-properties.user", "fuse_owner"),
                Map.entry("spring.datasource.hikari.connection-init-sql", "SET search_path=other"),
                Map.entry("spring.sql.init.mode", "always"), Map.entry("spring.sql.init.username", "fuse_owner"),
                Map.entry("spring.sql.init.password", SYNTHETIC), Map.entry("spring.sql.init.schema-locations", "classpath:synthetic.sql"),
                Map.entry("spring.sql.init.data-locations", "classpath:synthetic.sql"));
        for (var entry : attempts.entrySet()) {
            var values = defaults(); values.put(entry.getKey(), entry.getValue());
            assertThrows(IllegalArgumentException.class, () -> RuntimeSchemaAdmission.configuration(environment(values)), entry.getKey());
        }
    }

    @Test void finalPropertyPrecedenceIsValidatedAndProfilesNeverDisableTheGate() {
        var environment = environment(defaults());
        environment.setActiveProfiles("test");
        environment.getPropertySources().addFirst(new MapPropertySource("higher-precedence", Map.of("spring.datasource.username", "fuse_owner")));
        assertThrows(IllegalArgumentException.class, () -> RuntimeSchemaAdmission.configuration(environment));
    }

    @Test void urlPropertiesCredentialsAndAmbiguousTargetsAreRejected() {
        for (String url : new String[]{"jdbc:postgresql:fuse", "jdbc:postgresql://localhost/fuse", "jdbc:postgresql://a:1,b:2/fuse",
                "jdbc:postgresql://user:secret@localhost:5432/fuse", "jdbc:postgresql://localhost:5432/fuse?user=fuse_owner",
                "jdbc:postgresql://localhost:5432/fuse?password=synthetic", "jdbc:postgresql://localhost:5432/fuse?options=-c%20search_path=x",
                "jdbc:postgresql://localhost:5432/fuse?currentSchema=other", "jdbc:postgresql://localhost:5432/fuse#fragment",
                "jdbc:postgresql://localhost:5432/f%75se", "jdbc:h2:mem:synthetic"})
            assertThrows(IllegalArgumentException.class, () -> BoundedPostgresDataSource.Configuration.parse(url, "fuse_runtime", SYNTHETIC));
    }

    @Test void unsupportedOperationsFailBeforeAnyConnectionOrCredentialUse() {
        for (String[] args : new String[][]{ {}, {"migrate-fresh"}, {"migrate"}, {"clean"}, {"repair"},
                {"migrate-fresh", "--new-install", "--new-install"}, {"migrate-fresh", "--password", SYNTHETIC},
                {"migrate-fresh", "--new-install", "--locations", "/tmp"} })
            assertThrows(IllegalArgumentException.class, () -> DatabaseMigrator.execute(args, Map.of()));
    }

    @Test void theResourceBoundaryContainsOnlyTheReviewedSevenSqlMigrations() throws Exception {
        MigrationContract.requirePackagedScripts();
        assertEquals(7, MigrationContract.SCRIPTS.size());
    }

    @Test void pinnedFlywayOptionsUseExplicitEmptyArraysWithoutOpeningAConnection() {
        var source = new BoundedPostgresDataSource(
                BoundedPostgresDataSource.Configuration.parse("jdbc:postgresql://127.0.0.1:5432/fuse", "fuse_runtime", SYNTHETIC), true);
        var configuration = MigrationContract.flyway(source);
        assertEquals(0, configuration.getIgnoreMigrationPatterns().length);
        assertArrayEquals(new String[0], configuration.getLoggers());
    }

    @Test void fixedEmptyDataQueryCoversEveryReviewedNonstructuralTableExactlyOnce() {
        var expected = new java.util.HashSet<>(MigrationContract.TABLES);
        expected.remove("flyway_schema_history");
        expected.remove("execution_gate");
        var actual = java.util.regex.Pattern.compile("FROM public\\.([a-z_]+)")
                .matcher(DatabaseMigrator.EMPTY_APPLICATION_TABLES).results().map(match -> match.group(1)).toList();
        assertEquals(expected.size(), actual.size());
        assertEquals(expected, new java.util.HashSet<>(actual));
    }
}
