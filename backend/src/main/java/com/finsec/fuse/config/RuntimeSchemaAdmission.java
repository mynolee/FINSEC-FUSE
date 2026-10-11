package com.finsec.fuse.config;

import com.finsec.fuse.migration.BoundedPostgresDataSource;
import com.finsec.fuse.migration.MigrationContract;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;

/** Mandatory shipped-main preflight, before refresh, bean construction, HTTP, seed or recovery. */
public final class RuntimeSchemaAdmission implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    private static final String TIMEOUT_SQL = "SET lock_timeout = '2s'; SET statement_timeout = '5s'";

    @Override public void initialize(ConfigurableApplicationContext context) {
        try {
            var configuration = configuration(context.getEnvironment());
            MigrationContract.validate(configuration, configuration.username());
        } catch (Exception rejected) {
            // No cause: a binder/driver/Flyway exception can contain private configuration or a URL.
            throw new IllegalStateException("Database startup compatibility is unavailable. Complete approved offline setup or reconcile the existing database; runtime did not migrate it.");
        }
    }

    public static BoundedPostgresDataSource.Configuration configuration(ConfigurableEnvironment environment) {
        Binder binder = Binder.get(environment);
        // Missing values are not false: replacing application.yml must not restore Boot defaults.
        if (binder.bind("spring.flyway.enabled", Boolean.class).orElse(true))
            throw new IllegalArgumentException("Application startup cannot migrate the main database");
        String migrate = environment.getProperty("FUSE_MIGRATE");
        if (migrate != null && !migrate.isBlank() && !"false".equalsIgnoreCase(migrate))
            throw new IllegalArgumentException("Application startup cannot migrate the main database");
        for (String name : Set.of("FUSE_MIGRATION_USERNAME", "FUSE_MIGRATION_PASSWORD", "FUSE_DB_OWNER_PASSWORD"))
            if (!environment.getProperty(name, "").isBlank())
                throw new IllegalArgumentException("Main database owner configuration is not runtime configuration");
        Map<String, Object> datasource = binder.bind("spring.datasource", Bindable.mapOf(String.class, Object.class)).orElse(Map.of());
        requireKeys(datasource, Set.of("url", "username", "password", "hikari"));
        Map<String, Object> flyway = binder.bind("spring.flyway", Bindable.mapOf(String.class, Object.class)).orElse(Map.of());
        requireKeys(flyway, Set.of("enabled"));
        // Boot SQL initialization has its own credentials/locations and can bypass datasource-only checks.
        Map<String, Object> sqlInit = binder.bind("spring.sql.init", Bindable.mapOf(String.class, Object.class)).orElse(Map.of());
        requireKeys(sqlInit, Set.of("mode"));
        if (!"never".equalsIgnoreCase(binder.bind("spring.sql.init.mode", String.class).orElse("")))
            throw new IllegalArgumentException("Runtime SQL initialization is forbidden");
        Map<String, Object> hikari = binder.bind("spring.datasource.hikari", Bindable.mapOf(String.class, Object.class)).orElse(Map.of());
        // Reject JDBC URL/user/password/schema/catalog/JNDI/dataSourceProperties overrides and unknown aliases.
        requireKeys(hikari, Set.of("maximumpoolsize", "connectiontimeout", "connectioninitsql"));
        if (!TIMEOUT_SQL.equals(binder.bind("spring.datasource.hikari.connection-init-sql", String.class).orElse("")))
            throw new IllegalArgumentException("Runtime initialization SQL is fixed");
        var configuration = BoundedPostgresDataSource.Configuration.parse(
                binder.bind("spring.datasource.url", String.class).orElse(null),
                binder.bind("spring.datasource.username", String.class).orElse(null),
                binder.bind("spring.datasource.password", String.class).orElse(null));
        if (Set.of("fuse_owner", "postgres", "fuse_experiment_owner").contains(configuration.username()))
            throw new IllegalArgumentException("A separate least-privilege runtime identity is required");
        return configuration;
    }

    private static void requireKeys(Map<String, Object> values, Set<String> allowed) {
        for (String key : values.keySet())
            if (!allowed.contains(key.replace("-", "").replace("_", "").toLowerCase(java.util.Locale.ROOT)))
                throw new IllegalArgumentException("Unsupported runtime database override");
    }
}
