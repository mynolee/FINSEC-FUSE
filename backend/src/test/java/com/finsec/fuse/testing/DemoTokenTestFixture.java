package com.finsec.fuse.testing;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.AdmissionLimiter;
import com.finsec.fuse.auth.DemoAuthFilter;
import com.finsec.fuse.auth.DemoTokenAdministration;
import com.finsec.fuse.auth.DemoTokenStore;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.auth.JdbcDemoTokenStore;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.config.SecurityPolicy;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.sql.DataSource;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;

/** Explicit synthetic setup only. Never discovered by Spring and never used by production admission. */
public final class DemoTokenTestFixture {
    private final MemoryStore memory;
    private final DataSource dataSource;
    private final String ownedUrl;
    private final DevActorRegistry registry;

    public DemoTokenTestFixture(Environment environment, SecurityPolicy policy, Clock clock) {
        memory = new MemoryStore(clock, policy.devTokenTtlSeconds());
        dataSource = null;
        ownedUrl = null;
        registry = new DevActorRegistry(environment, policy, memory);
        for (var binding : registry.configuredBindings()) memory.issue(binding);
    }

    private DemoTokenTestFixture(DataSource dataSource, String ownedUrl) {
        this.memory = null;
        this.dataSource = dataSource;
        this.ownedUrl = ownedUrl;
        this.registry = null;
        withOwner(connection -> { });
    }

    public static DemoTokenTestFixture owner(DataSource dataSource, String ownedUrl) {
        return new DemoTokenTestFixture(dataSource, ownedUrl);
    }

    public DevActorRegistry registry() { return registry; }

    public static DemoAuthFilter filter(Environment environment, Json json) {
        var policy = policy(json);
        var fixture = new DemoTokenTestFixture(environment, policy, Clock.systemUTC());
        return new DemoAuthFilter(fixture.registry(), new AdmissionLimiter(policy), json);
    }

    public static void initializeOwned(DataSource dataSource, String ownedUrl, Environment environment) {
        var json = new Json(new JsonConfiguration().jsonMapper());
        var registry = new DevActorRegistry(environment, policy(json),
                new JdbcDemoTokenStore(new JdbcTemplate(dataSource)));
        owner(dataSource, ownedUrl).withOwner(connection ->
                DemoTokenAdministration.initialize(connection, registry.configuredBindings()));
    }

    /** Caller has just created/migrated this exact ephemeral PostgreSQL database. */
    public static void initializeOwned(DataSource dataSource, String ownedUrl, Map<String, String> tokens) {
        var environment = new MockEnvironment();
        environment.setActiveProfiles("test");
        tokens.forEach((role, token) -> environment.setProperty(
                role.equals("kyc-service") ? "fuse.service-token" : "fuse.auth." + role + "-token", token));
        initializeOwned(dataSource, ownedUrl, environment);
    }

    java.time.Instant authorityNow() {
        try (var connection = dataSource.getConnection()) {
            if (!ownedUrl.equals(connection.getMetaData().getURL()))
                throw new IllegalStateException("Refusing clock probe outside the owned database");
            try (var statement = connection.createStatement(); var rows = statement.executeQuery("SELECT clock_timestamp()")) {
                if (!rows.next()) throw new IllegalStateException("Missing synthetic authority clock");
                return rows.getTimestamp(1).toInstant();
            }
        } catch (SQLException failure) { throw new IllegalStateException("Synthetic authority clock unavailable", failure); }
    }

    public void issue(String token, Actor actor) {
        if (!DevActorRegistry.validToken(token)) throw new IllegalArgumentException("Invalid synthetic credential");
        var binding = new DemoTokenStore.Binding(DevActorRegistry.fingerprint(token), actor);
        if (memory != null) memory.issue(binding);
        else withOwner(connection -> DemoTokenAdministration.issue(connection, binding, Set.of()));
    }

    public void revoke(String actorId) {
        if (memory != null) memory.replace(actorId, null, true);
        else withOwner(connection -> DemoTokenAdministration.revokeActor(connection, actorId));
    }

    public void updateScope(String actorId, Set<String> scope) {
        if (memory != null) memory.replace(actorId, Set.copyOf(scope), false);
        else withOwner(connection -> DemoTokenAdministration.updateScope(connection, actorId, scope));
    }

    private interface OwnerAction { void apply(Connection connection) throws SQLException; }
    private void withOwner(OwnerAction action) {
        try (var connection = dataSource.getConnection()) {
            if (!ownedUrl.equals(connection.getMetaData().getURL()))
                throw new IllegalStateException("Refusing fixture administration outside the owned database");
            action.apply(connection);
        } catch (SQLException failure) {
            throw new IllegalStateException("Synthetic credential fixture operation failed", failure);
        }
    }

    private static SecurityPolicy policy(Json json) {
        try { return new JsonConfiguration().securityPolicy(json.mapper()); }
        catch (java.io.IOException failure) { throw new IllegalStateException("Test security policy unavailable", failure); }
    }

    /** Policy-test double only: no claim of JDBC persistence, process survival, or database time. */
    private static final class MemoryStore implements DemoTokenStore {
        private final Clock clock;
        private final int ttl;
        private final Map<String, Credential> rows = new LinkedHashMap<>();
        private MemoryStore(Clock clock, int ttl) { this.clock = clock; this.ttl = ttl; }
        private synchronized void issue(Binding binding) {
            if (rows.containsKey(binding.fingerprint())) throw new IllegalStateException("Duplicate synthetic credential");
            var now = clock.instant();
            rows.put(binding.fingerprint(), new Credential(binding.fingerprint(), binding.actor(),
                    binding.actor().customerIds(), now, now.plusSeconds(ttl), Status.ACTIVE, null, 0));
        }
        private synchronized void replace(String actorId, Set<String> scope, boolean revoke) {
            rows.replaceAll((fingerprint, row) -> {
                if (!row.initialActor().actorId().equals(actorId)) return row;
                if (revoke && row.status() == Status.REVOKED) return row;
                if (!revoke && row.currentScope().equals(scope)) return row;
                return new Credential(fingerprint, row.initialActor(), scope == null ? row.currentScope() : scope,
                        row.issuedAt(), row.expiresAt(), revoke ? Status.REVOKED : row.status(),
                        revoke ? clock.instant() : row.revokedAt(), row.revision() + 1);
            });
        }
        @Override public synchronized Snapshot lookup(String fingerprint, List<Binding> configured) {
            for (var binding : configured) {
                var row = rows.get(binding.fingerprint());
                if (row == null || !row.initialActor().equals(binding.actor())) throw new Unavailable();
            }
            return new Snapshot(clock.instant(), fingerprint == null ? null : rows.get(fingerprint));
        }
    }
}
