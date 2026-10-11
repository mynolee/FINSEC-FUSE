package com.finsec.fuse.migration;

import java.sql.*;
import java.util.Map;

/** Explicit fresh-only administration. No Spring, HTTP, worker, recovery, seed or token initialization. */
public final class DatabaseMigrator {
    private DatabaseMigrator() { }
    private static final long LOCK = 0x46494e5345430007L;

    public static void main(String[] args) {
        try {
            execute(args, System.getenv());
            System.out.println("Migration COMPLETE: schema=7 migrations=7. Authentication remains uninitialized.");
        } catch (Exception failure) {
            System.err.println("Migration NOT_CONFIRMED. Preserve private diagnostics and reconcile the database before any retry. No cleanup was performed.");
            System.exit(1);
        }
    }

    public static void execute(String[] args, Map<String, String> environment) throws Exception {
        if (args.length != 2 || !"migrate-fresh".equals(args[0]) || !"--new-install".equals(args[1]))
            throw new IllegalArgumentException("Explicit fresh migration operation required");
        var configuration = BoundedPostgresDataSource.Configuration.parse(environment.get("FUSE_DB_URL"),
                environment.get("FUSE_MIGRATION_USERNAME"), environment.get("FUSE_MIGRATION_PASSWORD"));
        if (!"fuse".equals(configuration.database()) || !"fuse_owner".equals(configuration.username()))
            throw new IllegalArgumentException("The standard installation owner and database are required");
        MigrationContract.requirePackagedScripts();
        var owner = new BoundedPostgresDataSource(configuration, false);
        try (Connection lock = owner.getConnection()) {
            try (PreparedStatement query = lock.prepareStatement("SELECT pg_try_advisory_lock(?)")) {
                query.setLong(1, LOCK);
                try (ResultSet rows = query.executeQuery()) {
                    if (!rows.next() || !rows.getBoolean(1)) throw MigrationContract.rejected();
                }
            }
            // This lock coordinates this tool, not arbitrary administrators. No application may be running.
            MigrationContract.requireFresh(lock);
            var plan = MigrationContract.flyway(new BoundedPostgresDataSource(configuration, true)).load().info().all();
            if (plan.length != MigrationContract.SCRIPTS.size()) throw MigrationContract.rejected();
            for (int i = 0; i < plan.length; i++) {
                if (plan[i].getVersion() == null || !Integer.toString(i + 1).equals(plan[i].getVersion().getVersion())
                        || !MigrationContract.SCRIPTS.get(i).equals(plan[i].getScript())
                        || !"SQL".equals(plan[i].getType().toString()) || !"PENDING".equals(plan[i].getState().name()))
                    throw MigrationContract.rejected();
            }
            var result = MigrationContract.flyway(owner).load().migrate();
            if (result.migrationsExecuted != MigrationContract.SCRIPTS.size()) throw MigrationContract.rejected();
            MigrationContract.validate(configuration, "fuse_runtime");
            try (Statement query = lock.createStatement(); ResultSet rows = query.executeQuery(
                    "SELECT (SELECT count(*) FROM demo_auth_registry)=0 AND (SELECT count(*) FROM demo_token)=0 "
                    + "AND (SELECT count(*) FROM execution_gate WHERE id=1 AND epoch=0)=1")) {
                if (!rows.next() || !rows.getBoolean(1)) throw MigrationContract.rejected();
            }
            for (String table : MigrationContract.TABLES) {
                if (table.equals("flyway_schema_history") || table.equals("execution_gate")) continue;
                try (Statement query = lock.createStatement(); ResultSet rows = query.executeQuery("SELECT count(*)=0 FROM public.\"" + table + "\"")) {
                    if (!rows.next() || !rows.getBoolean(1)) throw MigrationContract.rejected();
                }
            }
            // Losing the independent lock session is an unconfirmed outcome, even if Flyway committed.
            try (PreparedStatement query = lock.prepareStatement("SELECT pg_advisory_unlock(?)")) {
                query.setLong(1, LOCK);
                try (ResultSet rows = query.executeQuery()) { if (!rows.next() || !rows.getBoolean(1)) throw MigrationContract.rejected(); }
            }
        }
    }
}
