package com.finsec.fuse.migration;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.jdbc.datasource.init.ScriptUtils;
import static org.junit.jupiter.api.Assertions.*;

/** Each fixture owns a new PG16.15 process, standard roles and database. No inherited DB/environment. */
class DatabaseMigratorIT {
    static final class Fixture implements AutoCloseable {
        final EmbeddedPostgres postgres;
        final String url;
        final String ownerPassword = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
        final String runtimePassword = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
        Fixture() throws Exception {
            postgres = EmbeddedPostgres.builder().setPort(0).setServerConfig("unix_socket_directories", "").start();
            try {
            String admin = postgres.getJdbcUrl("postgres", "postgres").split("\\?", 2)[0];
            url = admin.substring(0, admin.lastIndexOf('/') + 1) + "fuse";
            try (Connection c = DriverManager.getConnection(admin, "postgres", ""); Statement s = c.createStatement()) {
                try (ResultSet rows = s.executeQuery("SHOW server_version")) { rows.next(); assertTrue(rows.getString(1).startsWith("16.15")); }
                // Mirrors the official local image's initial administrative identity, only inside this owned cluster.
                s.execute("CREATE ROLE fuse_owner LOGIN SUPERUSER PASSWORD '" + ownerPassword + "'");
                s.execute("CREATE DATABASE fuse OWNER fuse_owner");
            }
            Path script = Path.of("../scripts/init-postgres.sh");
            if (!Files.isRegularFile(script)) script = Path.of("scripts/init-postgres.sh");
            String source = Files.readString(script), marker = "<<'SQL'\n";
            int start = source.indexOf(marker), end = source.lastIndexOf("\nSQL");
            if (start < 0 || end <= start) throw new IllegalStateException("Bootstrap SQL is unavailable");
            String sql = source.substring(start + marker.length(), end).replace(":'runtime_password'", "'" + runtimePassword + "'")
                    .replace(":'experiment_password'", "'" + UUID.randomUUID().toString().replace("-", "") + "'");
            try (Connection c = owner()) { ScriptUtils.executeSqlScript(c, new ByteArrayResource(sql.getBytes(java.nio.charset.StandardCharsets.UTF_8))); }
            } catch (Exception | Error failure) {
                try { postgres.close(); } catch (Exception cleanup) { failure.addSuppressed(cleanup); }
                throw failure;
            }
        }
        Connection owner() throws SQLException { return DriverManager.getConnection(url, "fuse_owner", ownerPassword); }
        Map<String, String> ownerEnvironment() { return Map.of("FUSE_DB_URL", url, "FUSE_MIGRATION_USERNAME", "fuse_owner", "FUSE_MIGRATION_PASSWORD", ownerPassword); }
        BoundedPostgresDataSource.Configuration runtimeConfiguration() { return BoundedPostgresDataSource.Configuration.parse(url, "fuse_runtime", runtimePassword); }
        void migrate() throws Exception { DatabaseMigrator.execute(new String[]{"migrate-fresh", "--new-install"}, ownerEnvironment()); }
        void sql(String sql) throws SQLException { try (Connection c = owner(); Statement s = c.createStatement()) { s.execute(sql); } }
        List<String> snapshot() throws SQLException {
            // Catalog definitions and all ordinary public rows, kept in memory only.
            // This is a logical preservation oracle, not a physical database-byte comparison.
            List<String> rows = new ArrayList<>();
            try (Connection c = owner(); Statement s = c.createStatement()) {
                for (String query : List.of(
                        "SELECT 'namespace:'||row_to_json(n)::text FROM pg_namespace n WHERE nspname NOT IN ('pg_catalog','pg_toast','information_schema')",
                        "SELECT 'class:'||row_to_json(c)::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'",
                        "SELECT 'function:'||pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'",
                        "SELECT 'type:'||row_to_json(t)::text FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public'",
                        "SELECT 'collation:'||row_to_json(o)::text FROM pg_collation o JOIN pg_namespace n ON n.oid=o.collnamespace WHERE n.nspname='public'",
                        "SELECT 'operator:'||row_to_json(o)::text FROM pg_operator o JOIN pg_namespace n ON n.oid=o.oprnamespace WHERE n.nspname='public'",
                        "SELECT 'default-acl:'||row_to_json(a)::text FROM pg_default_acl a")) {
                    try (ResultSet r = s.executeQuery(query + " ORDER BY 1")) { while (r.next()) rows.add(r.getString(1)); }
                }
                List<String> tables = new ArrayList<>();
                try (ResultSet r = s.executeQuery("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' ORDER BY c.relname")) {
                    while (r.next()) tables.add(r.getString(1));
                }
                for (String table : tables) {
                    String identifier = "\"" + table.replace("\"", "\"\"") + "\"";
                    try (ResultSet r = s.executeQuery("SELECT to_jsonb(t)::text FROM public." + identifier + " t ORDER BY 1")) {
                        while (r.next()) rows.add("row:" + table + ":" + r.getString(1));
                    }
                }
            }
            return rows;
        }
        @Override public void close() throws Exception { postgres.close(); }
    }

    @Test void freshMigrationLeavesOnlyStructuralRowsAndReadOnlyHistoryPrivileges() throws Exception {
        try (var fixture = new Fixture()) {
            fixture.migrate();
            MigrationContract.validate(fixture.runtimeConfiguration(), "fuse_runtime");
            try (Connection c = fixture.owner(); Statement s = c.createStatement()) {
                for (String table : MigrationContract.TABLES) {
                    try (ResultSet r = s.executeQuery("SELECT count(*) FROM public.\"" + table + "\"")) {
                        r.next(); assertEquals(table.equals("flyway_schema_history") ? 7 : table.equals("execution_gate") ? 1 : 0, r.getInt(1));
                    }
                }
            }
            var before = fixture.snapshot();
            assertThrows(Exception.class, fixture::migrate);
            assertTrue(before.equals(fixture.snapshot()), "A repeated fresh command must preserve existing schema");
        }
    }

    @Test void nonemptyHistoryFunctionTypeCollationOperatorAndExtraSchemaAreNotFresh() throws Exception {
        for (String statement : List.of("CREATE TABLE unrelated(id integer)", "CREATE TABLE flyway_schema_history(id integer)",
                "CREATE FUNCTION unrelated() RETURNS integer LANGUAGE sql AS 'SELECT 1'", "CREATE TYPE unrelated AS ENUM ('x')",
                "CREATE COLLATION unrelated (provider=libc,locale='C')",
                "CREATE OPERATOR public.## (LEFTARG=integer,RIGHTARG=integer,FUNCTION=pg_catalog.int4pl)",
                "CREATE SCHEMA unrelated", "CREATE SCHEMA pgcustom",
                "ALTER DEFAULT PRIVILEGES FOR ROLE fuse_owner IN SCHEMA public GRANT SELECT ON TABLES TO fuse_experiment_owner",
                "ALTER DEFAULT PRIVILEGES FOR ROLE fuse_owner GRANT SELECT ON TABLES TO fuse_runtime")) {
            try (var fixture = new Fixture()) {
                fixture.sql(statement); var before = fixture.snapshot();
                assertThrows(Exception.class, fixture::migrate);
                assertTrue(before.equals(fixture.snapshot()), "Nonfresh refusal must preserve observed catalogs and data");
                try (Connection c = fixture.owner(); Statement s = c.createStatement(); ResultSet r = s.executeQuery("SELECT to_regclass('public.demo_token') IS NULL")) {
                    r.next(); assertTrue(r.getBoolean(1));
                }
            }
        }
    }

    @Test void invalidBootstrapRuntimeAuthorityIsRejectedBeforeAnyMigration() throws Exception {
        for (String statement : List.of("ALTER ROLE fuse_runtime SUPERUSER", "ALTER ROLE fuse_runtime CREATEDB",
                "GRANT CREATE ON DATABASE fuse TO fuse_runtime", "GRANT CREATE ON SCHEMA public TO fuse_runtime",
                "GRANT fuse_owner TO fuse_runtime WITH INHERIT FALSE, SET TRUE")) {
            try (var fixture = new Fixture()) {
                fixture.sql(statement); var before = fixture.snapshot();
                assertThrows(Exception.class, fixture::migrate);
                assertTrue(before.equals(fixture.snapshot()), "Invalid runtime authority must refuse before schema changes");
                try (Connection c = fixture.owner(); Statement s = c.createStatement(); ResultSet r = s.executeQuery(
                        "SELECT to_regclass('public.flyway_schema_history') IS NULL AND to_regclass('public.workflow') IS NULL")) {
                    r.next(); assertTrue(r.getBoolean(1));
                }
            }
        }
    }

    @Test void everyValidatorConnectionIsServerReadOnlyIncludingAutocommitAndCannotUnwrap() throws Exception {
        try (var fixture = new Fixture()) {
            fixture.migrate();
            var source = new BoundedPostgresDataSource(fixture.runtimeConfiguration(), true);
            for (boolean autocommit : List.of(true, false)) try (Connection c = source.getConnection()) {
                c.setAutoCommit(autocommit);
                assertSame(c, c.getMetaData().getConnection());
                try (Statement s = c.createStatement()) {
                    assertSame(c, s.getConnection());
                    try (ResultSet r = s.executeQuery("SHOW transaction_read_only")) { r.next(); assertEquals("on", r.getString(1)); assertSame(s, r.getStatement()); }
                    SQLException denied = assertThrows(SQLException.class, () -> s.executeUpdate("INSERT INTO mock_profile(customer_id,monthly_income_krw,max_loan_amount_krw,profile_hash) VALUES('readonly-probe',1,2,'synthetic')"));
                    assertEquals("25006", denied.getSQLState());
                }
                if (!autocommit) c.rollback();
                assertThrows(SQLException.class, () -> c.setReadOnly(false));
                assertSame(c, c.unwrap(Connection.class));
                assertThrows(SQLException.class, () -> c.unwrap(Class.forName("org.postgresql.PGConnection")));
            }
        }
    }

    @Test void historyMutationMissingObjectsWrongSchemaAndNoInheritOwnerMembershipFailClosed() throws Exception {
        for (String tamper : List.of("GRANT UPDATE ON flyway_schema_history TO fuse_runtime",
                "GRANT UPDATE(checksum) ON flyway_schema_history TO fuse_runtime",
                "GRANT UPDATE(revision) ON demo_token TO fuse_runtime",
                "GRANT CREATE ON DATABASE fuse TO fuse_runtime",
                "ALTER TABLE demo_token DISABLE TRIGGER demo_token_immutable", "DROP TABLE workflow_job CASCADE",
                "UPDATE flyway_schema_history SET checksum=checksum+1 WHERE version='1'",
                "INSERT INTO flyway_schema_history(installed_rank,version,description,type,script,checksum,installed_by,execution_time,success) VALUES(8,'8','synthetic','SQL','V8__synthetic.sql',1,'fuse_owner',0,true)",
                "GRANT fuse_owner TO fuse_runtime WITH INHERIT FALSE, SET TRUE")) {
            try (var fixture = new Fixture()) {
                fixture.migrate(); fixture.sql(tamper);
                assertThrows(Exception.class, () -> MigrationContract.validate(fixture.runtimeConfiguration(), "fuse_runtime"));
            }
        }
        try (var fixture = new Fixture()) {
            fixture.migrate(); fixture.sql("ALTER ROLE fuse_runtime IN DATABASE fuse SET search_path=public,pg_catalog");
            assertThrows(Exception.class, () -> MigrationContract.validate(fixture.runtimeConfiguration(), "fuse_runtime"));
        }
        try (var fixture = new Fixture()) {
            fixture.migrate(); fixture.sql("CREATE SCHEMA other AUTHORIZATION fuse_runtime");
            fixture.sql("ALTER ROLE fuse_runtime IN DATABASE fuse SET search_path=other,public");
            assertThrows(Exception.class, () -> MigrationContract.validate(fixture.runtimeConfiguration(), "fuse_runtime"));
        }
    }
}
