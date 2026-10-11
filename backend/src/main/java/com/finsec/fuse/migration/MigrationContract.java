package com.finsec.fuse.migration;

import java.net.JarURLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.*;
import java.util.*;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.configuration.FluentConfiguration;

/** Reviewed V1–V7 compatibility, not a forensic comparison of arbitrary DBA changes. */
public final class MigrationContract {
    private MigrationContract() { }
    public static final List<String> SCRIPTS = List.of(
            "V1__fuse_core.sql", "V2__experiments.sql", "V3__immutable_agent_results.sql",
            "V4__pre_execution_quarantine_holds.sql", "V5__experiment_arm_bindings.sql",
            "V6__durable_demo_tokens.sql", "V7__protect_flyway_history.sql");
    public static final Set<String> TABLES = Set.of(
            "execution_gate", "agent_registry", "mock_account", "mock_profile", "application_registry",
            "source_document_version", "trusted_evidence", "loan_application", "workflow", "workflow_stage",
            "agent_run", "agent_result", "run_source_use", "run_evidence_use", "run_dependency", "action_request",
            "approval", "workflow_job", "delegation_grant", "payment_reservation", "risk_ledger", "mock_payment",
            "quarantine", "audit_event", "experiment", "experiment_case_result", "quarantine_workflow_hold",
            "experiment_arm_binding", "demo_auth_registry", "demo_token", "flyway_schema_history");
    private static final Map<String, String> TRIGGERS = Map.ofEntries(
            Map.entry("audit_append_only", "audit_event"), Map.entry("risk_append_only", "risk_ledger"),
            Map.entry("source_append_only", "source_document_version"), Map.entry("application_immutable", "loan_application"),
            Map.entry("payment_immutable", "mock_payment"), Map.entry("agent_result_integrity", "agent_result"),
            Map.entry("quarantine_hold_append_only", "quarantine_workflow_hold"),
            Map.entry("demo_registry_immutable", "demo_auth_registry"), Map.entry("demo_registry_no_truncate", "demo_auth_registry"),
            Map.entry("demo_token_immutable", "demo_token"), Map.entry("demo_token_no_truncate", "demo_token"));
    private static final List<String> FUNCTIONS = List.of("reject_immutable_mutation()", "protect_agent_result_integrity()",
            "demo_scope_valid(text[])", "protect_demo_registry()", "protect_demo_token()");
    private static final Map<String, Set<String>> COLUMNS = Map.of(
            "flyway_schema_history", Set.of("installed_rank", "version", "type", "script", "checksum", "success"),
            "demo_auth_registry", Set.of("id", "registry_id", "format_version", "initialized_at"),
            "demo_token", Set.of("fingerprint", "registry_id", "actor_id", "role", "initial_scope", "current_scope",
                    "issued_at", "expires_at", "security_policy", "issuance_ttl_seconds", "status", "revoked_at", "revision"),
            "workflow_job", Set.of("id", "workflow_id", "generation", "phase", "state", "execution_action_id", "run_id",
                    "approval_id", "lease_token", "lease_until", "last_error", "created_at", "started_at", "completed_at"));

    public static FluentConfiguration flyway(DataSource source) {
        BoundedPostgresDataSource.quietDriverLogging();
        return Flyway.configure().dataSource(source).locations("classpath:db/migration")
                .schemas("public").defaultSchema("public").createSchemas(false)
                .cleanDisabled(true).baselineOnMigrate(false).outOfOrder(false).group(true)
                .connectRetries(0).lockRetryCount(0).validateOnMigrate(true).validateMigrationNaming(true)
                .ignoreMigrationPatterns().placeholderReplacement(false).skipDefaultCallbacks(true).loggers("none");
    }

    /** Reject additions, callbacks, Java migrations, duplicate roots and unsupported resource protocols. */
    public static void requirePackagedScripts() throws Exception {
        var roots = Collections.list(MigrationContract.class.getClassLoader().getResources("db/migration"));
        if (roots.size() != 1) throw rejected();
        var root = roots.getFirst();
        Set<String> names = new HashSet<>();
        if ("file".equals(root.getProtocol())) {
            try (var files = Files.list(Path.of(root.toURI()))) {
                for (Path file : files.toList()) {
                    if (!Files.isRegularFile(file) || Files.isSymbolicLink(file)) throw rejected();
                    names.add(file.getFileName().toString());
                }
            }
        } else if ("jar".equals(root.getProtocol())) {
            var connection = root.openConnection();
            if (!(connection instanceof JarURLConnection jar)) throw rejected();
            String prefix = jar.getEntryName().replaceAll("/+$", "") + "/";
            var entries = jar.getJarFile().entries();
            while (entries.hasMoreElements()) {
                var entry = entries.nextElement();
                if (entry.getName().startsWith(prefix) && !entry.isDirectory())
                    names.add(entry.getName().substring(prefix.length()));
            }
        } else throw rejected();
        if (!names.equals(new HashSet<>(SCRIPTS))) throw rejected();
    }

    public static void requireFresh(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(
                "SELECT current_database()='fuse' AND current_user='fuse_owner' AND session_user='fuse_owner' "
                + "AND current_schema()='public' AND EXISTS (SELECT 1 FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba "
                + "WHERE d.datname=current_database() AND r.rolname='fuse_owner') "
                + "AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname='fuse_runtime') "
                + "AND NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname NOT IN "
                + "('public','information_schema','pg_catalog','pg_toast')) "
                + "AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') "
                + "AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public') "
                + "AND NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public') "
                // Namespace dependencies also cover collations/conversions/operators/opclasses/opfamilies.
                // The bootstrap's owner table/sequence default ACL metadata is the sole permitted object.
                + "AND NOT EXISTS (SELECT 1 FROM pg_depend d JOIN pg_namespace n ON n.oid=d.refobjid "
                + "WHERE d.refclassid='pg_namespace'::regclass AND n.nspname='public' "
                + "AND d.classid<>'pg_default_acl'::regclass) "
                + "AND NOT EXISTS (SELECT 1 FROM pg_default_acl a JOIN pg_namespace n ON n.oid=a.defaclnamespace "
                + "JOIN pg_roles r ON r.oid=a.defaclrole WHERE n.nspname='public' "
                + "AND (r.rolname<>'fuse_owner' OR a.defaclobjtype NOT IN ('r','S'))) "
                + "AND NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname<>'plpgsql') "
                + "AND NOT EXISTS (SELECT 1 FROM pg_event_trigger) AND NOT EXISTS (SELECT 1 FROM pg_publication) "
                + "AND NOT EXISTS (SELECT 1 FROM pg_subscription) AND NOT EXISTS (SELECT 1 FROM pg_largeobject_metadata)")) {
            if (!rows.next() || !rows.getBoolean(1)) throw rejected();
        }
        requireFreshDefaults(connection);
        requireRuntimeAuthority(connection, "fuse_runtime");
    }

    private static void requireFreshDefaults(Connection connection) throws SQLException {
        Map<String, Set<String>> actual = new HashMap<>();
        int records;
        try (Statement query = connection.createStatement(); ResultSet rows = query.executeQuery("SELECT count(*) FROM pg_default_acl")) {
            rows.next(); records = rows.getInt(1);
        }
        if (records != 2) throw rejected();
        try (Statement query = connection.createStatement(); ResultSet rows = query.executeQuery(
                "SELECT a.defaclobjtype::text,owner.rolname,n.nspname,grantee.rolname,grantor.rolname,x.privilege_type,x.is_grantable "
                + "FROM pg_default_acl a JOIN pg_roles owner ON owner.oid=a.defaclrole "
                + "JOIN pg_namespace n ON n.oid=a.defaclnamespace CROSS JOIN LATERAL aclexplode(a.defaclacl) x "
                + "LEFT JOIN pg_roles grantee ON grantee.oid=x.grantee LEFT JOIN pg_roles grantor ON grantor.oid=x.grantor")) {
            while (rows.next()) {
                if (!"fuse_owner".equals(rows.getString(2)) || !"public".equals(rows.getString(3))
                        || !"fuse_runtime".equals(rows.getString(4))
                        || !"fuse_owner".equals(rows.getString(5)) || rows.getBoolean(7)) throw rejected();
                actual.computeIfAbsent(rows.getString(1) + ":" + rows.getString(4), ignored -> new HashSet<>()).add(rows.getString(6));
            }
        }
        // IN SCHEMA entries are additive to global/implicit owner defaults; they contain
        // only the grants made by init-postgres, not the owner's implicit full privileges.
        Map<String, Set<String>> expected = Map.of(
                "r:fuse_runtime", Set.of("SELECT", "INSERT", "UPDATE", "DELETE"),
                "S:fuse_runtime", Set.of("SELECT", "USAGE"));
        if (!actual.equals(expected)) throw rejected();
    }

    public static void validate(BoundedPostgresDataSource.Configuration configuration, String runtimeRole) throws Exception {
        requirePackagedScripts();
        DataSource readOnly = new BoundedPostgresDataSource(configuration, true);
        try (Connection connection = readOnly.getConnection()) {
            requireExactHistory(connection);
            requireObjects(connection);
            requireRuntimePrivileges(connection, runtimeRole);
        }
        // This source supplies enforced read-only connections, even when Flyway chooses autocommit.
        // Never replace a validation failure with migrate, repair, baseline or a read/write connection.
        flyway(readOnly).load().validate();
    }

    public static void requireExactHistory(Connection connection) throws SQLException {
        int index = 0;
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(
                "SELECT version,type,script,checksum,success FROM public.flyway_schema_history ORDER BY installed_rank")) {
            while (rows.next()) {
                if (index >= SCRIPTS.size() || !Integer.toString(index + 1).equals(rows.getString(1))
                        || !"SQL".equals(rows.getString(2)) || !SCRIPTS.get(index).equals(rows.getString(3))
                        || rows.getObject(4) == null || !rows.getBoolean(5)) throw rejected();
                index++;
            }
        }
        if (index != SCRIPTS.size()) throw rejected();
    }

    public static void requireObjects(Connection connection) throws SQLException {
        Set<String> actual = new HashSet<>();
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(
                "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                + "WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f')")) {
            while (rows.next()) actual.add(rows.getString(1));
        }
        if (!actual.equals(TABLES)) throw rejected();
        for (String table : TABLES) {
            try (PreparedStatement query = connection.prepareStatement("SELECT c.relkind='r' AND c.relpersistence='p' "
                    + "AND EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid=c.oid AND k.contype='p' AND k.convalidated) "
                    + "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=?")) {
                query.setString(1, table);
                try (ResultSet rows = query.executeQuery()) { if (!rows.next() || !rows.getBoolean(1)) throw rejected(); }
            }
        }
        for (var entry : TRIGGERS.entrySet()) {
            try (PreparedStatement query = connection.prepareStatement("SELECT count(*)=1 FROM pg_trigger t "
                    + "JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                    + "WHERE n.nspname='public' AND c.relname=? AND t.tgname=? AND NOT t.tgisinternal AND t.tgenabled='O'")) {
                query.setString(1, entry.getValue()); query.setString(2, entry.getKey());
                try (ResultSet rows = query.executeQuery()) { if (!rows.next() || !rows.getBoolean(1)) throw rejected(); }
            }
        }
        for (String function : FUNCTIONS) {
            try (PreparedStatement query = connection.prepareStatement("SELECT to_regprocedure(?) IS NOT NULL")) {
                query.setString(1, "public." + function);
                try (ResultSet rows = query.executeQuery()) { if (!rows.next() || !rows.getBoolean(1)) throw rejected(); }
            }
        }
        for (var entry : COLUMNS.entrySet()) {
            Set<String> columns = new HashSet<>();
            try (PreparedStatement query = connection.prepareStatement("SELECT column_name FROM information_schema.columns "
                    + "WHERE table_schema='public' AND table_name=?")) {
                query.setString(1, entry.getKey());
                try (ResultSet rows = query.executeQuery()) { while (rows.next()) columns.add(rows.getString(1)); }
            }
            if (!columns.containsAll(entry.getValue())) throw rejected();
        }
    }

    private static void requireRuntimeAuthority(Connection connection, String role) throws SQLException {
        try (PreparedStatement query = connection.prepareStatement("SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole "
                + "OR rolreplication OR rolbypassrls) AND has_database_privilege(rolname,current_database(),'CONNECT') "
                + "AND NOT has_database_privilege(rolname,current_database(),'CREATE') "
                + "AND has_schema_privilege(rolname,'public','USAGE') AND NOT has_schema_privilege(rolname,'public','CREATE') "
                + "AND NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid) "
                + "AND NOT EXISTS (SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND d.datdba=r.oid) "
                + "AND NOT EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname='public' AND n.nspowner=r.oid) "
                + "AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                + "WHERE n.nspname='public' AND pg_has_role(rolname,p.proowner,'MEMBER')) "
                + "AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                + "WHERE n.nspname='public' AND c.relkind IN ('r','S') AND pg_has_role(rolname,c.relowner,'MEMBER')) "
                + "FROM pg_roles r WHERE rolname=?")) {
            query.setString(1, role);
            try (ResultSet rows = query.executeQuery()) { if (!rows.next() || !rows.getBoolean(1)) throw rejected(); }
        }
    }

    public static void requireRuntimePrivileges(Connection connection, String role) throws SQLException {
        requireRuntimeAuthority(connection, role);
        for (String table : List.of("flyway_schema_history", "demo_auth_registry", "demo_token")) {
            // Column-level mutation grants survive REVOKE ALL ON TABLE and must also be absent.
            try (PreparedStatement query = connection.prepareStatement("SELECT has_any_column_privilege(?,?,'INSERT,UPDATE,REFERENCES')")) {
                query.setString(1, role); query.setString(2, "public." + table);
                try (ResultSet rows = query.executeQuery()) { if (!rows.next() || rows.getBoolean(1)) throw rejected(); }
            }
            for (String privilege : List.of("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")) {
                try (PreparedStatement query = connection.prepareStatement("SELECT has_table_privilege(?,?,?)")) {
                    query.setString(1, role); query.setString(2, "public." + table); query.setString(3, privilege);
                    try (ResultSet rows = query.executeQuery()) {
                        if (!rows.next() || rows.getBoolean(1) != "SELECT".equals(privilege)) throw rejected();
                    }
                }
            }
        }
    }

    public static SQLException rejected() { return new SQLException("Database compatibility contract rejected", "55000"); }
}
