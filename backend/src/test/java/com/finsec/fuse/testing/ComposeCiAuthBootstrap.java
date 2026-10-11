package com.finsec.fuse.testing;

import com.finsec.fuse.auth.DemoTokenProvisioner;
import java.net.InetAddress;
import java.sql.DriverManager;
import java.util.Map;
import java.util.Properties;
import org.flywaydb.core.Flyway;

/** Test-classpath-only, explicit initialization of one newly created CI database.
 * Never starts Spring, imports existing bearer values, or retries issuance. */
public final class ComposeCiAuthBootstrap {
    private ComposeCiAuthBootstrap() {}

    public static void main(String[] args) {
        try {
            Map<String, String> env = System.getenv();
            String project = "fuse-ci-" + env.get("GITHUB_RUN_ID") + "-" + env.get("GITHUB_RUN_ATTEMPT");
            if (args.length != 1 || !"true".equals(env.get("GITHUB_ACTIONS"))
                    || !project.matches("fuse-ci-[1-9][0-9]*-[1-9][0-9]*")
                    || !project.equals(env.get("FUSE_CI_AUTH_PROJECT"))
                    || "root".equals(System.getProperty("user.name"))) {
                throw new IllegalArgumentException("Synthetic CI ownership is required");
            }
            String address = env.getOrDefault("FUSE_CI_AUTH_ADDRESS", "");
            if (!address.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}"))
                throw new IllegalArgumentException("A literal CI bridge address is required");
            String[] parts = address.split("\\.");
            byte[] bytes = new byte[4];
            for (int i = 0; i < 4; i++) {
                int value = Integer.parseInt(parts[i]);
                if (value > 255 || !Integer.toString(value).equals(parts[i]))
                    throw new IllegalArgumentException("Invalid CI bridge address");
                bytes[i] = (byte) value;
            }
            InetAddress ip = InetAddress.getByAddress(bytes); // No DNS or external discovery.
            if (!ip.isSiteLocalAddress() || ip.isLoopbackAddress() || ip.isLinkLocalAddress())
                throw new IllegalArgumentException("Private CI bridge address required");
            String url = "jdbc:postgresql://" + address + ":5432/fuse";
            String password = env.getOrDefault("FUSE_MIGRATION_PASSWORD", "");
            if (!url.equals(env.get("FUSE_DB_URL")) || !"fuse_owner".equals(env.get("FUSE_MIGRATION_USERNAME"))
                    || !password.matches("[a-f0-9]{64}")
                    || env.keySet().stream().anyMatch(key -> key.endsWith("_TOKEN") || key.startsWith("SPRING_")))
                throw new IllegalArgumentException("Isolated owner environment required");
            // The Python owner verifies a newly created project/container/volume first.
            // This additional database check rejects a previously migrated database.
            Properties connectivity = new Properties();
            connectivity.setProperty("user", "fuse_owner");
            connectivity.setProperty("password", password);
            connectivity.setProperty("connectTimeout", "5");
            connectivity.setProperty("socketTimeout", "10");
            try (var connection = DriverManager.getConnection(url, connectivity);
                 var statement = connection.createStatement()) {
                statement.setQueryTimeout(5);
                try (var rows = statement.executeQuery("SELECT current_database()='fuse' AND current_user='fuse_owner' "
                        + "AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                        + "WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' "
                        + "AND c.relkind IN ('r','p','v','m','S','f'))")) {
                    if (!rows.next() || !rows.getBoolean(1))
                        throw new IllegalStateException("An empty disposable database is required");
                }
            }
            Flyway.configure().dataSource(url, "fuse_owner", password)
                    .locations("classpath:db/migration").schemas("public").defaultSchema("public")
                    .cleanDisabled(true).baselineOnMigrate(false).connectRetries(0).load().migrate();
            // The unchanged issuer generates fresh bytes and requires empty migrated auth tables.
            DemoTokenProvisioner.main(new String[] {"init-fresh", "--new-install", "--output", args[0]});
        } catch (Exception failure) {
            // Driver/URL/output diagnostics must never reach CI stdout/stderr.
            System.err.println("Synthetic CI authentication preparation failed; no retry or completion claimed.");
            System.exit(1);
        }
    }
}
