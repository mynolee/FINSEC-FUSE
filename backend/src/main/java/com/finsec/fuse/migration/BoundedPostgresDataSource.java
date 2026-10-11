package com.finsec.fuse.migration;

import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.sql.*;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.sql.DataSource;

/** Unpooled, fixed PostgreSQL connectivity. No fallback credentials or caller JDBC properties. */
public final class BoundedPostgresDataSource implements DataSource {
    public record Configuration(String url, String username, String password, String database) {
        public static Configuration parse(String url, String username, String password) {
            if (url == null || username == null || password == null || !url.startsWith("jdbc:postgresql://")
                    || !username.matches("[A-Za-z_][A-Za-z0-9_]{0,62}") || password.isBlank()
                    || password.length() > 4096 || password.contains("CHANGE_ME")
                    || password.indexOf('\0') >= 0 || password.indexOf('\n') >= 0 || password.indexOf('\r') >= 0)
                throw new IllegalArgumentException("Explicit database configuration is required");
            try {
                URI uri = URI.create(url.substring(5));
                if (!"postgresql".equals(uri.getScheme()) || uri.getHost() == null
                        || uri.getPort() < 1 || uri.getPort() > 65535 || uri.getRawUserInfo() != null
                        || uri.getRawQuery() != null || uri.getRawFragment() != null
                        || !uri.getRawPath().matches("/[A-Za-z_][A-Za-z0-9_]{0,62}"))
                    throw new IllegalArgumentException("Unsupported database connection shape");
                return new Configuration(url, username, password, uri.getRawPath().substring(1));
            } catch (RuntimeException rejected) {
                throw new IllegalArgumentException("Unsupported database connection shape");
            }
        }
        @Override public String toString() { return "Database configuration (redacted)"; }
    }

    private final Configuration configuration;
    private final boolean readOnly;

    public BoundedPostgresDataSource(Configuration configuration, boolean readOnly) {
        this.configuration = java.util.Objects.requireNonNull(configuration);
        this.readOnly = readOnly;
    }

    public static void quietDriverLogging() {
        // Must precede DriverManager/Flyway initialization. Never enable JDBC tracing for these commands.
        Logger.getLogger("org.postgresql").setLevel(Level.OFF);
    }

    @Override public Connection getConnection() throws SQLException {
        quietDriverLogging();
        Properties properties = new Properties();
        properties.setProperty("user", configuration.username());
        properties.setProperty("password", configuration.password());
        properties.setProperty("connectTimeout", "5");
        properties.setProperty("socketTimeout", "10");
        properties.setProperty("tcpKeepAlive", "true");
        properties.setProperty("ApplicationName", readOnly ? "FINSEC-SCHEMA-VALIDATION" : "FINSEC-MIGRATION-ADMIN");
        // These startup options are trusted constants, never merged with URL/env/user-supplied options.
        properties.setProperty("options", "-c lock_timeout=2000 -c statement_timeout=5000"
                + (readOnly ? " -c default_transaction_read_only=on" : ""));
        properties.setProperty("readOnly", Boolean.toString(readOnly));
        properties.setProperty("readOnlyMode", "always");
        Connection connection = null;
        try {
            connection = DriverManager.getConnection(configuration.url(), properties);
            connection.setReadOnly(readOnly);
            try (Statement statement = connection.createStatement()) {
                statement.setQueryTimeout(5);
                try (ResultSet rows = statement.executeQuery(
                    """
                    SELECT pg_catalog.current_database(),current_user,session_user,pg_catalog.current_schema(),\
                    pg_catalog.current_setting('default_transaction_read_only'),pg_catalog.current_setting('transaction_read_only'),\
                    pg_catalog.current_setting('lock_timeout'),pg_catalog.current_setting('statement_timeout'),\
                    pg_catalog.current_schemas(true)::pg_catalog.text\
                    """)) {
                    if (!rows.next() || !configuration.database().equals(rows.getString(1))
                            || !configuration.username().equals(rows.getString(2))
                            || !configuration.username().equals(rows.getString(3)) || !"public".equals(rows.getString(4))
                            || (readOnly && (!"on".equals(rows.getString(5)) || !"on".equals(rows.getString(6))))
                            || !"2s".equals(rows.getString(7)) || !"5s".equals(rows.getString(8))
                            || !"{pg_catalog,public}".equals(rows.getString(9)))
                        throw new SQLException("Database connection contract rejected", "08001");
                }
            }
            return (Connection) new Guard(readOnly).wrap(connection);
        } catch (SQLException | RuntimeException rejected) {
            if (connection != null) try { connection.close(); } catch (SQLException ignored) { }
            throw new SQLException("Database connection contract rejected", "08001");
        }
    }

    /** Prevent JDBC API escapes from undoing the validated connection's read-only mode. */
    private static final class Guard {
        private final boolean readOnly;
        private final Map<Object, Object> wrappers = new IdentityHashMap<>();
        Guard(boolean readOnly) { this.readOnly = readOnly; }
        Object wrap(Object value) {
            if (value == null) return null;
            Class<?> type = value instanceof Connection ? Connection.class
                    : value instanceof DatabaseMetaData ? DatabaseMetaData.class
                    : value instanceof CallableStatement ? CallableStatement.class
                    : value instanceof PreparedStatement ? PreparedStatement.class
                    : value instanceof Statement ? Statement.class
                    : value instanceof ResultSet ? ResultSet.class : null;
            if (type == null) return value;
            if (wrappers.containsKey(value)) return wrappers.get(value);
            Object proxy = Proxy.newProxyInstance(BoundedPostgresDataSource.class.getClassLoader(), new Class<?>[]{type},
                    (self, method, args) -> {
                        String name = method.getName();
                        if (name.equals("toString")) return "FUSE JDBC handle (redacted)";
                        if (name.equals("equals")) return self == args[0];
                        if (name.equals("hashCode")) return System.identityHashCode(self);
                        if (name.equals("isWrapperFor")) return ((Class<?>) args[0]).isInstance(self);
                        if (name.equals("unwrap")) {
                            if (((Class<?>) args[0]).isInstance(self)) return self;
                            throw new SQLException("Raw JDBC access is unavailable", "25006");
                        }
                        if (readOnly && name.equals("setReadOnly") && Boolean.FALSE.equals(args[0]))
                            throw new SQLException("Validation connections remain read-only", "25006");
                        try {
                            // Includes metadata.getConnection, statement.getConnection, resultSet.getStatement.
                            return wrap(method.invoke(value, args));
                        } catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
            wrappers.put(value, proxy);
            return proxy;
        }
    }

    @Override public Connection getConnection(String user, String password) throws SQLException {
        throw new SQLException("Connection credential overrides are unsupported", "08001");
    }
    @Override public PrintWriter getLogWriter() { return null; }
    @Override public void setLogWriter(PrintWriter writer) throws SQLException {
        if (writer != null) throw new SQLException("Database tracing is unsupported");
    }
    @Override public void setLoginTimeout(int seconds) throws SQLException {
        if (seconds != 5) throw new SQLException("Connection timeout is fixed");
    }
    @Override public int getLoginTimeout() { return 5; }
    @Override public Logger getParentLogger() { return Logger.getLogger("org.postgresql"); }
    @Override public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) return iface.cast(this);
        throw new SQLException("Raw data source access is unavailable");
    }
    @Override public boolean isWrapperFor(Class<?> iface) { return iface.isInstance(this); }
    @Override public String toString() { return "Bounded PostgreSQL data source (redacted)"; }
}
