package com.finsec.fuse.reimplementation.persistence;

import com.finsec.fuse.reimplementation.auth.RegistryTokenSelection;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import static com.finsec.fuse.reimplementation.persistence.TokenSelectorPersistenceException.Code.*;

/** Low-level persistence, not authorization. No connection is opened at construction.
 * The injected source must provide a fresh, exclusive logical handle per call,
 * never shared/reissued during the call or enlisted in an ambient transaction.
 * Neither the DataSource interface nor this autocommit check proves that premise.
 * No registry existence, administrator identity or protected channel is inferred.
 */
public final class JdbcTokenSelectorRepository {
    private static final Pattern SCHEMA = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");
    private final DataSource source;
    private final String table;

    public enum Status { ACTIVE, REVOKED }
    /** Commit/attempt evidence, not current token validity or automatic retry authority. */
    public enum Outcome { REVOKED_CONFIRMED, NOT_APPLIED, COMMIT_UNCONFIRMED }
    public enum Cleanup { CONFIRMED, UNCONFIRMED }

    public record Snapshot(Status status, long revision) {
        public Snapshot {
            if (status == null || revision < 0) throw invalid();
        }
        @Override public String toString() { return "TokenSelectorSnapshot[REDACTED]"; }
    }

    public record RevokeResult(Outcome outcome, Cleanup cleanup) {
        public RevokeResult {
            if (outcome == null || cleanup == null) throw invalid();
        }
        @Override public String toString() { return "TokenSelectorRevokeResult[REDACTED]"; }
    }

    public JdbcTokenSelectorRepository(DataSource source, String schema) {
        if (source == null || schema == null || !SCHEMA.matcher(schema).matches()) throw invalid();
        this.source = source;
        this.table = "\"" + schema + "\".demo_token";
    }

    /** Exact registry, selector and expected revision; no match is intentionally opaque. */
    public Optional<Snapshot> lookupExpected(RegistryTokenSelection selection) {
        if (selection == null) throw invalid();
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rows = null;
        Optional<Snapshot> result = Optional.empty();
        boolean failed = false;
        boolean cleaned = true;
        try {
            connection = source.getConnection();
            if (connection == null || !connection.getAutoCommit()) throw new SQLException();
            statement = connection.prepareStatement("SELECT status,revision FROM " + table
                    + " WHERE registry_id=? AND selection_id=? AND revision=?");
            statement.setObject(1, selection.registryId());
            statement.setObject(2, selection.input().selectionId());
            statement.setLong(3, selection.input().expectedRevision());
            rows = statement.executeQuery();
            if (rows.next()) {
                Object status = rows.getObject(1);
                Object revision = rows.getObject(2);
                if (status == null || status.getClass() != String.class
                        || revision == null || revision.getClass() != Long.class) throw new SQLException();
                Status parsed;
                if (status.equals("ACTIVE")) parsed = Status.ACTIVE;
                else if (status.equals("REVOKED")) parsed = Status.REVOKED;
                else throw new SQLException();
                long value = (Long) revision;
                if (value < 0 || value != selection.input().expectedRevision() || rows.next()) {
                    throw new SQLException();
                }
                result = Optional.of(new Snapshot(parsed, value));
            }
        } catch (SQLException | RuntimeException rejected) {
            failed = true;
        } finally {
            cleaned &= close(rows);
            cleaned &= close(statement);
            cleaned &= close(connection);
        }
        if (failed || !cleaned) throw new TokenSelectorPersistenceException(STORAGE_UNAVAILABLE);
        return result;
    }

    /** Administrative monotonic revocation also permits expired ACTIVE rows.
     * Caller supplies time and authorization; this method reads no clock or credentials.
     * MAX revision is valid input but cannot advance, so it yields opaque NOT_APPLIED.
     */
    public RevokeResult revokeExpected(RegistryTokenSelection selection, Instant revokedAt) {
        if (selection == null || revokedAt == null) throw invalid();
        if (selection.input().expectedRevision() == Long.MAX_VALUE) {
            return new RevokeResult(Outcome.NOT_APPLIED, Cleanup.CONFIRMED);
        }
        OffsetDateTime timestamp;
        try {
            timestamp = OffsetDateTime.ofInstant(revokedAt, ZoneOffset.UTC);
        } catch (RuntimeException rejected) {
            throw new TokenSelectorPersistenceException(STORAGE_UNAVAILABLE);
        }
        Connection connection = null;
        PreparedStatement statement = null;
        boolean transactionAttempted = false;
        boolean resolved = false;
        boolean commitAttempted = false;
        boolean rollbackAttempted = false;
        boolean cleaned = true;
        Outcome outcome = null;
        TokenSelectorPersistenceException.Code failure = null;
        try {
            connection = source.getConnection();
            if (connection == null || !connection.getAutoCommit()) throw new SQLException();
            transactionAttempted = true;
            connection.setAutoCommit(false);
            statement = connection.prepareStatement("UPDATE " + table
                    + " SET status='REVOKED',revoked_at=?,revision=revision+1"
                    + " WHERE registry_id=? AND selection_id=? AND revision=?"
                    + " AND status='ACTIVE' AND revision<9223372036854775807");
            statement.setObject(1, timestamp, Types.TIMESTAMP_WITH_TIMEZONE);
            statement.setObject(2, selection.registryId());
            statement.setObject(3, selection.input().selectionId());
            statement.setLong(4, selection.input().expectedRevision());
            int changed = statement.executeUpdate();
            if (changed == 0) {
                rollbackAttempted = true;
                connection.rollback();
                resolved = true;
                outcome = Outcome.NOT_APPLIED;
            } else if (changed == 1) {
                commitAttempted = true;
                connection.commit();
                resolved = true;
                outcome = Outcome.REVOKED_CONFIRMED;
            } else {
                throw new SQLException();
            }
        } catch (SQLException | RuntimeException rejected) {
            if (commitAttempted) outcome = Outcome.COMMIT_UNCONFIRMED;
            else failure = STORAGE_UNAVAILABLE;
            if (transactionAttempted && !resolved) {
                if (rollbackAttempted) {
                    cleaned = false;
                    if (!commitAttempted) failure = TRANSACTION_STATE_UNCONFIRMED;
                } else {
                    rollbackAttempted = true;
                    try {
                        connection.rollback();
                        resolved = true;
                    } catch (SQLException | RuntimeException rollbackRejected) {
                        cleaned = false;
                        if (!commitAttempted) failure = TRANSACTION_STATE_UNCONFIRMED;
                    }
                }
            }
        } finally {
            cleaned &= close(statement);
            cleaned &= close(connection);
        }
        if (failure != null) throw new TokenSelectorPersistenceException(failure);
        return new RevokeResult(outcome, cleaned ? Cleanup.CONFIRMED : Cleanup.UNCONFIRMED);
    }

    private static boolean close(AutoCloseable resource) {
        if (resource == null) return true;
        try {
            resource.close();
            return true;
        } catch (Exception rejected) {
            return false;
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_TOKEN_SELECTOR_REPOSITORY_INPUT");
    }

    @Override public String toString() { return "JdbcTokenSelectorRepository[REDACTED]"; }
}
