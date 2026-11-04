package com.finsec.fuse.reimplementation.persistence;

import com.finsec.fuse.reimplementation.auth.TokenRegistryInput;
import com.finsec.fuse.reimplementation.auth.TokenStorageShape;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.sql.DataSource;

/** Explicit row storage, not token generation, issuance authority or bearer delivery.
 * Source must supply one fresh/exclusive logical handle, not shared/reissued or ambient;
 * this premise is not proven by DataSource or getAutoCommit. No connection on construction.
 * Only SQLException/RuntimeException have typed recovery. Error propagates unredacted,
 * may skip rollback/later sequential cleanup, and never proves no mutation or safe retry.
 */
public final class JdbcTokenIssuanceWriter {
    private static final Pattern SCHEMA = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");
    private final DataSource source;
    private final String table;
    /** Commit evidence only; neither value establishes current row state or safe reissuance. */
    public enum Outcome { INSERT_CONFIRMED, COMMIT_UNCONFIRMED }
    public enum Cleanup { CONFIRMED, UNCONFIRMED }
    public enum Code { STORAGE_UNAVAILABLE, TRANSACTION_STATE_UNCONFIRMED }

    public record InsertResult(Outcome outcome, Cleanup cleanup) {
        public InsertResult { if (outcome == null || cleanup == null) throw invalid(); }
        @Override public String toString() { return "TokenIssuanceInsertResult[REDACTED]"; }
    }

    /** Unclassified failure, not a rollback receipt or permission to retry/reissue.
     * STORAGE_UNAVAILABLE can include acquisition, begin, write or precommit cleanup failure.
     * Driver causes/suppressed exceptions are deliberately detached.
     */
    public static final class StorageFailure extends RuntimeException {
        private final Code code;
        private StorageFailure(Code code) { super(code.name(), null, false, false); this.code = code; }
        public Code code() { return code; }
        @Override public String toString() { return "TokenIssuanceStorageFailure[" + code.name() + "]"; }
    }

    public JdbcTokenIssuanceWriter(DataSource source, String schema) {
        if (source == null || schema == null || !SCHEMA.matcher(schema).matches()) throw invalid();
        this.source = source;
        this.table = "\"" + schema + "\".demo_token";
    }

    /** Preserves every explicit schema-valid value, including status/revision and independent scopes.
     * No ACTIVE/revision-zero policy, subset rule, clock read or identifier algorithm is inferred.
     */
    public InsertResult insertExact(UUID selectionId, UUID registryId, byte[] fingerprint,
            TokenRegistryInput initial, List<String> currentScope, Instant issuedAt, Instant expiresAt,
            String securityPolicy, int issuanceTtlSeconds, TokenStorageShape.Status status,
            Instant revokedAt, long revision) {
        byte[] fingerprintCopy;
        TokenRegistryInput current;
        try {
            if (selectionId == null || fingerprint == null || fingerprint.length != 32 || initial == null) throw invalid();
            fingerprintCopy = fingerprint.clone();
            current = new TokenRegistryInput(initial.actorId(), initial.role(), currentScope);
            TokenStorageShape.validate(fingerprintCopy, registryId, securityPolicy, issuanceTtlSeconds,
                    issuedAt, expiresAt, status, revokedAt, revision);
        } catch (RuntimeException rejected) {
            throw invalid();
        }
        OffsetDateTime issued;
        OffsetDateTime expiry;
        OffsetDateTime revoked;
        try {
            issued = OffsetDateTime.ofInstant(issuedAt, ZoneOffset.UTC);
            expiry = OffsetDateTime.ofInstant(expiresAt, ZoneOffset.UTC);
            revoked = revokedAt == null ? null : OffsetDateTime.ofInstant(revokedAt, ZoneOffset.UTC);
        } catch (RuntimeException rejected) {
            throw new StorageFailure(Code.STORAGE_UNAVAILABLE);
        }
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rows = null;
        Array initialArray = null;
        Array currentArray = null;
        boolean transactionAttempted = false;
        boolean commitAttempted = false;
        boolean resolved = false;
        boolean cleaned = true;
        Outcome outcome = null;
        Code failure = null;
        try {
            connection = source.getConnection();
            if (connection == null || !connection.getAutoCommit()) throw new SQLException();
            transactionAttempted = true;
            connection.setAutoCommit(false);
            initialArray = connection.createArrayOf("text", initial.customerScope().toArray(String[]::new));
            currentArray = connection.createArrayOf("text", current.customerScope().toArray(String[]::new));
            if (initialArray == null || currentArray == null) throw new SQLException();
            statement = connection.prepareStatement("INSERT INTO " + table
                    + " (selection_id,fingerprint,registry_id,actor_id,role,initial_scope,current_scope,"
                    + "issued_at,expires_at,security_policy,issuance_ttl_seconds,status,revoked_at,revision)"
                    + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING issued_at,expires_at,revoked_at");
            statement.setObject(1, selectionId);
            statement.setBytes(2, fingerprintCopy);
            statement.setObject(3, registryId);
            statement.setString(4, initial.actorId());
            statement.setString(5, initial.role().name());
            statement.setArray(6, initialArray);
            statement.setArray(7, currentArray);
            statement.setObject(8, issued, Types.TIMESTAMP_WITH_TIMEZONE);
            statement.setObject(9, expiry, Types.TIMESTAMP_WITH_TIMEZONE);
            statement.setString(10, securityPolicy);
            statement.setInt(11, issuanceTtlSeconds);
            statement.setString(12, status.name());
            if (revoked == null) statement.setNull(13, Types.TIMESTAMP_WITH_TIMEZONE);
            else statement.setObject(13, revoked, Types.TIMESTAMP_WITH_TIMEZONE);
            statement.setLong(14, revision);
            rows = statement.executeQuery();
            if (!rows.next() || !Objects.equals(readTime(rows, 1), issuedAt)
                    || !Objects.equals(readTime(rows, 2), expiresAt)
                    || !Objects.equals(readTime(rows, 3), revokedAt) || rows.next()) throw new SQLException();
            // Consume handles before each one-time precommit cleanup attempt.
            ResultSet completedRows = rows; rows = null;
            cleaned &= close(completedRows);
            PreparedStatement completedStatement = statement; statement = null;
            cleaned &= close(completedStatement);
            Array completedInitial = initialArray; initialArray = null;
            cleaned &= free(completedInitial);
            Array completedCurrent = currentArray; currentArray = null;
            cleaned &= free(completedCurrent);
            if (!cleaned) throw new SQLException();
            commitAttempted = true;
            connection.commit();
            resolved = true;
            outcome = Outcome.INSERT_CONFIRMED;
        } catch (SQLException | RuntimeException rejected) {
            if (commitAttempted) outcome = Outcome.COMMIT_UNCONFIRMED;
            else failure = Code.STORAGE_UNAVAILABLE;
            if (transactionAttempted && !resolved) {
                try {
                    connection.rollback();
                    resolved = true;
                } catch (SQLException | RuntimeException rollbackRejected) {
                    cleaned = false;
                    if (!commitAttempted) failure = Code.TRANSACTION_STATE_UNCONFIRMED;
                }
            }
        } finally {
            cleaned &= close(rows);
            cleaned &= close(statement);
            cleaned &= free(initialArray);
            cleaned &= free(currentArray);
            cleaned &= close(connection);
        }
        if (failure != null) throw new StorageFailure(failure);
        return new InsertResult(outcome, cleaned ? Cleanup.CONFIRMED : Cleanup.UNCONFIRMED);
    }

    private static Instant readTime(ResultSet rows, int column) throws SQLException {
        OffsetDateTime time = rows.getObject(column, OffsetDateTime.class);
        return time == null ? null : time.toInstant();
    }

    private static boolean close(AutoCloseable resource) {
        if (resource == null) return true;
        try { resource.close(); return true; }
        catch (Exception rejected) { return false; }
    }

    private static boolean free(Array array) {
        if (array == null) return true;
        try { array.free(); return true; }
        catch (Exception rejected) { return false; }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_TOKEN_ISSUANCE_STORAGE_INPUT");
    }

    @Override public String toString() { return "JdbcTokenIssuanceWriter[REDACTED]"; }
}
