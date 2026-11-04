package com.finsec.fuse.reimplementation.persistence;

import com.finsec.fuse.reimplementation.auth.RegistryTokenSelection;
import com.finsec.fuse.reimplementation.auth.TokenRevocationInput;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.persistence.JdbcTokenSelectorRepository.*;
import static com.finsec.fuse.reimplementation.persistence.TokenSelectorPersistenceException.Code.*;

/** Recording JDBC interfaces only, not DB enforcement, concurrency or durability proof. */
class JdbcTokenSelectorRepositoryTest {
    private static final Instant TIME = Instant.parse("2000-01-01T00:00:00Z");

    private static RegistryTokenSelection selection(long revision) {
        return new RegistryTokenSelection(new UUID(0, 1), new TokenRevocationInput(new UUID(0, 2), revision));
    }

    private static final class Recording {
        final List<String> calls = new ArrayList<>();
        final Map<Integer, Object> bindings = new HashMap<>();
        boolean autoCommit = true;
        boolean executeFails, commitFails, rollbackFails, statementCloseFails, connectionCloseFails;
        int changed = 1;
        int row = -1;
        Object[][] rows = new Object[0][];
        String sql;
        Integer timestampType;

        private SQLException sensitive() {
            SQLException failure = new SQLException("SYNTHETIC_PRIVATE_DRIVER_TEXT", new RuntimeException("SYNTHETIC_PRIVATE_CAUSE"));
            failure.addSuppressed(new RuntimeException("SYNTHETIC_PRIVATE_SUPPRESSED"));
            failure.setNextException(new SQLException("SYNTHETIC_PRIVATE_NEXT"));
            return failure;
        }

        private Object invoke(String owner, String name, Object[] args) throws SQLException {
            calls.add(owner + "." + name);
            if (name.equals("toString")) return "SYNTHETIC_PRIVATE_IDENTIFIER";
            if (owner.equals("source") && name.equals("getConnection")) return connection();
            if (owner.equals("connection")) {
                if (name.equals("getAutoCommit")) return autoCommit;
                if (name.equals("setAutoCommit")) { autoCommit = (Boolean) args[0]; return null; }
                if (name.equals("prepareStatement")) { sql = (String) args[0]; return statement(); }
                if (name.equals("commit")) { if (commitFails) throw sensitive(); return null; }
                if (name.equals("rollback")) { if (rollbackFails) throw sensitive(); return null; }
                if (name.equals("close")) { if (connectionCloseFails) throw sensitive(); return null; }
            }
            if (owner.equals("statement")) {
                if (name.equals("setObject") || name.equals("setLong")) {
                    bindings.put((Integer) args[0], args[1]);
                    if (args.length == 3) timestampType = (Integer) args[2];
                    return null;
                }
                if (name.equals("executeUpdate")) { if (executeFails) throw sensitive(); return changed; }
                if (name.equals("executeQuery")) { if (executeFails) throw sensitive(); return resultSet(); }
                if (name.equals("close")) { if (statementCloseFails) throw sensitive(); return null; }
            }
            if (owner.equals("rows")) {
                if (name.equals("next")) return ++row < rows.length;
                if (name.equals("getObject")) return rows[row][(Integer) args[0] - 1];
                if (name.equals("close")) return null;
            }
            throw new AssertionError("Unexpected synthetic JDBC protocol call: " + owner + "." + name);
        }

        private <T> T proxy(Class<T> type, String owner) {
            return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
                    (proxy, method, args) -> invoke(owner, method.getName(), args)));
        }
        DataSource source() { return proxy(DataSource.class, "source"); }
        Connection connection() { return proxy(Connection.class, "connection"); }
        PreparedStatement statement() { return proxy(PreparedStatement.class, "statement"); }
        ResultSet resultSet() { return proxy(ResultSet.class, "rows"); }
        long count(String call) { return calls.stream().filter(call::equals).count(); }
        JdbcTokenSelectorRepository repository() { return new JdbcTokenSelectorRepository(source(), "Synthetic_1"); }
    }

    private static void redacted(TokenSelectorPersistenceException error,
                                 TokenSelectorPersistenceException.Code code) {
        assertEquals(code, error.code());
        assertEquals(code.name(), error.getMessage());
        assertNull(error.getCause());
        assertEquals(0, error.getSuppressed().length);
        assertFalse(error.toString().contains("SYNTHETIC_PRIVATE"));
    }

    @Test void lookupBindsExactRegistrySelectorRevisionAndDoesNotStartTransaction() {
        Recording jdbc = new Recording(); jdbc.rows = new Object[][] {{"ACTIVE", 7L}};
        Snapshot value = jdbc.repository().lookupExpected(selection(7)).orElseThrow();
        assertEquals(Status.ACTIVE, value.status());
        assertEquals(7L, value.revision());
        assertEquals("SELECT status,revision FROM \"Synthetic_1\".demo_token WHERE registry_id=? AND selection_id=? AND revision=?", jdbc.sql);
        assertEquals(selection(7).registryId(), jdbc.bindings.get(1));
        assertEquals(selection(7).input().selectionId(), jdbc.bindings.get(2));
        assertEquals(7L, jdbc.bindings.get(3));
        assertEquals(0L, jdbc.count("connection.setAutoCommit"));
        assertEquals(0L, jdbc.count("connection.commit"));
        assertEquals(0L, jdbc.count("connection.rollback"));
        assertEquals(1L, jdbc.count("rows.close"));
        assertEquals(1L, jdbc.count("statement.close"));
        assertEquals(1L, jdbc.count("connection.close"));
        assertEquals("TokenSelectorSnapshot[REDACTED]", value.toString());
    }

    @Test void lookupDistinguishesEmptyFromMalformedNullCoercedOrExtraRows() {
        Recording empty = new Recording();
        assertTrue(empty.repository().lookupExpected(selection(7)).isEmpty());
        for (Object[][] rows : new Object[][][] {
                {{null, 7L}}, {{"UNKNOWN", 7L}}, {{"ACTIVE", null}}, {{"ACTIVE", 7}},
                {{"ACTIVE", "7"}}, {{"ACTIVE", -1L}}, {{"ACTIVE", 8L}},
                {{"ACTIVE", 7L}, {"REVOKED", 7L}}}) {
            Recording jdbc = new Recording(); jdbc.rows = rows;
            redacted(assertThrows(TokenSelectorPersistenceException.class,
                    () -> jdbc.repository().lookupExpected(selection(7))), STORAGE_UNAVAILABLE);
            assertEquals(1L, jdbc.count("connection.close"));
        }
    }

    @Test void ambientTransactionIsRejectedWithoutSqlOrTransactionMutation() {
        for (boolean lookup : new boolean[] {true, false}) {
            Recording jdbc = new Recording(); jdbc.autoCommit = false;
            redacted(assertThrows(TokenSelectorPersistenceException.class, () -> {
                if (lookup) jdbc.repository().lookupExpected(selection(0));
                else jdbc.repository().revokeExpected(selection(0), TIME);
            }), STORAGE_UNAVAILABLE);
            assertEquals(0L, jdbc.count("connection.prepareStatement"));
            assertEquals(0L, jdbc.count("connection.setAutoCommit"));
            assertEquals(0L, jdbc.count("connection.commit"));
            assertEquals(0L, jdbc.count("connection.rollback"));
            assertEquals(1L, jdbc.count("connection.close"));
        }
    }

    @Test void zeroRowsAreOpaqueRollbackAndMaxRevisionDoesNotAcquireConnection() {
        Recording zero = new Recording(); zero.changed = 0;
        RevokeResult result = zero.repository().revokeExpected(selection(7), TIME);
        assertEquals(Outcome.NOT_APPLIED, result.outcome());
        assertEquals(Cleanup.CONFIRMED, result.cleanup());
        assertEquals(1L, zero.count("connection.rollback"));
        assertEquals(0L, zero.count("connection.commit"));
        assertEquals(0L, zero.count("statement.executeQuery"));
        Recording max = new Recording();
        assertEquals(Outcome.NOT_APPLIED,
                max.repository().revokeExpected(selection(Long.MAX_VALUE), TIME).outcome());
        assertEquals(0L, max.count("source.getConnection"));
    }

    @Test void exactlyOneRowCommitsWithTimeBindingAndNoExpiryOrClockPredicate() {
        Recording jdbc = new Recording();
        RevokeResult result = jdbc.repository().revokeExpected(selection(7), TIME);
        assertEquals(Outcome.REVOKED_CONFIRMED, result.outcome());
        assertEquals(Cleanup.CONFIRMED, result.cleanup());
        assertEquals(OffsetDateTime.ofInstant(TIME, ZoneOffset.UTC), jdbc.bindings.get(1));
        assertEquals(Integer.valueOf(Types.TIMESTAMP_WITH_TIMEZONE), jdbc.timestampType);
        assertEquals(selection(7).registryId(), jdbc.bindings.get(2));
        assertEquals(selection(7).input().selectionId(), jdbc.bindings.get(3));
        assertEquals(7L, jdbc.bindings.get(4));
        assertTrue(jdbc.sql.contains("status='ACTIVE' AND revision<9223372036854775807"));
        assertFalse(jdbc.sql.contains("expires_at"));
        assertFalse(jdbc.sql.contains("fingerprint"));
        assertEquals(1L, jdbc.count("connection.commit"));
        assertEquals(0L, jdbc.count("connection.rollback"));
        assertEquals(1L, jdbc.count("connection.setAutoCommit"));
        assertEquals("TokenSelectorRevokeResult[REDACTED]", result.toString());
    }

    @Test void precommitFailureAndMultirowInvariantRollbackWithFixedErrors() {
        for (boolean executeFailure : new boolean[] {true, false}) {
            Recording jdbc = new Recording(); jdbc.executeFails = executeFailure; jdbc.changed = 2;
            redacted(assertThrows(TokenSelectorPersistenceException.class,
                    () -> jdbc.repository().revokeExpected(selection(7), TIME)), STORAGE_UNAVAILABLE);
            assertEquals(1L, jdbc.count("connection.rollback"));
            assertEquals(0L, jdbc.count("connection.commit"));
            assertEquals(1L, jdbc.count("connection.close"));
        }
    }

    @Test void failedRollbackIsNotOpaqueNoChangeAndIsNeverRetried() {
        Recording jdbc = new Recording(); jdbc.changed = 0; jdbc.rollbackFails = true;
        redacted(assertThrows(TokenSelectorPersistenceException.class,
                () -> jdbc.repository().revokeExpected(selection(7), TIME)), TRANSACTION_STATE_UNCONFIRMED);
        assertEquals(1L, jdbc.count("connection.rollback"));
        assertEquals(0L, jdbc.count("connection.commit"));
        assertEquals(1L, jdbc.count("connection.close"));
    }

    @Test void commitExceptionStaysUnconfirmedEvenWhenRollbackAcknowledges() {
        for (boolean rollbackFails : new boolean[] {false, true}) {
            Recording jdbc = new Recording(); jdbc.commitFails = true; jdbc.rollbackFails = rollbackFails;
            RevokeResult result = jdbc.repository().revokeExpected(selection(7), TIME);
            assertEquals(Outcome.COMMIT_UNCONFIRMED, result.outcome());
            assertEquals(rollbackFails ? Cleanup.UNCONFIRMED : Cleanup.CONFIRMED, result.cleanup());
            assertEquals(1L, jdbc.count("connection.commit"));
            assertEquals(1L, jdbc.count("connection.rollback"));
            assertEquals(1L, jdbc.count("source.getConnection"));
            assertEquals(1L, jdbc.count("statement.executeUpdate"));
            assertEquals(0L, jdbc.count("statement.executeQuery"));
        }
    }

    @Test void acknowledgedCommitAndRollbackRemainKnownDespiteCleanupFailure() {
        for (int changed : new int[] {0, 1}) {
            Recording jdbc = new Recording(); jdbc.changed = changed;
            jdbc.statementCloseFails = true; jdbc.connectionCloseFails = true;
            RevokeResult result = jdbc.repository().revokeExpected(selection(7), TIME);
            assertEquals(changed == 1 ? Outcome.REVOKED_CONFIRMED : Outcome.NOT_APPLIED, result.outcome());
            assertEquals(Cleanup.UNCONFIRMED, result.cleanup());
            assertEquals(1L, jdbc.count("statement.close"));
            assertEquals(1L, jdbc.count("connection.close"));
        }
        Recording lookup = new Recording(); lookup.connectionCloseFails = true;
        redacted(assertThrows(TokenSelectorPersistenceException.class,
                () -> lookup.repository().lookupExpected(selection(7))), STORAGE_UNAVAILABLE);
    }

    @Test void invalidInputsFailBeforeAcquisitionAndRepositoryDoesNotRenderSource() {
        Recording jdbc = new Recording();
        assertThrows(IllegalArgumentException.class, () -> new JdbcTokenSelectorRepository(null, "safe"));
        for (String schema : new String[] {"bad.schema", "A".repeat(64), "synthetic\";DROP"}) {
            assertThrows(IllegalArgumentException.class, () -> new JdbcTokenSelectorRepository(jdbc.source(), schema));
        }
        assertThrows(IllegalArgumentException.class, () -> jdbc.repository().lookupExpected(null));
        assertThrows(IllegalArgumentException.class, () -> jdbc.repository().revokeExpected(selection(7), null));
        assertEquals("JdbcTokenSelectorRepository[REDACTED]", jdbc.repository().toString());
        assertEquals(0L, jdbc.count("source.getConnection"));
        assertEquals(0L, jdbc.count("source.toString"));
    }

    @Test void commitUncertaintyAndExactSelectionSurviveEveryLaterCleanupFailure() {
        for (boolean rollbackFails : new boolean[] {false, true}) {
            Recording jdbc = new Recording(); jdbc.commitFails = true;
            jdbc.rollbackFails = rollbackFails; jdbc.statementCloseFails = true; jdbc.connectionCloseFails = true;
            RegistryTokenSelection selected = selection(7);
            RevokeResult result = jdbc.repository().revokeExpected(selected, TIME);
            assertEquals(Outcome.COMMIT_UNCONFIRMED, result.outcome());
            assertEquals(Cleanup.UNCONFIRMED, result.cleanup());
            assertEquals(1L, jdbc.count("source.getConnection"));
            assertEquals(1L, jdbc.count("statement.executeUpdate"));
            assertEquals(1L, jdbc.count("connection.commit"));
            assertEquals(1L, jdbc.count("connection.rollback"));
            assertEquals(1L, jdbc.count("statement.close"));
            assertEquals(1L, jdbc.count("connection.close"));
            assertEquals(selected.registryId(), jdbc.bindings.get(2));
            assertEquals(selected.input().selectionId(), jdbc.bindings.get(3));
            assertEquals(7L, jdbc.bindings.get(4));
            assertEquals(selection(7), selected);
        }
    }

    @Test void primaryRollbackAndCleanupDiagnosticsCannotBecomeFailureCauses() {
        for (boolean rollbackFails : new boolean[] {false, true}) {
            Recording jdbc = new Recording(); jdbc.executeFails = true;
            jdbc.rollbackFails = rollbackFails; jdbc.statementCloseFails = true; jdbc.connectionCloseFails = true;
            TokenSelectorPersistenceException failure = assertThrows(TokenSelectorPersistenceException.class,
                    () -> jdbc.repository().revokeExpected(selection(7), TIME));
            redacted(failure, rollbackFails ? TRANSACTION_STATE_UNCONFIRMED : STORAGE_UNAVAILABLE);
            assertEquals(0L, jdbc.count("connection.commit"));
            assertEquals(1L, jdbc.count("connection.rollback"));
            assertEquals(1L, jdbc.count("statement.close"));
            assertEquals(1L, jdbc.count("connection.close"));
        }
    }

}
