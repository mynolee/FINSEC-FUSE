package com.finsec.fuse.reimplementation.persistence;

import com.finsec.fuse.reimplementation.auth.TokenRegistryInput;
import com.finsec.fuse.reimplementation.auth.TokenStorageShape;
import java.lang.reflect.Proxy;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.persistence.JdbcTokenIssuanceWriter.*;

/** Synthetic recording interfaces only: no actual DB/FK/unique/durability proof. */
class JdbcTokenIssuanceWriterTest {
    private static final Instant TIME = Instant.parse("2000-01-01T00:00:00Z");
    private static final UUID SELECTOR = new UUID(0, 1);
    private static final UUID REGISTRY = new UUID(0, 2);

    private static final class Recording {
        final List<String> calls = new ArrayList<>();
        final Map<Integer, Object> bindings = new HashMap<>();
        final Map<Integer, Integer> sqlTypes = new HashMap<>();
        final List<List<Object>> scopeValues = new ArrayList<>();
        final Set<String> closeFailures = new HashSet<>();
        boolean autoCommit = true, executeFails, commitFails, rollbackFails, secondArrayFails, executeError;
        Runnable onAcquire = () -> {};
        int arrays, row = -1;
        Object[][] returned = {{utc(TIME), utc(TIME.plusSeconds(7200)), null}};
        String sql;

        private SQLException sensitive() {
            SQLException failure = new SQLException("SYNTHETIC_DRIVER_SECRET", new RuntimeException("SYNTHETIC_DRIVER_CAUSE"));
            failure.addSuppressed(new RuntimeException("SYNTHETIC_DRIVER_SUPPRESSED"));
            failure.setNextException(new SQLException("SYNTHETIC_DRIVER_NEXT"));
            return failure;
        }

        private Object invoke(String owner, String name, Object[] args) throws SQLException {
            calls.add(owner + "." + name);
            if (name.equals("toString")) return "SYNTHETIC_SOURCE_IDENTIFIER";
            if (name.equals("close") || name.equals("free")) {
                if (closeFailures.contains(owner)) throw sensitive();
                return null;
            }
            if (owner.equals("source") && name.equals("getConnection")) {
                onAcquire.run(); return proxy(Connection.class, "connection");
            }
            if (owner.equals("connection")) {
                if (name.equals("getAutoCommit")) return autoCommit;
                if (name.equals("setAutoCommit")) { autoCommit = (Boolean) args[0]; return null; }
                if (name.equals("createArrayOf")) {
                    arrays++;
                    if (secondArrayFails && arrays == 2) throw sensitive();
                    assertEquals("text", args[0]);
                    scopeValues.add(Arrays.asList(((Object[]) args[1]).clone()));
                    return proxy(Array.class, arrays == 1 ? "initialArray" : "currentArray");
                }
                if (name.equals("prepareStatement")) { sql = (String) args[0]; return proxy(PreparedStatement.class, "statement"); }
                if (name.equals("commit")) { if (commitFails) throw sensitive(); return null; }
                if (name.equals("rollback")) { if (rollbackFails) throw sensitive(); return null; }
            }
            if (owner.equals("statement")) {
                if (name.startsWith("set")) {
                    Object value = name.equals("setNull") ? null : args[1];
                    if (value instanceof byte[] bytes) value = bytes.clone();
                    bindings.put((Integer) args[0], value);
                    if (name.equals("setNull")) sqlTypes.put((Integer) args[0], (Integer) args[1]);
                    else if (args.length == 3) sqlTypes.put((Integer) args[0], (Integer) args[2]);
                    return null;
                }
                if (name.equals("executeQuery")) {
                    if (executeError) throw new AssertionError("SYNTHETIC_FATAL_DRIVER_ERROR");
                    if (executeFails) throw sensitive();
                    return proxy(ResultSet.class, "rows");
                }
            }
            if (owner.equals("rows")) {
                if (name.equals("next")) return ++row < returned.length;
                if (name.equals("getObject")) { assertEquals(OffsetDateTime.class, args[1]); return returned[row][(Integer) args[0] - 1]; }
            }
            throw new AssertionError("Unexpected synthetic protocol " + owner + "." + name);
        }

        private <T> T proxy(Class<T> type, String owner) {
            return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
                    (proxy, method, args) -> invoke(owner, method.getName(), args)));
        }
        DataSource source() { return proxy(DataSource.class, "source"); }
        JdbcTokenIssuanceWriter writer() { return new JdbcTokenIssuanceWriter(source(), "Synthetic_1"); }
        long count(String call) { return calls.stream().filter(call::equals).count(); }
    }

    private static OffsetDateTime utc(Instant time) { return OffsetDateTime.ofInstant(time, ZoneOffset.UTC); }
    private static TokenRegistryInput initial() {
        return new TokenRegistryInput("synthetic-actor", TokenRegistryInput.Role.CUSTOMER, List.of());
    }
    private static InsertResult insert(Recording jdbc) {
        return jdbc.writer().insertExact(SELECTOR, REGISTRY, new byte[32], initial(), List.of("customer-B"),
                TIME, TIME.plusSeconds(7200), "FUSE-SECURITY-1", 7200,
                TokenStorageShape.Status.ACTIVE, null, 0);
    }
    private static void fixed(StorageFailure error, Code code) {
        assertEquals(code, error.code()); assertEquals(code.name(), error.getMessage());
        assertNull(error.getCause()); assertEquals(0, error.getSuppressed().length);
        assertFalse(error.toString().contains("SYNTHETIC_DRIVER"));
    }

    @Test void fourteenExplicitValuesPreserveIndependentScopesAndSchemaValidRevokedMaxRow() {
        Recording jdbc = new Recording(); jdbc.returned[0][2] = utc(TIME);
        InsertResult result = jdbc.writer().insertExact(SELECTOR, REGISTRY, new byte[32], initial(),
                List.of("customer-B"), TIME, TIME.plusSeconds(7200), "FUSE-SECURITY-1", 7200,
                TokenStorageShape.Status.REVOKED, TIME, Long.MAX_VALUE);
        assertEquals(Outcome.INSERT_CONFIRMED, result.outcome());
        assertEquals(14, jdbc.bindings.size());
        assertEquals(SELECTOR, jdbc.bindings.get(1)); assertArrayEquals(new byte[32], (byte[]) jdbc.bindings.get(2));
        assertEquals(REGISTRY, jdbc.bindings.get(3)); assertEquals("synthetic-actor", jdbc.bindings.get(4));
        assertEquals("CUSTOMER", jdbc.bindings.get(5)); assertNotNull(jdbc.bindings.get(6)); assertNotNull(jdbc.bindings.get(7));
        assertEquals(List.of(), jdbc.scopeValues.get(0)); assertEquals(List.of("customer-B"), jdbc.scopeValues.get(1));
        assertEquals(utc(TIME), jdbc.bindings.get(8)); assertEquals(utc(TIME.plusSeconds(7200)), jdbc.bindings.get(9));
        assertEquals(Integer.valueOf(Types.TIMESTAMP_WITH_TIMEZONE), jdbc.sqlTypes.get(8));
        assertEquals(Integer.valueOf(Types.TIMESTAMP_WITH_TIMEZONE), jdbc.sqlTypes.get(9));
        assertEquals(Integer.valueOf(Types.TIMESTAMP_WITH_TIMEZONE), jdbc.sqlTypes.get(13));
        assertEquals("FUSE-SECURITY-1", jdbc.bindings.get(10)); assertEquals(7200, jdbc.bindings.get(11));
        assertEquals("REVOKED", jdbc.bindings.get(12)); assertEquals(utc(TIME), jdbc.bindings.get(13));
        assertEquals(Long.MAX_VALUE, jdbc.bindings.get(14));
        assertTrue(jdbc.sql.startsWith("INSERT INTO \"Synthetic_1\".demo_token"));
        assertFalse(jdbc.sql.contains("ON CONFLICT")); assertFalse(jdbc.sql.contains("UPDATE "));
        assertEquals(1L, jdbc.count("connection.commit"));
    }

    @Test void callerFingerprintAndCurrentScopeMutationAfterSnapshotCannotAlterBindings() {
        Recording jdbc = new Recording(); byte[] fingerprint = new byte[32];
        List<String> scope = new ArrayList<>(List.of("customer-B"));
        jdbc.onAcquire = () -> { fingerprint[0] = 99; scope.clear(); scope.add("customer-C"); };
        jdbc.writer().insertExact(SELECTOR, REGISTRY, fingerprint, initial(), scope, TIME, TIME.plusSeconds(7200),
                "FUSE-SECURITY-1", 7200, TokenStorageShape.Status.ACTIVE, null, 0);
        assertArrayEquals(new byte[32], (byte[]) jdbc.bindings.get(2));
        assertEquals(List.of("customer-B"), jdbc.scopeValues.get(1));
        assertNull(jdbc.bindings.get(13));
    }

    @Test void allFourPrecommitCleanupExceptionsRollbackWithoutCommitAndAttemptEveryHandleOnce() {
        for (String failed : List.of("rows", "statement", "initialArray", "currentArray")) {
            Recording jdbc = new Recording(); jdbc.closeFailures.add(failed);
            fixed(assertThrows(StorageFailure.class, () -> insert(jdbc)), Code.STORAGE_UNAVAILABLE);
            for (String call : List.of("rows.close", "statement.close", "initialArray.free", "currentArray.free", "connection.close")) {
                assertEquals(1L, jdbc.count(call));
            }
            assertEquals(0L, jdbc.count("connection.commit")); assertEquals(1L, jdbc.count("connection.rollback"));
        }
    }

    @Test void malformedNullExtraOrRoundedReturnedTimesFailBeforeCommit() {
        Object[] correct = {utc(TIME), utc(TIME.plusSeconds(7200)), null};
        for (Object[][] rows : new Object[][][] { {}, {{null, correct[1], null}},
                {{"synthetic-wrong-type", correct[1], null}}, {{correct[0], correct[1], utc(TIME)}},
                {{utc(TIME.plusNanos(1)), correct[1], null}}, {correct, correct} }) {
            Recording jdbc = new Recording(); jdbc.returned = rows;
            fixed(assertThrows(StorageFailure.class, () -> insert(jdbc)), Code.STORAGE_UNAVAILABLE);
            assertEquals(0L, jdbc.count("connection.commit")); assertEquals(1L, jdbc.count("connection.rollback"));
        }
        Recording rounded = new Recording();
        fixed(assertThrows(StorageFailure.class, () -> rounded.writer().insertExact(SELECTOR, REGISTRY,
                new byte[32], initial(), List.of(), TIME.plusNanos(1), TIME.plusNanos(1).plusSeconds(7200),
                "FUSE-SECURITY-1", 7200, TokenStorageShape.Status.ACTIVE, null, 0)), Code.STORAGE_UNAVAILABLE);
        assertEquals(0L, rounded.count("connection.commit"));
    }

    @Test void resourcesAreClosedBeforeSingleCommitAndConnectionAfterward() {
        Recording jdbc = new Recording(); InsertResult result = insert(jdbc);
        assertEquals(Cleanup.CONFIRMED, result.cleanup());
        int commit = jdbc.calls.indexOf("connection.commit");
        for (String call : List.of("rows.close", "statement.close", "initialArray.free", "currentArray.free")) {
            assertTrue(jdbc.calls.indexOf(call) >= 0 && jdbc.calls.indexOf(call) < commit);
        }
        assertTrue(jdbc.calls.indexOf("connection.close") > commit);
        assertEquals(1L, jdbc.count("connection.setAutoCommit")); assertEquals(0L, jdbc.count("connection.rollback"));
        assertEquals("TokenIssuanceInsertResult[REDACTED]", result.toString());
    }

    @Test void commitFailureStaysUncertainAndNeverRetriesEvenIfRollbackSucceeds() {
        for (boolean rollbackFails : new boolean[] {false, true}) {
            Recording jdbc = new Recording(); jdbc.commitFails = true; jdbc.rollbackFails = rollbackFails;
            InsertResult result = insert(jdbc);
            assertEquals(Outcome.COMMIT_UNCONFIRMED, result.outcome());
            assertEquals(rollbackFails ? Cleanup.UNCONFIRMED : Cleanup.CONFIRMED, result.cleanup());
            assertEquals(1L, jdbc.count("source.getConnection")); assertEquals(1L, jdbc.count("statement.executeQuery"));
            assertEquals(1L, jdbc.count("connection.commit")); assertEquals(1L, jdbc.count("connection.rollback"));
        }
    }

    @Test void acknowledgedCommitDoesNotBecomeRetryableFailureWhenConnectionCloseFails() {
        Recording jdbc = new Recording(); jdbc.closeFailures.add("connection");
        InsertResult result = insert(jdbc);
        assertEquals(Outcome.INSERT_CONFIRMED, result.outcome()); assertEquals(Cleanup.UNCONFIRMED, result.cleanup());
        assertEquals(1L, jdbc.count("connection.commit")); assertEquals(0L, jdbc.count("connection.rollback"));
    }

    @Test void precommitSqlErrorAndFailedRollbackHaveFixedSeparateClassifications() {
        for (boolean rollbackFails : new boolean[] {false, true}) {
            Recording jdbc = new Recording(); jdbc.executeFails = true; jdbc.rollbackFails = rollbackFails;
            fixed(assertThrows(StorageFailure.class, () -> insert(jdbc)),
                    rollbackFails ? Code.TRANSACTION_STATE_UNCONFIRMED : Code.STORAGE_UNAVAILABLE);
            assertEquals(1L, jdbc.count("connection.rollback")); assertEquals(0L, jdbc.count("connection.commit"));
        }
        Recording partial = new Recording(); partial.secondArrayFails = true;
        fixed(assertThrows(StorageFailure.class, () -> insert(partial)), Code.STORAGE_UNAVAILABLE);
        assertEquals(1L, partial.count("initialArray.free")); assertEquals(0L, partial.count("statement.executeQuery"));
    }

    @Test void invalidShapeOrMissingSelectorRejectsBeforeAnyAcquisitionAndNoDefaultsAreInvented() {
        Recording jdbc = new Recording();
        assertThrows(IllegalArgumentException.class, () -> jdbc.writer().insertExact(null, REGISTRY, new byte[32],
                initial(), List.of(), TIME, TIME.plusSeconds(7200), "FUSE-SECURITY-1", 7200,
                TokenStorageShape.Status.ACTIVE, null, 0));
        assertThrows(IllegalArgumentException.class, () -> jdbc.writer().insertExact(SELECTOR, REGISTRY, new byte[31],
                initial(), List.of(), TIME, TIME.plusSeconds(7200), "FUSE-SECURITY-1", 7200,
                TokenStorageShape.Status.ACTIVE, null, 0));
        assertThrows(IllegalArgumentException.class, () -> new JdbcTokenIssuanceWriter(jdbc.source(), "bad.schema"));
        assertEquals(0L, jdbc.count("source.getConnection"));
        assertEquals("JdbcTokenIssuanceWriter[REDACTED]", jdbc.writer().toString());
        assertEquals(0L, jdbc.count("source.toString"));
    }

    @Test void ambientTransactionIsNeverJoinedOrModified() {
        Recording jdbc = new Recording(); jdbc.autoCommit = false;
        fixed(assertThrows(StorageFailure.class, () -> insert(jdbc)), Code.STORAGE_UNAVAILABLE);
        for (String call : List.of("connection.setAutoCommit", "connection.createArrayOf", "connection.prepareStatement",
                "connection.commit", "connection.rollback")) assertEquals(0L, jdbc.count(call));
        assertEquals(1L, jdbc.count("connection.close"));
    }

    @Test void fatalErrorIsNotSwallowedOrConvertedToTypedStorageOutcome() {
        Recording jdbc = new Recording(); jdbc.executeError = true;
        assertThrows(AssertionError.class, () -> insert(jdbc));
        assertEquals(0L, jdbc.count("connection.commit"));
        // No universal Error cleanup, rollback, redaction or no-mutation guarantee is inferred.
    }

    @Test void commitUncertaintySurvivesSimultaneousRollbackAndConnectionCloseFailures() {
        for (boolean rollbackFails : new boolean[] {false, true}) {
            Recording jdbc = new Recording(); jdbc.commitFails = true;
            jdbc.rollbackFails = rollbackFails; jdbc.closeFailures.add("connection");
            InsertResult result = insert(jdbc);
            assertEquals(Outcome.COMMIT_UNCONFIRMED, result.outcome());
            assertEquals(Cleanup.UNCONFIRMED, result.cleanup());
            assertEquals(1L, jdbc.count("source.getConnection"));
            assertEquals(1L, jdbc.count("statement.executeQuery"));
            assertEquals(1L, jdbc.count("connection.commit"));
            assertEquals(1L, jdbc.count("connection.rollback"));
            assertEquals(1L, jdbc.count("connection.close"));
            assertEquals(SELECTOR, jdbc.bindings.get(1));
            assertEquals(REGISTRY, jdbc.bindings.get(3));
            assertFalse(result.toString().contains("SYNTHETIC_DRIVER"));
        }
    }

    @Test void primaryRollbackAndAllCleanupDiagnosticChainsStayDetached() {
        for (boolean rollbackFails : new boolean[] {false, true}) {
            Recording jdbc = new Recording(); jdbc.executeFails = true;
            jdbc.rollbackFails = rollbackFails;
            jdbc.closeFailures.addAll(List.of("statement", "initialArray", "currentArray", "connection"));
            StorageFailure failure = assertThrows(StorageFailure.class, () -> insert(jdbc));
            fixed(failure, rollbackFails ? Code.TRANSACTION_STATE_UNCONFIRMED : Code.STORAGE_UNAVAILABLE);
            assertEquals(0L, jdbc.count("connection.commit"));
            assertEquals(1L, jdbc.count("connection.rollback"));
            for (String call : List.of("statement.close", "initialArray.free", "currentArray.free", "connection.close"))
                assertEquals(1L, jdbc.count(call));
            assertEquals(SELECTOR, jdbc.bindings.get(1));
            assertEquals(REGISTRY, jdbc.bindings.get(3));
        }
    }

}
