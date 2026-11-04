package com.finsec.fuse.reimplementation.persistence;

import com.finsec.fuse.reimplementation.auth.TokenMaterialCodec;
import com.finsec.fuse.reimplementation.auth.TokenRegistryInput;
import com.finsec.fuse.reimplementation.auth.TokenStorageShape;
import java.lang.reflect.Proxy;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic real-codec/real-writer boundary; recording JDBC only, no issuance authority. */
final class TokenMaterialIssuanceBoundaryTest {
    private static final UUID SELECTOR = new UUID(0, 51);
    private static final UUID REGISTRY = new UUID(0, 52);
    private static final Instant ISSUED = Instant.parse("2000-01-01T00:00:00Z");
    private static final byte[] EXPECTED = HexFormat.of().parseHex(
            "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925");

    private static final class Recording {
        final Map<Integer, Object> parameters = new HashMap<>();
        final List<String> calls = new ArrayList<>();
        Runnable acquired = () -> {};
        String sql;
        int row;

        private Object invoke(String owner, String method, Object[] args) {
            calls.add(owner + "." + method);
            if (owner.equals("source") && method.equals("getConnection")) {
                acquired.run();
                return proxy(Connection.class, "connection");
            }
            if (method.equals("close") || method.equals("free")) return null;
            if (owner.equals("connection")) {
                if (method.equals("getAutoCommit")) return true;
                if (method.equals("setAutoCommit")) { assertEquals(false, args[0]); return null; }
                if (method.equals("createArrayOf")) {
                    assertEquals("text", args[0]);
                    return proxy(Array.class, "scope");
                }
                if (method.equals("prepareStatement")) {
                    sql = (String) args[0];
                    return proxy(PreparedStatement.class, "statement");
                }
                if (method.equals("commit") || method.equals("rollback")) return null;
            }
            if (owner.equals("statement")) {
                if (method.startsWith("set")) {
                    Object value = method.equals("setNull") ? null : args[1];
                    parameters.put((Integer) args[0], value instanceof byte[] bytes ? bytes.clone() : value);
                    return null;
                }
                if (method.equals("executeQuery")) return proxy(ResultSet.class, "rows");
            }
            if (owner.equals("rows")) {
                if (method.equals("next")) return row++ == 0;
                if (method.equals("getObject")) {
                    assertEquals(OffsetDateTime.class, args[1]);
                    return switch ((Integer) args[0]) {
                        case 1 -> OffsetDateTime.ofInstant(ISSUED, ZoneOffset.UTC);
                        case 2 -> OffsetDateTime.ofInstant(ISSUED.plusSeconds(7200), ZoneOffset.UTC);
                        case 3 -> null;
                        default -> throw new AssertionError("Unexpected synthetic time column");
                    };
                }
            }
            throw new AssertionError("Unexpected recording JDBC protocol");
        }

        private <T> T proxy(Class<T> type, String owner) {
            return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
                    (proxy, method, args) -> invoke(owner, method.getName(), args)));
        }
        JdbcTokenIssuanceWriter writer() {
            return new JdbcTokenIssuanceWriter(proxy(DataSource.class, "source"), "Synthetic_1");
        }
        long count(String method) { return calls.stream().filter(method::equals).count(); }
    }

    private JdbcTokenIssuanceWriter.InsertResult insert(Recording jdbc, byte[] fingerprint) {
        return jdbc.writer().insertExact(SELECTOR, REGISTRY, fingerprint,
                new TokenRegistryInput("synthetic-actor", TokenRegistryInput.Role.CUSTOMER, List.of()),
                List.of("customer-A"), ISSUED, ISSUED.plusSeconds(7200), "FUSE-SECURITY-1", 7200,
                TokenStorageShape.Status.ACTIVE, null, 0);
    }

    @Test void codecFingerprintBindsToWriterWithoutBearerEnteringSqlParameters() {
        var material = TokenMaterialCodec.encode(new byte[32]);
        Recording jdbc = new Recording();
        var result = insert(jdbc, material.fingerprint());
        assertEquals(JdbcTokenIssuanceWriter.Outcome.INSERT_CONFIRMED, result.outcome());
        assertEquals(JdbcTokenIssuanceWriter.Cleanup.CONFIRMED, result.cleanup());
        assertArrayEquals(EXPECTED, (byte[]) jdbc.parameters.get(2));
        assertEquals(SELECTOR, jdbc.parameters.get(1));
        assertEquals(REGISTRY, jdbc.parameters.get(3));
        assertEquals(14, jdbc.parameters.size());
        assertEquals("A".repeat(43), material.bearer());
        assertFalse(jdbc.sql.contains(material.bearer()));
        assertFalse(jdbc.parameters.values().stream().anyMatch(value ->
                value instanceof String text && text.equals(material.bearer())));
        assertEquals(1L, jdbc.count("source.getConnection"));
        assertEquals(1L, jdbc.count("statement.executeQuery"));
        assertEquals(1L, jdbc.count("connection.commit"));
        assertEquals(0L, jdbc.count("connection.rollback"));
    }

    @Test void callerMutationAtAcquisitionCannotChangeCodecOrWriterFingerprintSnapshots() {
        byte[] raw = new byte[32];
        var material = TokenMaterialCodec.encode(raw);
        byte[] fingerprint = material.fingerprint();
        Recording jdbc = new Recording();
        jdbc.acquired = () -> { raw[0] = 99; fingerprint[0] ^= 1; };
        insert(jdbc, fingerprint);
        assertEquals(99, raw[0]);
        assertNotEquals(EXPECTED[0], fingerprint[0]);
        assertArrayEquals(EXPECTED, material.fingerprint());
        assertEquals("A".repeat(43), material.bearer());
        assertArrayEquals(EXPECTED, (byte[]) jdbc.parameters.get(2));
        byte[] exposed = material.fingerprint(); exposed[1] ^= 1;
        assertArrayEquals(EXPECTED, material.fingerprint());
        assertArrayEquals(EXPECTED, (byte[]) jdbc.parameters.get(2));
        assertEquals(1L, jdbc.count("source.getConnection"));
        assertEquals(1L, jdbc.count("statement.executeQuery"));
    }
}
