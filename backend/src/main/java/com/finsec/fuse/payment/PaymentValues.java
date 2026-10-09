package com.finsec.fuse.payment;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

/** JDBC values are normalized here without using floating-point amounts or application clocks. */
public final class PaymentValues {
    private PaymentValues() {}
    public static UUID uuid(Map<String, Object> row, String name) {
        Object value = row.get(name);
        return value == null ? null : value instanceof UUID id ? id : UUID.fromString(value.toString());
    }
    public static String str(Map<String, Object> row, String name) {
        Object value = row.get(name);
        return value == null ? null : value.toString();
    }
    public static int integer(Map<String, Object> row, String name) { return ((Number) row.get(name)).intValue(); }
    public static long number(Map<String, Object> row, String name) { return ((Number) row.get(name)).longValue(); }
    public static Instant instant(Map<String, Object> row, String name) {
        Object value = row.get(name);
        if (value == null) return null;
        if (value instanceof Instant instant) return instant;
        if (value instanceof Timestamp timestamp) return timestamp.toInstant();
        if (value instanceof OffsetDateTime offset) return offset.toInstant();
        return Instant.parse(value.toString());
    }
}
