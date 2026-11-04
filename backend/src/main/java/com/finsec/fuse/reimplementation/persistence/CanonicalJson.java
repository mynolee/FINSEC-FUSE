package com.finsec.fuse.reimplementation.persistence;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * JDK-only JSON values, immutable copies and deterministic fingerprints.
 * Sorted methods use Java String natural key order; ordered methods retain input Map iteration order.
 * Numbers are finite, normalized decimal JSON numbers; arrays retain their order.
 * Custom numeric subclasses and duplicate string keys are rejected.
 */
public final class CanonicalJson {
    private static final int MAX_DEPTH = 128;
    private static final int MAX_NUMBER_CHARACTERS = 4096;

    private CanonicalJson() {}

    /** Preserves Map iteration order, including nested objects and null values. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> immutableObject(Map<String, ?> object) {
        Objects.requireNonNull(object, "object");
        return (Map<String, Object>) freeze(object, false, new IdentityHashMap<>(), 0);
    }

    public static String write(Object value) {
        return encode(value, true);
    }

    public static String orderedWrite(Object value) {
        return encode(value, false);
    }

    public static String sha256(Object value) {
        return digest(write(value));
    }

    public static String orderedSha256(Object value) {
        return digest(orderedWrite(value));
    }

    private static String encode(Object value, boolean sorted) {
        Object copy = freeze(value, sorted, new IdentityHashMap<>(), 0);
        StringBuilder output = new StringBuilder();
        append(copy, output);
        return output.toString();
    }

    private static String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable", unavailable);
        }
    }

    private static Object freeze(Object value, boolean sorted,
                                 IdentityHashMap<Object, Boolean> active, int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("JSON nesting is too deep");
        }
        if (value == null || value instanceof Boolean) {
            return value;
        }
        if (value instanceof String text) {
            validateString(text);
            return text;
        }
        if (value instanceof Number number) {
            numberText(number);
            return number;
        }
        if (value instanceof Map<?, ?> map) {
            enter(value, active);
            try {
                Map<String, Object> copy = sorted ? new TreeMap<>() : new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!(entry.getKey() instanceof String key)) {
                        throw new IllegalArgumentException("JSON object keys must be strings");
                    }
                    validateString(key);
                    if (copy.containsKey(key)) {
                        throw new IllegalArgumentException("Duplicate JSON object key");
                    }
                    copy.put(key, freeze(entry.getValue(), sorted, active, depth + 1));
                }
                return Collections.unmodifiableMap(new LinkedHashMap<>(copy));
            } finally {
                active.remove(value);
            }
        }
        if (value instanceof List<?> list) {
            enter(value, active);
            try {
                List<Object> copy = new ArrayList<>(list.size());
                for (Object element : list) {
                    copy.add(freeze(element, sorted, active, depth + 1));
                }
                return Collections.unmodifiableList(copy);
            } finally {
                active.remove(value);
            }
        }
        throw new IllegalArgumentException("Unsupported JSON value type");
    }

    private static void enter(Object value, IdentityHashMap<Object, Boolean> active) {
        if (active.put(value, Boolean.TRUE) != null) {
            throw new IllegalArgumentException("Cyclic JSON values are not supported");
        }
    }

    private static void validateString(String text) {
        for (int i = 0; i < text.length(); i++) {
            char current = text.charAt(i);
            if (Character.isHighSurrogate(current)) {
                if (i + 1 >= text.length() || !Character.isLowSurrogate(text.charAt(i + 1))) {
                    throw new IllegalArgumentException("Unpaired JSON string surrogate");
                }
                i++;
            } else if (Character.isLowSurrogate(current)) {
                throw new IllegalArgumentException("Unpaired JSON string surrogate");
            }
        }
    }

    private static String numberText(Number number) {
        // BigDecimal and BigInteger are extensible: a subclass can expose mutable
        // numeric state even though the containing maps/lists are unmodifiable.
        if ((number instanceof BigDecimal && number.getClass() != BigDecimal.class)
                || (number instanceof BigInteger && number.getClass() != BigInteger.class)) {
            throw new IllegalArgumentException("Unsupported JSON number type");
        }
        BigDecimal decimal;
        if (number instanceof BigDecimal value) {
            decimal = value;
        } else if (number instanceof BigInteger value) {
            decimal = new BigDecimal(value);
        } else if (number instanceof Byte || number instanceof Short
                || number instanceof Integer || number instanceof Long) {
            decimal = BigDecimal.valueOf(number.longValue());
        } else if (number instanceof Float value) {
            if (!Float.isFinite(value)) {
                throw new IllegalArgumentException("JSON numbers must be finite");
            }
            decimal = new BigDecimal(Float.toString(value));
        } else if (number instanceof Double value) {
            if (!Double.isFinite(value)) {
                throw new IllegalArgumentException("JSON numbers must be finite");
            }
            decimal = BigDecimal.valueOf(value);
        } else {
            throw new IllegalArgumentException("Unsupported JSON number type");
        }
        if (decimal.signum() == 0) {
            return "0";
        }
        BigDecimal normalized;
        try {
            normalized = decimal.stripTrailingZeros();
        } catch (ArithmeticException unsupportedScale) {
            throw new IllegalArgumentException("JSON number representation exceeds supported limits");
        }
        long scale = normalized.scale();
        long precision = normalized.precision();
        long characters = scale <= 0 ? precision - scale : Math.max(precision + 1, scale + 2);
        if (normalized.signum() < 0) characters++;
        if (characters > MAX_NUMBER_CHARACTERS) {
            throw new IllegalArgumentException("JSON number representation exceeds supported limits");
        }
        return normalized.toPlainString();
    }

    private static void append(Object value, StringBuilder output) {
        if (value == null) {
            output.append("null");
        } else if (value instanceof String text) {
            appendString(text, output);
        } else if (value instanceof Boolean bool) {
            output.append(bool);
        } else if (value instanceof Number number) {
            output.append(numberText(number));
        } else if (value instanceof Map<?, ?> map) {
            output.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) output.append(',');
                first = false;
                appendString((String) entry.getKey(), output);
                output.append(':');
                append(entry.getValue(), output);
            }
            output.append('}');
        } else if (value instanceof List<?> list) {
            output.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) output.append(',');
                append(list.get(i), output);
            }
            output.append(']');
        } else {
            throw new IllegalArgumentException("Unsupported JSON value type");
        }
    }

    private static void appendString(String text, StringBuilder output) {
        output.append('"');
        for (int i = 0; i < text.length(); i++) {
            char current = text.charAt(i);
            switch (current) {
                case '"' -> output.append("\\\"");
                case '\\' -> output.append("\\\\");
                case '\b' -> output.append("\\b");
                case '\f' -> output.append("\\f");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                default -> {
                    if (current < 0x20) {
                        String hexadecimal = Integer.toHexString(current);
                        output.append("\\u").append("0".repeat(4 - hexadecimal.length())).append(hexadecimal);
                    } else {
                        output.append(current);
                    }
                }
            }
        }
        output.append('"');
    }
}
