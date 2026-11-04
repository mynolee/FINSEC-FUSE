package com.finsec.fuse.reimplementation.persistence;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic transport vectors; no model, database, HTTP client or external fixture is used. */
class CanonicalJsonTransportRegressionTest {
    @Test void orderedIntegerBindingsUseDecimalDigitsRatherThanExponentNotation() throws Exception {
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("generation", 10);
        input.put("documentVersion", 1000);
        input.put("maximumLong", Long.MAX_VALUE);
        input.put("negative", -10L);
        input.put("minimumLong", Long.MIN_VALUE);
        input.put("zero", 0);
        String expected = "{\"generation\":10,\"documentVersion\":1000,\"maximumLong\":"
                + Long.MAX_VALUE + ",\"negative\":-10,\"minimumLong\":" + Long.MIN_VALUE + ",\"zero\":0}";
        assertEquals(expected, CanonicalJson.orderedWrite(input));
        assertEquals(digest(expected), CanonicalJson.orderedSha256(input));
        assertEquals(Long.toString(Long.MAX_VALUE), CanonicalJson.orderedWrite(Long.MAX_VALUE));
        assertEquals(Long.toString(Long.MIN_VALUE), CanonicalJson.orderedWrite(Long.MIN_VALUE));
    }

    @Test void sortedAndOrderedNumericValidationShareTheSamePlainNormalizedNumbers() {
        assertEquals("1000", CanonicalJson.write(new BigDecimal("1e3")));
        assertEquals("1000", CanonicalJson.orderedWrite(new BigDecimal("1000.000")));
        assertEquals("-1000", CanonicalJson.orderedWrite(new BigDecimal("-1e3")));
        assertEquals("-123456789012345678901234567890",
                CanonicalJson.orderedWrite(new BigInteger("-123456789012345678901234567890")));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(new BigDecimal("1e5000")));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.orderedWrite(Double.NEGATIVE_INFINITY));
    }

    @Test void validUnicodeCodePointsRemainUtf8AndAreNotAsciiEscapedOrNormalized() throws Exception {
        String text = "\uD55C\uAE00" + new String(Character.toChars(0x1F680)) + " e\u0301";
        Map<String, Object> input = Map.of("text", text);
        String expected = "{\"text\":\"" + text + "\"}";
        assertEquals(expected, CanonicalJson.orderedWrite(input));
        assertEquals(digest(expected), CanonicalJson.orderedSha256(input));
        assertNotEquals(CanonicalJson.orderedSha256(Map.of("text", "\u00E9")),
                CanonicalJson.orderedSha256(Map.of("text", "e\u0301")));
        assertThrows(IllegalArgumentException.class,
                () -> CanonicalJson.orderedWrite(Map.of("text", String.valueOf((char) 0xD800))));
        assertThrows(IllegalArgumentException.class,
                () -> CanonicalJson.write(Map.of(String.valueOf((char) 0xDC00), "text")));
    }

    @Test void controlsQuotesAndBackslashesUseJsonEscapesRatherThanRawControlCharacters() {
        String encoded = CanonicalJson.orderedWrite("a\nb\t\"\\");
        assertEquals("\"a\\nb\\t\\\"\\\\\"", encoded);
    }

    private static String digest(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
    }
}
