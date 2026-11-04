package com.finsec.fuse.reimplementation.persistence;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CanonicalJsonTest {
    @Test void rejectsEqualStringKeysFromIdentityMapsInsteadOfSilentlyCollapsingThem() {
        var source = new IdentityHashMap<String, Object>();
        source.put(new String("amount"), 1);
        source.put(new String("amount"), 2);
        assertEquals(2, source.size());
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(source));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.orderedWrite(source));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.immutableObject(source));
    }

    @Test void sortsKeysForFingerprintsButRetainsObjectOrderForOrderedBindings() {
        Map<String, Object> first = new LinkedHashMap<>();
        first.put("z", 2);
        first.put("a", Map.of("b", 1));
        Map<String, Object> second = new LinkedHashMap<>();
        second.put("a", Map.of("b", 1));
        second.put("z", 2);
        assertEquals("{\"a\":{\"b\":1},\"z\":2}", CanonicalJson.write(first));
        assertEquals(CanonicalJson.sha256(first), CanonicalJson.sha256(second));
        assertEquals("{\"z\":2,\"a\":{\"b\":1}}", CanonicalJson.orderedWrite(first));
        assertNotEquals(CanonicalJson.orderedSha256(first), CanonicalJson.orderedSha256(second));
        assertEquals(CanonicalJson.orderedWrite(first),
                CanonicalJson.orderedWrite(CanonicalJson.immutableObject(first)));
    }

    @Test void arrayOrderIsSignificantAndFiniteDecimalNumbersAreNormalized() {
        assertNotEquals(CanonicalJson.sha256(List.of(1, 2)), CanonicalJson.sha256(List.of(2, 1)));
        assertEquals("1", CanonicalJson.write(new BigDecimal("1.000")));
        assertEquals(CanonicalJson.sha256(1000), CanonicalJson.sha256(new BigDecimal("1e3")));
        assertEquals("0", CanonicalJson.write(-0.0d));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(Double.NaN));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.orderedWrite(Float.POSITIVE_INFINITY));
    }

    @Test void preservesJsonNullAndEscapesControlsWithoutAcceptingBrokenUnicode() {
        Map<String, Object> source = new LinkedHashMap<>();
        source.put("nothing", null);
        source.put("text", "line\n\t\"\\");
        String encoded = CanonicalJson.write(source);
        assertTrue(encoded.contains("\"nothing\":null"));
        assertTrue(encoded.contains("\\n\\t\\\"\\\\"));
        assertFalse(encoded.contains("\n"));
        assertEquals("\"" + new String(Character.toChars(0x1F600)) + "\"",
                CanonicalJson.orderedWrite(new String(Character.toChars(0x1F600))));
        assertThrows(IllegalArgumentException.class,
                () -> CanonicalJson.write(String.valueOf((char) 0xD800)));
        assertThrows(IllegalArgumentException.class,
                () -> CanonicalJson.orderedWrite(String.valueOf((char) 0xDC00)));
    }

    @Test void copiesNestedValuesAndRejectsUnsupportedOrCyclicValues() {
        List<Object> nested = new ArrayList<>();
        nested.add("original");
        nested.add(null);
        Map<String, Object> original = new LinkedHashMap<>();
        original.put("items", nested);
        var copy = CanonicalJson.immutableObject(original);
        nested.set(0, "changed");
        assertEquals("original", ((List<?>) copy.get("items")).getFirst());
        assertNull(((List<?>) copy.get("items")).get(1));
        assertThrows(UnsupportedOperationException.class, () -> copy.put("other", true));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(UUID.randomUUID()));
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(Map.of(1, "not a string key")));
        original.put("self", original);
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.write(original));
    }
}
