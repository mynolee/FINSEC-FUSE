package com.finsec.fuse.reimplementation.http;

import com.finsec.fuse.reimplementation.simulation.SimulationFailure;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import static org.junit.jupiter.api.Assertions.*;

/** Public header extraction only. Fixed structural byte patterns are not live credentials or authority. */
class LocalVirtualBearerHeaderTest {
    private static final String ZERO = "A".repeat(43);
    private static final String ONES = "_".repeat(42) + "8";
    private static final class Request extends MockHttpServletRequest {
        final List<String> values; final boolean nullEnumeration;
        int headerReads, enumerationChecks, nextReads;
        Request(List<String> values) { this.values = values; nullEnumeration = values == null; }
        @Override public Enumeration<String> getHeaders(String name) {
            assertEquals("Authorization", name); headerReads++;
            if (nullEnumeration) return null;
            Iterator<String> iterator = values.iterator();
            return new Enumeration<>() {
                public boolean hasMoreElements() { enumerationChecks++; return iterator.hasNext(); }
                public String nextElement() { nextReads++; return iterator.next(); }
            };
        }
        @Override public String getHeader(String name) { throw new AssertionError("Must use all header values"); }
        @Override public void setAttribute(String name, Object value) { throw new AssertionError("Never retain extracted credential"); }
    }
    private static SimulationFailure rejected(Request request) {
        var failure = assertThrows(SimulationFailure.class, () -> LocalVirtualBearerHeader.canonical(request));
        assertEquals(401, failure.status()); assertEquals("UNAUTHENTICATED", failure.code());
        assertEquals("UNAUTHENTICATED", failure.getMessage()); assertNull(failure.getCause());
        assertEquals(1, request.headerReads);
        assertFalse(failure.toString().contains(ZERO)); assertFalse(failure.toString().contains(ONES));
        assertFalse(failure.toString().contains("synthetic-private-bearer-canary"));
        return failure;
    }
    @Test void canonicalStructural32BytePatternsAndSchemeCaseUseActualEnumeration() {
        for (String token : List.of(ZERO, ONES, "-" + "A".repeat(42), "_" + "A".repeat(42))) {
            for (String scheme : List.of("Bearer", "bearer", "bEaReR")) {
                var request = new Request(List.of(scheme + " " + token));
                assertEquals(token, LocalVirtualBearerHeader.canonical(request));
                assertEquals(1, request.headerReads); assertEquals(1, request.nextReads);
                assertEquals(2, request.enumerationChecks);
            }
        }
    }
    @Test void missingNullEnumerationAndNullValueAreUnauthenticatedNotAbsentAuthorityDefaults() {
        rejected(new Request(null)); rejected(new Request(List.of()));
        rejected(new Request(Collections.singletonList(null)));
        assertThrows(NullPointerException.class, () -> LocalVirtualBearerHeader.canonical(null));
    }
    @Test void repeatedHeadersRejectBeforeReadingASecondSensitiveValue() {
        var request = new Request(List.of("Bearer " + ZERO, "Bearer " + ONES));
        rejected(request); assertEquals(1, request.nextReads); assertEquals(2, request.enumerationChecks);
        rejected(new Request(List.of("Bearer " + ZERO, "Bearer " + ZERO)));
        rejected(new Request(List.of("Bearer " + ZERO + ", Bearer " + ONES)));
    }
    @Test void framingRequiresExactlyOneAsciiSpaceAndNoTrimmingOrLineFolding() {
        for (String header : List.of("Basic " + ZERO, " Bearer " + ZERO, "Bearer  " + ZERO,
                "Bearer\t" + ZERO, "Bearer\u00a0" + ZERO, "Bearer " + ZERO + " ",
                "Bearer " + ZERO + "\r\n", "Bearer" + ZERO, "Bearer " + ZERO + ","))
            rejected(new Request(List.of(header)));
    }
    @Test void exactLengthAndUrlAlphabetRejectPaddingStandardBase64AndTextMaterial() {
        for (String token : List.of("A".repeat(42), "A".repeat(44), ZERO + "=", "A".repeat(42) + "=",
                "+" + "A".repeat(42), "/" + "A".repeat(42), "A".repeat(42) + "\t",
                "A".repeat(42) + "한", "synthetic-private-bearer-canary"))
            rejected(new Request(List.of("Bearer " + token)));
    }
    @Test void alternateUnusedTrailingBitsCannotAliasTheCanonical32ByteValue() {
        // 43 URL characters encode32 bytes; low2 bits of the last symbol must be zero.
        // B/C/D differ only in those unused bits from canonical A and must be refused.
        for (String last : List.of("B", "C", "D"))
            rejected(new Request(List.of("Bearer " + "A".repeat(42) + last)));
        assertEquals(ZERO, LocalVirtualBearerHeader.canonical(new Request(List.of("Bearer " + ZERO))));
    }
    @Test void servletMockHeaderNamesAreCaseInsensitiveButRepeatedValuesStillFail() {
        var single = new MockHttpServletRequest(); single.addHeader("authorization", "Bearer " + ZERO);
        assertEquals(ZERO, LocalVirtualBearerHeader.canonical(single));
        single.addHeader("AUTHORIZATION", "Bearer " + ONES);
        var failure = assertThrows(SimulationFailure.class, () -> LocalVirtualBearerHeader.canonical(single));
        assertEquals(401, failure.status()); assertEquals("UNAUTHENTICATED", failure.getMessage());
        assertNull(failure.getCause());
    }
}
