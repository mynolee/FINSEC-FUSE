package com.finsec.fuse.reimplementation.http;

import jakarta.servlet.ServletInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import static org.junit.jupiter.api.Assertions.*;

/** Calls the actual public byte decoder with explicit synthetic limits and mock request enumeration. */
class TypedWorkflowRequestDecoderTest {
    private static final String COMMAND = "00000000-0000-4000-8000-00000000abce";
    private static final String REQUEST = "00000000-0000-4000-8000-00000000abcd";
    private static final String CANARY = "synthetic-private-command-body-or-header-canary";
    private static byte[] bytes(String body) { return body.getBytes(StandardCharsets.UTF_8); }
    private static byte[] valid() { return bytes("{\"commandRef\":\"" + COMMAND + "\"}"); }
    private static final class Request extends MockHttpServletRequest {
        final List<String> values; int headerReads, nextReads;
        Request(List<String> values) { this.values = values; }
        @Override public Enumeration<String> getHeaders(String name) {
            assertEquals("Idempotency-Key", name); headerReads++;
            if (values == null) return null;
            var iterator = values.iterator();
            return new Enumeration<>() {
                public boolean hasMoreElements() { return iterator.hasNext(); }
                public String nextElement() { nextReads++; return iterator.next(); }
            };
        }
        @Override public String getHeader(String name) { throw new AssertionError("Must enumerate repeated headers"); }
        @Override public ServletInputStream getInputStream() { throw new AssertionError("Supplied bounded bytes only"); }
    }
    private static TypedWorkflowRequestDecoder decoder(int bytes, int depth) {
        return new TypedWorkflowRequestDecoder(new HttpLimits(512, bytes, depth));
    }
    private static PublicHttpErrors.Rejected rejected(TypedWorkflowRequestDecoder decoder, Request request,
            byte[] body, PublicHttpErrors.Error expected) {
        var failure = assertThrows(PublicHttpErrors.Rejected.class, () -> decoder.decode(request, body));
        assertSame(expected, failure.error()); assertEquals(expected.code(), failure.getMessage());
        assertNull(failure.getCause()); assertEquals(0, failure.getStackTrace().length);
        assertFalse(failure.toString().contains(CANARY)); return failure;
    }
    @Test void canonicalSelectionAndJsonEscapedKnownKeyReachActualHeaderEnumeration() {
        var decoder = decoder(valid().length + 32, 1);
        for (byte[] body : List.of(valid(), bytes(" {\"commandR\\u0065f\":\"" + COMMAND + "\"} \n"))) {
            var request = new Request(List.of(REQUEST)); var before = body.clone();
            var selected = decoder.decode(request, body);
            assertEquals(UUID.fromString(COMMAND), selected.commandRef());
            assertEquals(UUID.fromString(REQUEST), selected.requestId());
            assertEquals(1, request.headerReads); assertEquals(1, request.nextReads); assertArrayEquals(before, body);
        }
        var nativeRequest = new MockHttpServletRequest(); nativeRequest.addHeader("idempotency-key", REQUEST);
        assertEquals(UUID.fromString(REQUEST), decoder.decode(nativeRequest, valid()).requestId());
    }
    @Test void absentNullOrRepeatedIdempotencyHeadersCannotSelectACommand() {
        var decoder = decoder(512, 3);
        for (List<String> values : Arrays.asList(null, List.<String>of(), Collections.<String>singletonList(null),
                List.of(REQUEST, REQUEST), List.of(REQUEST, COMMAND))) {
            var request = new Request(values); rejected(decoder, request, valid(), PublicHttpErrors.Error.INVALID_REQUEST);
            assertEquals(1, request.headerReads); assertTrue(request.nextReads <= 1);
        }
    }
    @Test void headerUuidIsCanonicalWithoutWhitespaceTrimmingAlternateFormsOrCommaJoining() {
        var decoder = decoder(512, 3);
        for (String key : List.of(" " + REQUEST, REQUEST + " ", "\t" + REQUEST, REQUEST + "\r\n",
                REQUEST.toUpperCase(Locale.ROOT), "1-1-1-1-1", REQUEST + "," + COMMAND, CANARY)) {
            var request = new Request(List.of(key)); rejected(decoder, request, valid(), PublicHttpErrors.Error.INVALID_REQUEST);
            assertEquals(1, request.nextReads);
        }
    }
    @Test void closedRootAndCommandRefStringTypeDoNotAdmitNumbersNativeJsonValuesOrUnknownFields() {
        var decoder = decoder(2048, 5);
        for (String body : List.of("{}", "[]", "null", "true", "12", "\"" + COMMAND + "\"",
                "{\"commandRef\":null}", "{\"commandRef\":true}", "{\"commandRef\":1}", "{\"commandRef\":1.0}",
                "{\"commandRef\":[]}", "{\"commandRef\":{\"raw\":\"" + CANARY + "\"}}",
                "{\"commandRef\":\"" + COMMAND.toUpperCase(Locale.ROOT) + "\"}",
                "{\"commandRef\":\" " + COMMAND + "\"}", "{\"commandRef\":\"1-1-1-1-1\"}",
                "{\"commandref\":\"" + COMMAND + "\"}",
                "{\"commandRef\":\"" + COMMAND + "\",\"role\":\"" + CANARY + "\"}")) {
            var request = new Request(List.of(REQUEST)); rejected(decoder, request, bytes(body), PublicHttpErrors.Error.INVALID_REQUEST);
            assertEquals(1, request.headerReads); // Valid JSON got past strict inspection before closed-schema refusal.
        }
    }
    @Test void invalidUtf8DuplicateDecodedKeysAndMalformedJsonFailBeforeAnyHeaderSelection() {
        var decoder = decoder(2048, 5);
        var duplicate = "{\"commandRef\":\"" + COMMAND + "\",\"commandR\\u0065f\":\"" + COMMAND + "\"}";
        for (byte[] body : List.of(new byte[] {(byte)0xc3, (byte)0x28}, bytes(duplicate),
                bytes("{\"commandRef\":NaN}"), bytes("{\"commandRef\":1e309}"),
                bytes("{\"commandRef\":01}"), bytes("{\"commandRef\":\"\\uD800\"}"),
                bytes("{\"commandRef\":\"\\q\"}"), bytes("{\"commandRef\":\"" + COMMAND + "\",}"),
                bytes(new String(valid(), StandardCharsets.UTF_8) + "{}"))) {
            var request = new Request(List.of(REQUEST)); rejected(decoder, request, body, PublicHttpErrors.Error.INVALID_REQUEST);
            assertEquals(0, request.headerReads);
        }
    }
    @Test void bodyByteCapIsInclusiveAndChecksUtf8BytesBeforeParsingOrHeaderAccess() {
        byte[] body = valid(); var exact = decoder(body.length, 1);
        assertEquals(UUID.fromString(COMMAND), exact.decode(new Request(List.of(REQUEST)), body).commandRef());
        var extra = Arrays.copyOf(body, body.length + 1); extra[body.length] = ' ';
        var request = new Request(List.of(REQUEST)); rejected(exact, request, extra, PublicHttpErrors.Error.REQUEST_TOO_LARGE);
        assertEquals(0, request.headerReads);
        String unicode = "{\"unknown\":\"한\"}";
        request = new Request(List.of(REQUEST));
        rejected(decoder(unicode.length(), 2), request, bytes(unicode), PublicHttpErrors.Error.REQUEST_TOO_LARGE);
        assertEquals(0, request.headerReads);
    }
    @Test void explicitDepthBoundarySeparatesInspectorRejectionFromLaterSchemaRejection() {
        assertNotNull(decoder(512, 1).decode(new Request(List.of(REQUEST)), valid()));
        byte[] nested = bytes("{\"commandRef\":{\"value\":\"" + COMMAND + "\"}}");
        var shallow = new Request(List.of(REQUEST));
        rejected(decoder(512, 1), shallow, nested, PublicHttpErrors.Error.REQUEST_TOO_LARGE);
        assertEquals(0, shallow.headerReads);
        var deepEnough = new Request(List.of(REQUEST));
        rejected(decoder(512, 2), deepEnough, nested, PublicHttpErrors.Error.INVALID_REQUEST);
        assertEquals(1, deepEnough.headerReads); // Depth accepted, but a nested object is not commandRef text.
    }
    @Test void emptyOrMissingBodyAndMissingProgrammerDependenciesDoNotGetDefaultLimits() {
        var decoder = decoder(512, 2);
        rejected(decoder, new Request(List.of(REQUEST)), null, PublicHttpErrors.Error.INVALID_REQUEST);
        rejected(decoder, new Request(List.of(REQUEST)), new byte[0], PublicHttpErrors.Error.INVALID_REQUEST);
        assertThrows(NullPointerException.class, () -> new TypedWorkflowRequestDecoder(null));
        assertThrows(NullPointerException.class, () -> decoder.decode(null, valid()));
        assertThrows(IllegalArgumentException.class, () -> new HttpLimits(512, 512, 0));
    }
}
