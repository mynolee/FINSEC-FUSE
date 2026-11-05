package com.finsec.fuse.reimplementation.http;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.mock.web.MockHttpServletRequest;
import static com.finsec.fuse.reimplementation.http.PublicHttpErrors.Error.*;
import static org.junit.jupiter.api.Assertions.*;

class RequestGuardTest {
    private static final HttpLimits SYNTHETIC = new HttpLimits(4096, 1024, 8);

    private static MockHttpServletRequest request(String body) {
        var request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setContentType("application/json");
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        return request;
    }

    private static void rejected(PublicHttpErrors.Error error, Executable action) {
        var rejected = assertThrows(PublicHttpErrors.Rejected.class, action);
        assertSame(error, rejected.error());
        assertEquals(error.code(), rejected.getMessage());
        assertNull(rejected.getCause());
        assertEquals(0, rejected.getStackTrace().length);
    }

    @Test void positiveLimitsAndExplicitCollaboratorsAreRequired() {
        assertThrows(IllegalArgumentException.class, () -> new HttpLimits(0, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new HttpLimits(1, 0, 1));
        assertThrows(IllegalArgumentException.class, () -> new HttpLimits(1, 1, 0));
        assertThrows(IllegalArgumentException.class, () -> new HttpLimits(-1, 1, 1));
        assertThrows(NullPointerException.class, () -> new RequestGuard(null));
        assertThrows(NullPointerException.class, () -> new BoundedRequestFilter(null, new PublicHttpErrors()));
        assertThrows(NullPointerException.class, () -> new BoundedRequestFilter(new RequestGuard(SYNTHETIC), null));
        assertThrows(NullPointerException.class, () -> new PublicHttpAdvice(null));
    }

    @Test void rejectsDuplicateKeysAfterUnescapingAtEveryDepthAndInvalidNumbers() {
        for (String body : List.of("{\"a\":1,\"a\":2}",
                "{\"nested\":{\"a\":1,\"\\u0061\":2}}", "{\"n\":NaN}", "{\"n\":Infinity}",
                "{\"n\":-Infinity}", "{\"n\":1e309}", "{\"n\":01}", "{\"n\":1,}", "[1,]",
                "{\"s\":\"\\q\"}", "{\"s\":\"\\uD800\"}", "{}{}", "")) {
            rejected(INVALID_REQUEST, () -> new RequestGuard(SYNTHETIC).inspect(request(body)));
        }
        String nonAsciiHexEscape = "{\"s\":\"" + (char) 92 + "uＦＦ４１\"}";
        rejected(INVALID_REQUEST, () -> new RequestGuard(SYNTHETIC).inspect(request(nonAsciiHexEscape)));
    }

    @Test void requiresStrictUtf8AndAcceptsDistinctKeysAcrossObjects() throws Exception {
        var malformed = request("{}");
        malformed.setContent(new byte[] {(byte) 0xc3, (byte) 0x28});
        rejected(INVALID_REQUEST, () -> new RequestGuard(SYNTHETIC).inspect(malformed));
        String json = "{\"a\":1,\"nested\":{\"a\":2},\"list\":[true,false,null,-1.25e3],\"s\":\"한글\"}";
        assertArrayEquals(json.getBytes(StandardCharsets.UTF_8),
                new RequestGuard(SYNTHETIC).inspect(request(json)).getInputStream().readAllBytes());
    }

    @Test void bodyAndContainerDepthBoundsAreInclusive() throws Exception {
        assertEquals(2, new RequestGuard(new HttpLimits(4096, 2, 1)).inspect(request("{}")).getContentLength());
        rejected(REQUEST_TOO_LARGE, () -> new RequestGuard(new HttpLimits(4096, 2, 1)).inspect(request("{} ")));
        assertNotNull(new RequestGuard(new HttpLimits(4096, 1024, 2)).inspect(request("{\"a\":[]}")));
        rejected(REQUEST_TOO_LARGE, () -> new RequestGuard(new HttpLimits(4096, 1024, 1))
                .inspect(request("{\"a\":[]}")));
        String deeplyNested = "[".repeat(1000) + "0" + "]".repeat(1000);
        rejected(REQUEST_TOO_LARGE, () -> new RequestGuard(new HttpLimits(4096, 4096, 8))
                .inspect(request(deeplyNested)));
    }

    @Test void unknownLengthInputConsumesAtMostOneByteBeyondTheBound() {
        var seen = new AtomicInteger();
        var input = new ByteArrayInputStream(new byte[100]);
        var raw = new MockHttpServletRequest() {
            @Override public int getContentLength() { return -1; }
            @Override public long getContentLengthLong() { return -1; }
            @Override public ServletInputStream getInputStream() {
                return new ServletInputStream() {
                    @Override public int read() {
                        int value = input.read();
                        if (value >= 0) seen.incrementAndGet();
                        return value;
                    }
                    @Override public int read(byte[] target, int offset, int length) {
                        int read = input.read(target, offset, length);
                        if (read > 0) seen.addAndGet(read);
                        return read;
                    }
                    @Override public boolean isFinished() { return input.available() == 0; }
                    @Override public boolean isReady() { return true; }
                    @Override public void setReadListener(ReadListener listener) { throw new AssertionError("Unused"); }
                };
            }
        };
        raw.setMethod("POST"); raw.setContentType("application/json"); raw.addHeader("Transfer-Encoding", "chunked");
        rejected(REQUEST_TOO_LARGE, () -> new RequestGuard(new HttpLimits(4096, 8, 8)).inspect(raw));
        assertEquals(9, seen.get());
    }

    @Test void checksDeclaredLengthBeforeReadAndRejectsAmbiguousOrMismatchedFraming() {
        var declared = new MockHttpServletRequest() {
            @Override public ServletInputStream getInputStream() { throw new AssertionError("Must reject before read"); }
        };
        declared.setMethod("POST"); declared.setContentType("application/json"); declared.addHeader("Content-Length", "9");
        rejected(REQUEST_TOO_LARGE, () -> new RequestGuard(new HttpLimits(4096, 8, 8)).inspect(declared));
        for (String length : List.of("-1", "2,2", "synthetic")) {
            var raw = request("{}"); raw.addHeader("Content-Length", length);
            rejected(INVALID_REQUEST, () -> new RequestGuard(SYNTHETIC).inspect(raw));
        }
        var mismatch = request("{}"); mismatch.addHeader("Content-Length", "3");
        rejected(INVALID_REQUEST, () -> new RequestGuard(SYNTHETIC).inspect(mismatch));
        var ambiguous = request("{}"); ambiguous.addHeader("Content-Length", "2"); ambiguous.addHeader("Transfer-Encoding", "chunked");
        rejected(INVALID_REQUEST, () -> new RequestGuard(SYNTHETIC).inspect(ambiguous));
        var repeated = request("{}"); repeated.addHeader("Content-Length", "2"); repeated.addHeader("Content-Length", "2");
        rejected(INVALID_REQUEST, () -> new RequestGuard(SYNTHETIC).inspect(repeated));
    }

    @Test void headerBudgetCountsEachVisibleValueWithUtf8BytesAndDelimiters() throws Exception {
        var raw = new MockHttpServletRequest(); raw.setMethod("GET"); raw.addHeader("X-Synthetic", "한");
        long exact = "X-Synthetic".getBytes(StandardCharsets.UTF_8).length + "한".getBytes(StandardCharsets.UTF_8).length + 4;
        assertNotNull(new RequestGuard(new HttpLimits(exact, 8, 1)).inspect(raw));
        rejected(HEADERS_TOO_LARGE, () -> new RequestGuard(new HttpLimits(exact - 1, 8, 1)).inspect(raw));
        var repeated = new MockHttpServletRequest(); repeated.setMethod("GET");
        repeated.addHeader("X", "a"); repeated.addHeader("X", "b");
        rejected(HEADERS_TOO_LARGE, () -> new RequestGuard(new HttpLimits(11, 8, 1)).inspect(repeated));
    }

    @Test void acceptsOnlyExplicitJsonUtf8AndNoContentEncoding() throws Exception {
        for (String media : List.of("text/plain", "application/problem+json", "application/json;charset=ISO-8859-1",
                "application/json;profile=synthetic", "application/json;charset=UTF-8;charset=UTF-8", "application/json;")) {
            var raw = request("{}"); raw.setContentType(media);
            rejected(UNSUPPORTED_MEDIA_TYPE, () -> new RequestGuard(SYNTHETIC).inspect(raw));
        }
        for (String encoding : List.of("gzip", "identity", "")) {
            var raw = request("{}"); raw.addHeader("Content-Encoding", encoding);
            rejected(UNSUPPORTED_MEDIA_TYPE, () -> new RequestGuard(SYNTHETIC).inspect(raw));
        }
        var duplicate = request("{}"); duplicate.addHeader("Content-Type", "application/json");
        rejected(UNSUPPORTED_MEDIA_TYPE, () -> new RequestGuard(SYNTHETIC).inspect(duplicate));
        var missing = new MockHttpServletRequest(); missing.setMethod("POST"); missing.setContent(new byte[0]);
        rejected(UNSUPPORTED_MEDIA_TYPE, () -> new RequestGuard(SYNTHETIC).inspect(missing));
        var accepted = request("{}"); accepted.setContentType("Application/JSON; charset=\"UTF-8\"");
        assertNotNull(new RequestGuard(SYNTHETIC).inspect(accepted));
    }

    @Test void cachedWrapperRepeatsInspectedBytesAndUsesOneActualLength() throws Exception {
        var raw = request("{\"s\":\"한글\"}");
        var cached = new RequestGuard(SYNTHETIC).inspect(raw);
        byte[] expected = "{\"s\":\"한글\"}".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(expected, cached.getInputStream().readAllBytes());
        assertArrayEquals(expected, cached.getInputStream().readAllBytes());
        assertEquals("{\"s\":\"한글\"}", cached.getReader().readLine());
        assertEquals(expected.length, cached.getContentLength());
        assertEquals(expected.length, cached.getContentLengthLong());
        assertEquals(expected.length, cached.getIntHeader("content-length"));
        assertEquals(List.of(Integer.toString(expected.length)), Collections.list(cached.getHeaders("Content-Length")));
        assertEquals("UTF-8", cached.getCharacterEncoding());
        var stream = cached.getInputStream(); assertFalse(stream.isFinished()); stream.readAllBytes(); assertTrue(stream.isFinished());
        assertFalse(cached.isAsyncSupported());
        rejected(DEPENDENCY_UNAVAILABLE, cached::startAsync);
        rejected(DEPENDENCY_UNAVAILABLE, () -> stream.setReadListener(null));
    }

    @Test void inspectedChunkedBodyHasNoStaleTransferEncoding() throws Exception {
        var raw = new MockHttpServletRequest() {
            @Override public long getContentLengthLong() { return -1; }
        };
        raw.setMethod("POST"); raw.setContentType("application/json"); raw.setContent("{}".getBytes(StandardCharsets.UTF_8));
        raw.addHeader("Transfer-Encoding", "chunked");
        var cached = new RequestGuard(SYNTHETIC).inspect(raw);
        assertNull(cached.getHeader("Transfer-Encoding"));
        assertTrue(Collections.list(cached.getHeaders("Transfer-Encoding")).isEmpty());
        assertEquals(-1, cached.getIntHeader("transfer-encoding"));
        assertEquals(-1L, cached.getDateHeader("TRANSFER-ENCODING"));
        assertFalse(Collections.list(cached.getHeaderNames()).stream().anyMatch(name -> name.equalsIgnoreCase("Transfer-Encoding")));
        assertEquals("2", cached.getHeader("Content-Length"));
    }
    @Test void originalFramingFactSurvivesNormalizationButNeverTraversesUntrustedWrappers() throws Exception {
        var raw = new MockHttpServletRequest(); raw.setMethod("GET");
        assertEquals(BoundedRequestFilter.Framing.UNCONFIRMED, BoundedRequestFilter.originalTransferEncoding(raw));
        raw.setAttribute("originalTransferEncodingPresent", false);
        var absent = new RequestGuard(SYNTHETIC).inspect(raw);
        assertEquals(BoundedRequestFilter.Framing.ABSENT, BoundedRequestFilter.originalTransferEncoding(absent));
        raw.addHeader("Transfer-Encoding", "chunked");
        var present = new RequestGuard(SYNTHETIC).inspect(raw);
        assertNull(present.getHeader("Transfer-Encoding"));
        assertEquals(BoundedRequestFilter.Framing.PRESENT, BoundedRequestFilter.originalTransferEncoding(present));
        assertEquals(BoundedRequestFilter.Framing.UNCONFIRMED, BoundedRequestFilter.originalTransferEncoding(
            new jakarta.servlet.http.HttpServletRequestWrapper(present)));
        raw.removeHeader("Transfer-Encoding");
        assertEquals(BoundedRequestFilter.Framing.PRESENT, BoundedRequestFilter.originalTransferEncoding(present));
        assertEquals(BoundedRequestFilter.Framing.ABSENT, BoundedRequestFilter.originalTransferEncoding(absent));
    }

}
