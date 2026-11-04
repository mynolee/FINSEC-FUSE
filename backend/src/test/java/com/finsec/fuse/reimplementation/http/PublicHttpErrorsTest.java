package com.finsec.fuse.reimplementation.http;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import static org.junit.jupiter.api.Assertions.*;

class PublicHttpErrorsTest {
    private static final String PRIVATE_MARKER = "SYNTHETIC_PRIVATE_DETAIL";

    @Test void filterReplacesRepresentationHeadersButPreservesModeSecurityAndCors() throws Exception {
        var filter = new BoundedRequestFilter(new RequestGuard(new HttpLimits(4096, 64, 4)), new PublicHttpErrors());
        var raw = new MockHttpServletRequest(); raw.setMethod("GET");
        var response = new MockHttpServletResponse();
        var stale = java.util.List.of("Content-Encoding", "Transfer-Encoding", "Trailer", "Content-Range",
                "Accept-Ranges", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest", "ETag",
                "Last-Modified", "Content-Location", "Content-Disposition");
        new com.finsec.fuse.reimplementation.simulation.SimulationModeFilter().doFilter(raw, response,
                (request, reply) -> filter.doFilter(request, reply, (cached, target) -> {
                    for (String name : stale) response.addHeader(name, PRIVATE_MARKER);
                    response.setContentType("text/plain"); response.setContentLength(999);
                    response.setHeader("Cache-Control", "no-store");
                    response.setHeader("X-Content-Type-Options", "nosniff");
                    response.setHeader("Access-Control-Allow-Origin", "https://synthetic.invalid");
                    response.getOutputStream().write(PRIVATE_MARKER.getBytes(StandardCharsets.UTF_8));
                    throw new ServletException(PRIVATE_MARKER);
                }));
        assertEquals(503, response.getStatus());
        assertEquals("{\"decision\":\"ERROR\",\"reasonCodes\":[\"DEPENDENCY_UNAVAILABLE\"],"
                + "\"message\":\"DEPENDENCY_UNAVAILABLE\"}", response.getContentAsString());
        assertEquals(response.getContentAsByteArray().length, response.getContentLength());
        assertTrue(response.getContentType().startsWith("application/json"));
        for (String name : stale) assertNull(response.getHeader(name), name);
        assertEquals("VIRTUAL_SIMULATION", response.getHeader("X-Fuse-Execution-Mode"));
        assertEquals("no-store", response.getHeader("Cache-Control"));
        assertEquals("nosniff", response.getHeader("X-Content-Type-Options"));
        assertEquals("https://synthetic.invalid", response.getHeader("Access-Control-Allow-Origin"));
    }

    @Test void committedRepresentationHeadersAreNotPartiallyMutated() throws Exception {
        var response = new MockHttpServletResponse();
        response.setHeader("Content-Encoding", "synthetic-encoding");
        response.setHeader("ETag", "synthetic-tag");
        response.getOutputStream().write("synthetic-committed".getBytes(StandardCharsets.UTF_8));
        response.flushBuffer();
        assertFalse(new PublicHttpErrors().write(response, PublicHttpErrors.Error.INVALID_REQUEST));
        assertEquals("synthetic-encoding", response.getHeader("Content-Encoding"));
        assertEquals("synthetic-tag", response.getHeader("ETag"));
        assertEquals("synthetic-committed", response.getContentAsString());
    }

    @Test void rendererHasExactlyThePublicStatusWhitelistAndConstantFields() throws Exception {
        var errors = new PublicHttpErrors();
        assertEquals(Set.of(400, 401, 403, 405, 406, 413, 415, 431, 503),
                java.util.Arrays.stream(PublicHttpErrors.Error.values())
                        .map(PublicHttpErrors.Error::status).collect(java.util.stream.Collectors.toSet()));
        for (var error : PublicHttpErrors.Error.values()) {
            assertSame(error, PublicHttpErrors.forStatus(error.status()));
            var response = new MockHttpServletResponse();
            assertTrue(errors.write(response, error));
            assertEquals(error.status(), response.getStatus());
            assertTrue(response.getContentType().startsWith("application/json"));
            assertEquals("{\"decision\":\"ERROR\",\"reasonCodes\":[\"" + error.code()
                    + "\"],\"message\":\"" + error.code() + "\"}", response.getContentAsString());
            assertEquals(response.getContentAsByteArray().length, response.getContentLength());
            assertEquals(error.status(), errors.response(error).getStatusCode().value());
        }
        assertThrows(IllegalArgumentException.class, () -> PublicHttpErrors.forStatus(500));
        assertThrows(IllegalArgumentException.class, () -> PublicHttpErrors.forStatus(200));
    }

    @Test void filterMasksDownstreamExceptionsAndReadFailuresWithoutCallingLaterCode() throws Exception {
        var filter = new BoundedRequestFilter(new RequestGuard(new HttpLimits(4096, 64, 4)), new PublicHttpErrors());
        var raw = new MockHttpServletRequest(); raw.setMethod("GET");
        var response = new MockHttpServletResponse();
        filter.doFilter(raw, response, (request, reply) -> { throw new ServletException(PRIVATE_MARKER); });
        assertEquals(503, response.getStatus());
        assertFalse(response.getContentAsString().contains(PRIVATE_MARKER));
        var broken = new MockHttpServletRequest() {
            @Override public ServletInputStream getInputStream() {
                return new ServletInputStream() {
                    @Override public int read() throws IOException { throw new IOException(PRIVATE_MARKER); }
                    @Override public boolean isFinished() { return false; }
                    @Override public boolean isReady() { return true; }
                    @Override public void setReadListener(jakarta.servlet.ReadListener listener) {
                        throw new IllegalStateException(PRIVATE_MARKER);
                    }
                };
            }
        };
        broken.setMethod("POST"); broken.setContentType("application/json");
        var readFailure = new MockHttpServletResponse();
        filter.doFilter(broken, readFailure, (request, reply) -> fail("Must not reach a controller"));
        assertEquals(503, readFailure.getStatus());
        assertFalse(readFailure.getContentAsString().contains(PRIVATE_MARKER));
    }

    @Test void rejectsAsynchronousDispatchAndKeepsCommittedResponseLimitationExplicit() throws Exception {
        var errors = new PublicHttpErrors();
        var filter = new BoundedRequestFilter(new RequestGuard(new HttpLimits(4096, 64, 4)), errors);
        var raw = new MockHttpServletRequest(); raw.setMethod("GET");
        raw.setDispatcherType(jakarta.servlet.DispatcherType.ASYNC);
        var response = new MockHttpServletResponse();
        filter.doFilter(raw, response, (request, reply) -> fail("Synchronous contract only"));
        assertEquals(503, response.getStatus());
        var committed = new MockHttpServletResponse();
        committed.getOutputStream().write("SYNTHETIC_COMMITTED".getBytes(StandardCharsets.UTF_8));
        committed.flushBuffer();
        assertFalse(errors.write(committed, PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE));
        assertEquals("SYNTHETIC_COMMITTED", committed.getContentAsString());
    }
}
