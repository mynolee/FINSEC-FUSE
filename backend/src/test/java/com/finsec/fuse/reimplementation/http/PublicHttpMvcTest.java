package com.finsec.fuse.reimplementation.http;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.WorkflowResumeBoundary;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import static com.finsec.fuse.reimplementation.WorkflowHttpController.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class PublicHttpMvcTest {
    private static final UUID ACTION = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID WORKFLOW = UUID.fromString("00000000-0000-4000-8000-000000000002");
    private static final UUID JOB = UUID.fromString("00000000-0000-4000-8000-000000000003");
    private static final String PRIVATE_MARKER = "SYNTHETIC_PRIVATE_DETAIL";
    private static final String START = """
        {"businessReference":"synthetic","customerId":"synthetic-customer",
         "amountKrw":1,"payoutAccountId":"00000000-0000-4000-8000-000000000004"}
        """;
    private static final String RESUME = "{\"expectedGeneration\":1,\"reason\":\"synthetic reviewed remediation\"}";
    private static final HttpLimits SYNTHETIC = new HttpLimits(4096, 1024, 8);

    private static CommandPort commands(AtomicInteger calls) {
        return new CommandPort() {
            public Receipt start(WorkflowStartBoundary.Command command) {
                calls.incrementAndGet();
                return new Receipt(ACTION, WORKFLOW, 1, State.KYC_PENDING, Decision.ALLOW,
                        List.of(), "Synthetic public receipt", false, null);
            }
            public Receipt resume(WorkflowResumeBoundary.Command command) {
                calls.incrementAndGet();
                return new Receipt(ACTION, WORKFLOW, 2, State.KYC_PENDING, Decision.ALLOW,
                        List.of(), "Synthetic public receipt", false, JOB);
            }
        };
    }

    private static MockMvc mvc(HttpLimits limits, ActorPort actors, CommandPort commands) {
        var errors = new PublicHttpErrors();
        return MockMvcBuilders.standaloneSetup(new WorkflowHttpController(actors, commands), new SyntheticController())
                .addFilters(new BoundedRequestFilter(new RequestGuard(limits), errors))
                .setControllerAdvice(new PublicHttpAdvice(errors)).build();
    }

    private static ActorPort actor() {
        return (request, operation, workflow, customer) -> new WorkflowStartBoundary.ActorRef("synthetic-actor");
    }

    @Test void explicitFilterAndAdvicePreserveStartResumeBindingsAndRepeatableBody() throws Exception {
        var calls = new AtomicInteger();
        ActorPort verifyingActor = (request, operation, workflow, customer) -> {
            assertInstanceOf(CachedBodyRequest.class, request);
            String expected = operation == Operation.START ? START : RESUME;
            try {
                assertEquals(expected, new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
                assertEquals(expected, new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
            } catch (java.io.IOException unavailable) { throw new AssertionError(unavailable); }
            return new WorkflowStartBoundary.ActorRef("synthetic-actor");
        };
        var http = mvc(SYNTHETIC, verifyingActor, commands(calls));
        http.perform(post("/api/v1/workflows").header("Idempotency-Key", ACTION)
                .contentType("application/json").content(START)).andExpect(status().isOk())
                .andExpect(jsonPath("$.requestId").value(ACTION.toString()))
                .andExpect(jsonPath("$.workflowId").value(WORKFLOW.toString()));
        http.perform(post("/api/v1/workflows/" + WORKFLOW + "/resume").header("Idempotency-Key", ACTION)
                .contentType("application/json").content(RESUME)).andExpect(status().isOk())
                .andExpect(jsonPath("$.generation").value(2)).andExpect(jsonPath("$.kycJobId").value(JOB.toString()));
        assertEquals(2, calls.get());
    }

    @Test void malformedDuplicateAndNonfiniteInputNeverReachesAuthorityOrCommands() throws Exception {
        var actorCalls = new AtomicInteger(); var commandCalls = new AtomicInteger();
        var http = mvc(SYNTHETIC, (request, operation, workflow, customer) -> {
            actorCalls.incrementAndGet(); return new WorkflowStartBoundary.ActorRef("synthetic-actor");
        }, commands(commandCalls));
        for (String body : List.of(START.replace("\"amountKrw\":1", "\"amountKrw\":1,\"amountKrw\":2"),
                START.replace("\"amountKrw\":1", "\"amountKrw\":NaN"),
                START.replace("\"amountKrw\":1", "\"amountKrw\":1e309"), "{")) {
            http.perform(post("/api/v1/workflows").header("Idempotency-Key", ACTION)
                    .contentType("application/json").content(body)).andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value("INVALID_REQUEST"));
        }
        assertEquals(0, actorCalls.get()); assertEquals(0, commandCalls.get());
    }

    @Test void resourceAndMediaRejectionsUseFixedPublicErrors() throws Exception {
        var calls = new AtomicInteger();
        mvc(new HttpLimits(4096, 2, 8), actor(), commands(calls)).perform(post("/api/v1/workflows")
                .contentType("application/json").content(START)).andExpect(status().is(413))
                .andExpect(jsonPath("$.message").value("REQUEST_TOO_LARGE"));
        mvc(new HttpLimits(4096, 1024, 1), actor(), commands(calls)).perform(post("/api/v1/workflows")
                .contentType("application/json").content("{\"a\":[]}")).andExpect(status().is(413));
        mvc(new HttpLimits(16, 1024, 8), actor(), commands(calls)).perform(post("/api/v1/workflows")
                .contentType("application/json").content(START)).andExpect(status().is(431))
                .andExpect(jsonPath("$.decision").value("ERROR"));
        var http = mvc(SYNTHETIC, actor(), commands(calls));
        http.perform(post("/api/v1/workflows").contentType("text/plain").content(START))
                .andExpect(status().isUnsupportedMediaType());
        http.perform(post("/api/v1/workflows").contentType("application/json").header("Content-Encoding", "gzip").content(START))
                .andExpect(status().isUnsupportedMediaType());
        assertEquals(0, calls.get());
    }

    @Test void authorityDecisionsRemainWithExistingActorPort() throws Exception {
        var calls = new AtomicInteger();
        mvc(SYNTHETIC, (request, operation, workflow, customer) -> null, commands(calls))
                .perform(post("/api/v1/workflows").header("Idempotency-Key", ACTION).contentType("application/json").content(START))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.message").value("UNAUTHENTICATED"));
        mvc(SYNTHETIC, (request, operation, workflow, customer) -> { throw new Rejection(Denial.FORBIDDEN); }, commands(calls))
                .perform(post("/api/v1/workflows").header("Idempotency-Key", ACTION).contentType("application/json").content(START))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.message").value("FORBIDDEN"));
        assertEquals(0, calls.get());
    }

    @Test void frameworkAndUnexpectedErrorsNeverExposeFrameworkMessagesOrInput() throws Exception {
        var http = mvc(SYNTHETIC, actor(), commands(new AtomicInteger()));
        http.perform(get("/api/v1/workflows")).andExpect(status().isMethodNotAllowed())
                .andExpect(header().string("Allow", "POST"))
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.message").value("METHOD_NOT_ALLOWED"));
        http.perform(post("/api/v1/workflows").header("Idempotency-Key", ACTION).contentType("application/json")
                .accept("text/plain").content(START)).andExpect(status().isNotAcceptable())
                .andExpect(jsonPath("$.message").value("NOT_ACCEPTABLE"));
        String binding = http.perform(post("/synthetic/binding").contentType("application/json")
                .content("{\"count\":\"" + PRIVATE_MARKER + "\"}")).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("INVALID_REQUEST")).andReturn().getResponse().getContentAsString();
        assertFalse(binding.contains(PRIVATE_MARKER));
        String unknown = http.perform(get("/synthetic/explode")).andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.message").value("DEPENDENCY_UNAVAILABLE")).andReturn().getResponse().getContentAsString();
        assertFalse(unknown.contains(PRIVATE_MARKER));
        String forbidden = http.perform(get("/synthetic/framework")).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("FORBIDDEN")).andReturn().getResponse().getContentAsString();
        assertFalse(forbidden.contains(PRIVATE_MARKER));
        http.perform(get("/synthetic/unknown-status")).andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.message").value("DEPENDENCY_UNAVAILABLE"));
    }

    @RestController
    static final class SyntheticController {
        record Input(int count) {}
        @PostMapping(path = "/synthetic/binding", consumes = "application/json", produces = "application/json")
        Map<String, Object> binding(@RequestBody Input input) { return Map.of("count", input.count()); }
        @GetMapping(path = "/synthetic/explode", produces = "application/json")
        Map<String, Object> explode() { throw new IllegalStateException(PRIVATE_MARKER); }
        @GetMapping(path = "/synthetic/framework", produces = "application/json")
        Map<String, Object> framework() { throw new ResponseStatusException(HttpStatus.FORBIDDEN, PRIVATE_MARKER); }
        @GetMapping(path = "/synthetic/unknown-status", produces = "application/json")
        Map<String, Object> unknownStatus() { throw new ResponseStatusException(HttpStatus.GONE, PRIVATE_MARKER); }

        @GetMapping(path = "/synthetic/poison/{kind}", produces = "application/json")
        Map<String, Object> poison(@org.springframework.web.bind.annotation.PathVariable("kind") String kind,
                                  jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
            for (String name : List.of("Content-Encoding", "Transfer-Encoding", "Trailer", "Content-Range",
                    "Accept-Ranges", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest", "ETag",
                    "Last-Modified", "Content-Location", "Content-Disposition")) response.setHeader(name, PRIVATE_MARKER);
            response.setContentLength(999);
            response.setHeader("X-Fuse-Execution-Mode", "VIRTUAL_SIMULATION");
            response.setHeader("Cache-Control", "no-store");
            response.setHeader("X-Content-Type-Options", "nosniff");
            response.setHeader("Access-Control-Allow-Origin", "https://synthetic.invalid");
            response.getOutputStream().write(PRIVATE_MARKER.getBytes(StandardCharsets.UTF_8));
            if (kind.equals("rejected")) throw new PublicHttpErrors.Rejected(PublicHttpErrors.Error.FORBIDDEN);
            if (kind.equals("framework")) throw new ResponseStatusException(HttpStatus.FORBIDDEN, PRIVATE_MARKER);
            if (kind.equals("invalid")) throw new IllegalArgumentException(PRIVATE_MARKER);
            throw new IllegalStateException(PRIVATE_MARKER);
        }
    }

    @Test void adviceReplacesBufferedRepresentationWithoutLosingPolicyHeaders() throws Exception {
        var http = mvc(SYNTHETIC, actor(), commands(new AtomicInteger()));
        for (String kind : List.of("rejected", "framework", "invalid", "unexpected")) {
            int expectedStatus = kind.equals("invalid") ? 400 : kind.equals("unexpected") ? 503 : 403;
            String code = expectedStatus == 400 ? "INVALID_REQUEST"
                    : expectedStatus == 503 ? "DEPENDENCY_UNAVAILABLE" : "FORBIDDEN";
            var response = http.perform(get("/synthetic/poison/" + kind))
                    .andExpect(status().is(expectedStatus))
                    .andExpect(jsonPath("$.length()").value(3))
                    .andExpect(jsonPath("$.decision").value("ERROR"))
                    .andExpect(jsonPath("$.reasonCodes.length()").value(1))
                    .andExpect(jsonPath("$.reasonCodes[0]").value(code))
                    .andExpect(jsonPath("$.message").value(code)).andReturn().getResponse();
            assertTrue(response.getContentType().startsWith("application/json"));
            assertEquals("UTF-8", response.getCharacterEncoding());
            assertFalse(response.getContentAsString().contains(PRIVATE_MARKER));
            for (String name : List.of("Content-Encoding", "Transfer-Encoding", "Trailer", "Content-Range",
                    "Accept-Ranges", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest", "ETag",
                    "Last-Modified", "Content-Location", "Content-Disposition")) assertNull(response.getHeader(name), name);
            assertNotEquals("999", response.getHeader("Content-Length"));
            if (response.getContentLength() >= 0)
                assertEquals(response.getContentAsByteArray().length, response.getContentLength());
            assertEquals("VIRTUAL_SIMULATION", response.getHeader("X-Fuse-Execution-Mode"));
            assertEquals("no-store", response.getHeader("Cache-Control"));
            assertEquals("nosniff", response.getHeader("X-Content-Type-Options"));
            assertEquals("https://synthetic.invalid", response.getHeader("Access-Control-Allow-Origin"));
        }
    }

    @Test void adviceDoesNotReplaceCommittedBodyOrRepresentationHeaders() throws Exception {
        var response = new org.springframework.mock.web.MockHttpServletResponse();
        response.setHeader("Content-Encoding", "synthetic-encoding");
        response.getOutputStream().write("synthetic-committed".getBytes(StandardCharsets.UTF_8));
        response.flushBuffer();
        assertNull(new PublicHttpAdvice(new PublicHttpErrors()).unavailable(response));
        assertEquals("synthetic-encoding", response.getHeader("Content-Encoding"));
        assertEquals("synthetic-committed", response.getContentAsString());
    }
}
