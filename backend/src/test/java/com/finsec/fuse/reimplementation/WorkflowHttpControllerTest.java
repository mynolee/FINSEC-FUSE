package com.finsec.fuse.reimplementation;

import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.simulation.SimulationFailure;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static com.finsec.fuse.reimplementation.WorkflowHttpController.*;

class WorkflowHttpControllerTest {
    private static final UUID ACTION = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID WORKFLOW = UUID.fromString("00000000-0000-4000-8000-000000000002");
    private static final UUID JOB = UUID.fromString("00000000-0000-4000-8000-000000000003");
    private static final String START = """
        {"businessReference":"synthetic","customerId":"synthetic-customer",
         "amountKrw":1,"payoutAccountId":"00000000-0000-4000-8000-000000000004"}
        """;
    private static final String RESUME = "{\"expectedGeneration\":1,\"reason\":\"synthetic reviewed remediation\"}";

    private static Receipt receipt(Decision decision) {
        boolean allow = decision == Decision.ALLOW;
        return new Receipt(ACTION, WORKFLOW, allow ? 2 : 1,
                allow ? State.KYC_PENDING : State.ON_HOLD, decision,
                List.of(), "Synthetic public receipt", false, allow ? JOB : null);
    }

    private static CommandPort ports(Receipt start, Receipt resume, AtomicInteger calls) {
        return new CommandPort() {
            public Receipt start(WorkflowStartBoundary.Command command) { calls.incrementAndGet(); return start; }
            public Receipt resume(WorkflowResumeBoundary.Command command) { calls.incrementAndGet(); return resume; }
        };
    }

    private static MockMvc mvc(ActorPort actors, CommandPort commands) {
        return MockMvcBuilders.standaloneSetup(new WorkflowHttpController(actors, commands)).build();
    }

    private static ActorPort actor() {
        return (request, operation, workflow, customer) -> new WorkflowStartBoundary.ActorRef("synthetic-actor");
    }

    @Test void requiresBothExplicitPorts() {
        assertThrows(NullPointerException.class, () -> new WorkflowHttpController(null, ports(null, null, new AtomicInteger())));
        assertThrows(NullPointerException.class, () -> new WorkflowHttpController(actor(), null));
    }

    @Test void startReturnsOnlyBoundPublicReceiptFields() throws Exception {
        var calls = new AtomicInteger();
        var start = new Receipt(ACTION, WORKFLOW, 1, State.KYC_PENDING, Decision.ALLOW,
                List.of(), "Synthetic public receipt", false, null);
        mvc(actor(), ports(start, null, calls)).perform(post("/api/v1/workflows")
                .header("Idempotency-Key", ACTION).contentType("application/json").content(START))
                .andExpect(status().isOk()).andExpect(jsonPath("$.requestId").value(ACTION.toString()))
                .andExpect(jsonPath("$.workflowId").value(WORKFLOW.toString()))
                .andExpect(jsonPath("$.decision").value("ALLOW")).andExpect(jsonPath("$.kycJobId").doesNotExist());
        assertEquals(1, calls.get());
    }

    @Test void invalidActionOrUnauthenticatedCallerNeverCallsCommandPort() throws Exception {
        var calls = new AtomicInteger();
        var controller = mvc((request, operation, workflow, customer) -> null, ports(null, null, calls));
        controller.perform(post("/api/v1/workflows").contentType("application/json").content(START))
                .andExpect(status().isBadRequest());
        controller.perform(post("/api/v1/workflows").header("Idempotency-Key", ACTION, ACTION)
                .contentType("application/json").content(START)).andExpect(status().isBadRequest());
        controller.perform(post("/api/v1/workflows").header("Idempotency-Key", ACTION)
                .contentType("application/json").content(START)).andExpect(status().isUnauthorized());
        assertEquals(0, calls.get());
    }

    @Test void resumeSupportsBoundSuccessAndSavedRunLimitDenial() throws Exception {
        var calls = new AtomicInteger();
        mvc(actor(), ports(null, receipt(Decision.ALLOW), calls))
                .perform(post("/api/v1/workflows/" + WORKFLOW + "/resume")
                .header("Idempotency-Key", ACTION).contentType("application/json").content(RESUME))
                .andExpect(status().isOk()).andExpect(jsonPath("$.generation").value(2))
                .andExpect(jsonPath("$.kycJobId").value(JOB.toString()));
        mvc(actor(), ports(null, receipt(Decision.DENY), calls))
                .perform(post("/api/v1/workflows/" + WORKFLOW + "/resume")
                .header("Idempotency-Key", ACTION).contentType("application/json").content(RESUME))
                .andExpect(status().isOk()).andExpect(jsonPath("$.generation").value(1))
                .andExpect(jsonPath("$.state").value("ON_HOLD")).andExpect(jsonPath("$.kycJobId").doesNotExist());
    }

    @Test void failuresAndMismatchedReceiptsNeverBecomeSuccessOrExposeExceptionDetails() throws Exception {
        var calls = new AtomicInteger();
        var commands = new CommandPort() {
            public Receipt start(WorkflowStartBoundary.Command command) {
                calls.incrementAndGet();
                throw new IllegalArgumentException("SYNTHETIC_PRIVATE_DETAIL");
            }
            public Receipt resume(WorkflowResumeBoundary.Command command) {
                calls.incrementAndGet();
                throw new IllegalStateException("SYNTHETIC_PRIVATE_DETAIL");
            }
        };
        var controller = mvc(actor(), commands);
        String[] routes = {"/api/v1/workflows", "/api/v1/workflows/" + WORKFLOW + "/resume"};
        String[] bodies = {START, RESUME};
        for (int index = 0; index < routes.length; index++) {
            var response = controller.perform(post(routes[index])
                    .header("Idempotency-Key", ACTION).contentType("application/json").content(bodies[index]))
                    .andExpect(status().isServiceUnavailable())
                    .andExpect(content().json("""
                        {"decision":"ERROR","reasonCodes":["DEPENDENCY_UNAVAILABLE"],
                         "message":"DEPENDENCY_UNAVAILABLE"}
                        """, true))
                    .andReturn().getResponse().getContentAsString();
            assertFalse(response.contains("SYNTHETIC_PRIVATE_DETAIL"));
        }
        assertEquals(2, calls.get());
        var mismatched = new Receipt(UUID.randomUUID(), WORKFLOW, 2, State.KYC_PENDING,
                Decision.ALLOW, List.of(), "Synthetic", false, JOB);
        mvc(actor(), ports(null, mismatched, new AtomicInteger()))
                .perform(post("/api/v1/workflows/" + WORKFLOW + "/resume")
                .header("Idempotency-Key", ACTION).contentType("application/json").content(RESUME))
                .andExpect(status().isServiceUnavailable());
    }

    @Test void authoritativeForbiddenAndUnknownBodyFieldsStayRejected() throws Exception {
        var calls = new AtomicInteger();
        mvc((request, operation, workflow, customer) -> { throw new Rejection(Denial.FORBIDDEN); },
                ports(null, null, calls)).perform(post("/api/v1/workflows")
                .header("Idempotency-Key", ACTION).contentType("application/json").content(START))
                .andExpect(status().isForbidden());
        mvc(actor(), ports(null, null, calls)).perform(post("/api/v1/workflows")
                .header("Idempotency-Key", ACTION).contentType("application/json")
                .content(START.replace("\"amountKrw\":1", "\"amountKrw\":1,\"unexpected\":true")))
                .andExpect(status().isBadRequest());
        assertEquals(0, calls.get());
    }

    @Test void bothRoutesPreserveTypedServiceFailuresAndActionConflicts() throws Exception {
        var failures = List.of(SimulationFailure.invalid(), SimulationFailure.unauthenticated(),
                SimulationFailure.forbidden(), SimulationFailure.unavailable(),
                new ActionJournal.ActionConflictException());
        int[] statuses = {400, 401, 403, 503, 400};
        String[] codes = {"INVALID_REQUEST", "UNAUTHENTICATED", "FORBIDDEN", "DEPENDENCY_UNAVAILABLE", "INVALID_REQUEST"};
        for (int index = 0; index < failures.size(); index++) {
            RuntimeException failure = failures.get(index);
            var calls = new AtomicInteger();
            var commands = new CommandPort() {
                public Receipt start(WorkflowStartBoundary.Command command) { calls.incrementAndGet(); throw failure; }
                public Receipt resume(WorkflowResumeBoundary.Command command) { calls.incrementAndGet(); throw failure; }
            };
            var controller = mvc(actor(), commands);
            controller.perform(post("/api/v1/workflows").header("Idempotency-Key", ACTION)
                    .contentType("application/json").content(START))
                    .andExpect(status().is(statuses[index]))
                    .andExpect(jsonPath("$.decision").value("ERROR"))
                    .andExpect(jsonPath("$.reasonCodes[0]").value(codes[index]))
                    .andExpect(jsonPath("$.message").value(codes[index]));
            controller.perform(post("/api/v1/workflows/" + WORKFLOW + "/resume").header("Idempotency-Key", ACTION)
                    .contentType("application/json").content(RESUME))
                    .andExpect(status().is(statuses[index]))
                    .andExpect(jsonPath("$.message").value(codes[index]));
            assertEquals(2, calls.get());
        }
    }
}
