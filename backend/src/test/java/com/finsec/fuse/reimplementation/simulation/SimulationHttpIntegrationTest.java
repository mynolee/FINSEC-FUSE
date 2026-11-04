package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** In-process synthetic HTTP regression source. No listener, DB, or test has been executed. */
final class SimulationHttpIntegrationTest {
    private MockMvc mvc(SimulationFixture f, HttpLimits limits) {
        var experiments = new VirtualExperimentService(f.store, f.access, List.of(new VirtualExperimentService.FixtureSet(
                "synthetic-suite", List.of(new VirtualExperimentService.Case("synthetic-normal", SimulationSpec.KycStatus.VERIFIED,
                        List.of(ID_FACT, FACE_FACT))))), new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment, String caseId, int repeat, Map<String, Object> shared) {
                return new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.WAIT_APPROVAL, VirtualExperimentService.Reason.SYNTHETIC_REVIEW);
            }
        }, f::id);
        var harness = SimulationHarness.compose(f.workflows, f.quarantines, experiments,
                (http, operation, workflow, customer) -> {
                    if (!"synthetic-session".equals(http.getHeader("X-Synthetic-Session")))
                        throw new WorkflowHttpController.Rejection(WorkflowHttpController.Denial.UNAUTHENTICATED);
                    return ACTOR;
                },
                (http, operation, workflow) -> {
                    if (!"synthetic-session".equals(http.getHeader("X-Synthetic-Session"))) throw SimulationFailure.unauthenticated();
                    return ACTOR;
                }, limits);
        return MockMvcBuilders.standaloneSetup(harness.workflowController(), harness.apiController())
                .addFilters(harness.orderedFilters()).setControllerAdvice(harness.publicErrors()).build();
    }
    private String startBody() {
        return "{\"businessReference\":\"synthetic-reference-1\",\"customerId\":\"synthetic-customer-1\",\"amountKrw\":1000,\"payoutAccountId\":\"" + ACCOUNT + "\"}";
    }
    @Test void authenticatedStartReplaysClosedReceiptAndGetCarriesVirtualMode() throws Exception {
        var f = new SimulationFixture(); var http = mvc(f, new HttpLimits(4096, 8192, 16)); UUID action = f.id();
        var request = post("/api/v1/workflows").header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", action.toString()).contentType(MediaType.APPLICATION_JSON).content(startBody());
        http.perform(request).andExpect(status().isOk()).andExpect(header().string("X-Fuse-Execution-Mode", VirtualTransactionalStore.MODE))
                .andExpect(jsonPath("$.state").value("KYC_PENDING")).andExpect(jsonPath("$.replayed").value(false))
                .andExpect(jsonPath("$.kycJobId").doesNotExist()).andExpect(jsonPath("$.durable").doesNotExist());
        http.perform(post("/api/v1/workflows").header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", action.toString()).contentType(MediaType.APPLICATION_JSON).content(startBody()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.replayed").value(true));
        http.perform(get("/api/v1/workflows").header("X-Synthetic-Session", "synthetic-session"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.executionMode").value(VirtualTransactionalStore.MODE));
        assertEquals(1, f.rows(VirtualWorkflowService.WORKFLOWS));
    }
    @Test void missingAuthorityFailsClosedWithoutCreatingWorkflow() throws Exception {
        var f = new SimulationFixture(); var http = mvc(f, new HttpLimits(4096, 8192, 16));
        http.perform(post("/api/v1/workflows").header("Idempotency-Key", f.id().toString())
                .contentType(MediaType.APPLICATION_JSON).content(startBody()))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.reasonCodes[0]").value("UNAUTHENTICATED"));
        assertEquals(0, f.rows(VirtualWorkflowService.WORKFLOWS));
    }
    @Test void duplicateJsonAndBodyLimitAreRejectedBeforeServiceMutation() throws Exception {
        var f = new SimulationFixture(); var http = mvc(f, new HttpLimits(4096, 8192, 16));
        http.perform(post("/api/v1/workflows").header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", f.id().toString()).contentType(MediaType.APPLICATION_JSON)
                .content(startBody().replace("\"amountKrw\":1000", "\"amountKrw\":1000,\"amountKrw\":2000")))
                .andExpect(status().isBadRequest()).andExpect(header().string("X-Fuse-Execution-Mode", VirtualTransactionalStore.MODE));
        var small = mvc(f, new HttpLimits(4096, 8, 16));
        small.perform(post("/api/v1/workflows").header("Idempotency-Key", f.id().toString())
                .contentType(MediaType.APPLICATION_JSON).content(startBody()))
                .andExpect(status().is(413)).andExpect(header().string("X-Fuse-Execution-Mode", VirtualTransactionalStore.MODE));
        assertEquals(0, f.rows(VirtualWorkflowService.WORKFLOWS));
    }
    @Test void approvalPreviewAndReceiptFollowPublicFrontendContract() throws Exception {
        var f = new SimulationFixture(); UUID workflow = f.ready(); var http = mvc(f, new HttpLimits(4096, 8192, 16));
        String snapshot = (String) f.workflows.approvalPreview(ACTOR, workflow).get("reviewSnapshotHash");
        http.perform(get("/api/v1/workflows/" + workflow + "/approval-preview").header("X-Synthetic-Session", "synthetic-session"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.reviewSnapshotHash").value(snapshot));
        http.perform(post("/api/v1/workflows/" + workflow + "/approvals").header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", f.id().toString()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"decision\":\"REJECT\",\"reviewSnapshotHash\":\"" + snapshot + "\",\"comment\":\"\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.decision").value("ALLOW"))
                .andExpect(jsonPath("$.state").value("REJECTED")).andExpect(jsonPath("$.extraRiskLimit").value(0));
    }
    @Test void syntheticRegistryIsExplicitAndLiveRequestCannotFallBackToReplay() throws Exception {
        var f = new SimulationFixture(); var http = mvc(f, new HttpLimits(4096, 8192, 16));
        http.perform(get("/api/v1/simulation/fixtures").header("X-Synthetic-Session", "synthetic-session"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.fixtureSets[0].fixtureSetId").value("synthetic-suite"))
                .andExpect(jsonPath("$.fixtureSets[0].modelModes[0]").value("REPLAY"));
        http.perform(post("/api/v1/experiments").header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", f.id().toString()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"fixtureSetId\":\"synthetic-suite\",\"caseIds\":[\"synthetic-normal\"],\"mode\":\"PAIRED\",\"modelMode\":\"LIVE\",\"repeatCount\":1}"))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.reasonCodes[0]").value("DEPENDENCY_UNAVAILABLE"));
        assertFalse(f.store.snapshot().containsKey("virtual_experiments"));
    }
    @Test void unsupportedMediaAndOversizedHeadersKeepVirtualModeOnEarlyRejection() throws Exception {
        var f = new SimulationFixture(); var http = mvc(f, new HttpLimits(4096, 8192, 16));
        http.perform(post("/api/v1/workflows").contentType(MediaType.TEXT_PLAIN).content("{}"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(header().string("X-Fuse-Execution-Mode", VirtualTransactionalStore.MODE));
        var small = mvc(f, new HttpLimits(64, 8192, 16));
        small.perform(post("/api/v1/workflows").contentType(MediaType.APPLICATION_JSON)
                .header("X-Synthetic-Marker", "oversized".repeat(64)).content("{}"))
                .andExpect(status().is(431)).andExpect(header().string("X-Fuse-Execution-Mode", VirtualTransactionalStore.MODE));
        assertEquals(0, f.rows(VirtualWorkflowService.WORKFLOWS));
    }
    @Test void unexpectedAuthorityDiagnosticIsRenderedAsFixedPublicFailure() throws Exception {
        String marker = "synthetic-private-diagnostic-marker";
        var f = new SimulationFixture(20, (actor, operation, workflow, customer) -> {
            throw new IllegalStateException(marker);
        });
        mvc(f, new HttpLimits(4096, 8192, 16)).perform(get("/api/v1/workflows").header("X-Synthetic-Session", "synthetic-session"))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.reasonCodes[0]").value("DEPENDENCY_UNAVAILABLE"))
                .andExpect(result -> assertFalse(result.getResponse().getContentAsString().contains(marker)));
    }
    @Test void cancelExperimentRequiresClosedBodyCanonicalIdentityAndReplaysWithoutInternalClaim() throws Exception {
        var f = new SimulationFixture(); var http = mvc(f, new HttpLimits(4096, 8192, 16));
        UUID id = createExperiment(http, f), cancel = f.id(); String route = "/api/v1/experiments/" + id + "/cancel";
        var before = f.store.snapshot();
        for (String body : List.of("{\"attemptToken\":\"synthetic-client-input\"}", "{\"unknown\":true}")) {
            http.perform(post(route).header("X-Synthetic-Session", "synthetic-session")
                    .header("Idempotency-Key", cancel.toString()).contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isBadRequest());
            assertEquals(before, f.store.snapshot());
        }
        http.perform(post(route).header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", cancel.toString(), f.id().toString()).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
        http.perform(post(route).header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", "not-a-uuid").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
        assertEquals(before, f.store.snapshot());
        http.perform(post(route).header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", cancel.toString()).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isOk()).andExpect(content().json("{\"requestId\":\"" + cancel + "\",\"experimentId\":\"" + id
                        + "\",\"status\":\"CANCELLED\",\"completedPairs\":0,\"replayed\":false,\"resultsSource\":\"VIRTUAL_SIMULATION\"}", true));
        var cancelled = f.store.snapshot();
        http.perform(post(route).header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", cancel.toString()).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.replayed").value(true));
        assertEquals(cancelled, f.store.snapshot());
        http.perform(get("/api/v1/experiments/" + id).header("X-Synthetic-Session", "synthetic-session"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("CANCELLED"))
                .andExpect(jsonPath("$.actorId").doesNotExist()).andExpect(jsonPath("$.activeClaim").doesNotExist())
                .andExpect(jsonPath("$.fence").doesNotExist());
        f.permitted.set(false);
        http.perform(post(route).header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", cancel.toString()).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isForbidden()).andExpect(content().json("{\"decision\":\"ERROR\",\"reasonCodes\":[\"FORBIDDEN\"],\"message\":\"FORBIDDEN\"}", true));
        assertEquals(cancelled, f.store.snapshot());
    }

    @Test void cancelUnknownOwnerAuthenticationAndFenceFailuresRemainFixedWithoutMutation() throws Exception {
        var f = new SimulationFixture(); var http = mvc(f, new HttpLimits(4096, 8192, 16)); UUID id = createExperiment(http, f);
        String route = "/api/v1/experiments/" + id + "/cancel"; var before = f.store.snapshot();
        http.perform(post(route).header("Idempotency-Key", f.id().toString()).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());
        http.perform(post("/api/v1/experiments/" + f.id() + "/cancel").header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", f.id().toString()).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
        assertEquals(before, f.store.snapshot());
        f.store.transaction(tx -> { var row = tx.get("virtual_experiments", id.toString());
            tx.put("virtual_experiments", id.toString(), SimulationRows.changed(row, "actorId", "synthetic-other")); return null; });
        before = f.store.snapshot();
        http.perform(post(route).header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", f.id().toString()).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isForbidden());
        assertEquals(before, f.store.snapshot());
        f.store.transaction(tx -> { var row = tx.get("virtual_experiments", id.toString());
            tx.put("virtual_experiments", id.toString(), SimulationRows.changed(row, "actorId", ACTOR.actorId(), "fence", Long.MAX_VALUE)); return null; });
        before = f.store.snapshot();
        http.perform(post(route).header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", f.id().toString()).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().json("{\"decision\":\"ERROR\",\"reasonCodes\":[\"DEPENDENCY_UNAVAILABLE\"],\"message\":\"DEPENDENCY_UNAVAILABLE\"}", true));
        assertEquals(before, f.store.snapshot());
    }

    private UUID createExperiment(MockMvc http, SimulationFixture f) throws Exception {
        http.perform(post("/api/v1/experiments").header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", f.id().toString()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"fixtureSetId\":\"synthetic-suite\",\"caseIds\":[\"synthetic-normal\"],\"mode\":\"PAIRED\",\"modelMode\":\"REPLAY\",\"repeatCount\":1}"))
                .andExpect(status().isOk());
        return UUID.fromString(f.store.snapshot().get("virtual_experiments").keySet().iterator().next());
    }

    @Test void incompleteHarnessCannotBeConstructed() {
        assertThrows(NullPointerException.class, () -> new SimulationHarness(null, null, null, null, null));
    }
}
