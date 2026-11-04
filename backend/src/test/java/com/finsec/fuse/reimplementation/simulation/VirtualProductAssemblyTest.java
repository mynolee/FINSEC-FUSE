package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.http.HttpLimits;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;
import static com.finsec.fuse.reimplementation.simulation.VirtualWorkflowService.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** New assembly-boundary regressions; no test, servlet container or provider was executed. */
final class VirtualProductAssemblyTest {
    private VirtualProductAssembly compose(SimulationFixture f, AtomicInteger calls) {
        return VirtualProductAssembly.compose(new VirtualProductAssembly.Inputs(f.store, f.catalog,
                new SimulationSpec.RiskTerms("SYNTHETIC-POLICY-1", 1, 2, 3, 20, 5, 2, Duration.ofMinutes(5)),
                (actor, operation, workflow, customer) -> f.permitted.get(),
                (actor, target, remediation) -> f.remediationVerified.get(),
                List.of(new VirtualExperimentService.FixtureSet("synthetic-suite", List.of(
                        new VirtualExperimentService.Case("synthetic-normal", SimulationSpec.KycStatus.VERIFIED, List.of(ID_FACT, FACE_FACT))))),
                new VirtualExperimentService.PairEvaluator() {
                    public String mode() { return VirtualTransactionalStore.MODE; }
                    public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                            String caseId, int repeat, Map<String, Object> shared) {
                        calls.incrementAndGet();
                        return new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.WAIT_APPROVAL,
                                VirtualExperimentService.Reason.SYNTHETIC_REVIEW);
                    }
                }, f.clock, f::id,
                (http, operation, workflow, customer) -> {
                    if (!"synthetic-session".equals(http.getHeader("X-Synthetic-Session")))
                        throw new WorkflowHttpController.Rejection(WorkflowHttpController.Denial.UNAUTHENTICATED);
                    return ACTOR;
                },
                (http, operation, workflow) -> {
                    if (!"synthetic-session".equals(http.getHeader("X-Synthetic-Session"))) throw SimulationFailure.unauthenticated();
                    return ACTOR;
                }, new HttpLimits(4096, 8192, 16)));
    }
    private MockMvc http(VirtualProductAssembly product) {
        var bundle = product.http();
        return MockMvcBuilders.standaloneSetup(bundle.workflowController(), bundle.apiController())
                .addFilters(bundle.orderedFilters()).setControllerAdvice(bundle.publicErrors()).build();
    }
    @SuppressWarnings("unchecked") private Map<String, Object> input(VirtualProductAssembly product, SimulationFixture f, UUID workflow) {
        return (Map<String, Object>) product.agentBridge().prepare(ACTOR, f.id(), workflow).get("input");
    }
    private Map<String, Object> observation(Map<String, Object> input) {
        return object("requestId", input.get("requestId"), "workflowId", input.get("workflowId"), "generation", input.get("generation"),
                "runId", input.get("runId"), "inputSnapshotHash", input.get("inputSnapshotHash"),
                "proposal", object("status", "VERIFIED", "evidenceIds", List.of(ID_FACT.toString(), FACE_FACT.toString()), "explanation", "synthetic check"),
                "modelMetadata", object("model", "synthetic-model", "promptVersion", "KYC-PROMPT-1"));
    }

    @Test void compositionHasNoDomainMutationOrImplicitEvaluatorWork() {
        var f = new SimulationFixture(); var calls = new AtomicInteger(); long ids = f.sequence.get();
        var product = compose(f, calls);
        assertSame(f.store, product.store()); assertEquals(VirtualTransactionalStore.MODE, product.mode());
        assertTrue(product.store().snapshot().isEmpty()); assertEquals(ids, f.sequence.get()); assertEquals(0, calls.get());
        assertEquals(2, product.http().orderedFilters().length);
    }
    @Test void everyServiceUsesOneGlobalActionJournalAndOneWorkflowState() {
        var f = new SimulationFixture(); var product = compose(f, new AtomicInteger()); UUID action = f.id();
        UUID workflow = product.workflows().start(new WorkflowStartBoundary.Command(ACTOR, action, f.app.request())).workflowId();
        assertThrows(ActionJournal.ActionConflictException.class, () -> product.experiments().create(ACTOR, action,
                new VirtualExperimentService.Plan("synthetic-suite", List.of("synthetic-normal"), "PAIRED", "REPLAY", 1)));
        var target = new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.WORKFLOW, object("workflowId", workflow.toString()));
        product.quarantines().create(ACTOR, f.id(), target, "SYNTHETIC_CONTAINMENT", "");
        assertEquals("BLOCKED", product.workflows().get(ACTOR, workflow).get("state"));
        assertEquals(1, product.store().snapshot().get(WORKFLOWS).size());
    }
    @Test void independentlyConstructedProductsDoNotShareRows() {
        var first = new SimulationFixture(); var second = new SimulationFixture();
        var a = compose(first, new AtomicInteger()); var b = compose(second, new AtomicInteger());
        a.workflows().start(new WorkflowStartBoundary.Command(ACTOR, first.id(), first.app.request()));
        assertEquals(1, a.store().snapshot().get(WORKFLOWS).size()); assertTrue(b.store().snapshot().isEmpty());
    }
    @Test void publicQueriesReviewContainmentAndExplicitRecoveryUseTheSameGraph() throws Exception {
        var f = new SimulationFixture(); var product = compose(f, new AtomicInteger()); var http = http(product);
        UUID workflow = product.workflows().start(new WorkflowStartBoundary.Command(ACTOR, f.id(), f.app.request())).workflowId();
        var original = input(product, f, workflow);
        product.agentBridge().accept(ACTOR, f.id(), observation(original));
        http.perform(get("/api/v1/workflows/" + workflow).header("X-Synthetic-Session", "synthetic-session"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.state").value("WAIT_APPROVAL"));
        http.perform(get("/api/v1/workflows/" + workflow + "/trace").header("X-Synthetic-Session", "synthetic-session"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.results.length()").value(2));
        String snapshot = (String) product.workflows().approvalPreview(ACTOR, workflow).get("reviewSnapshotHash");
        http.perform(post("/api/v1/workflows/" + workflow + "/approvals").header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", f.id().toString()).contentType(MediaType.APPLICATION_JSON)
                .content(CanonicalJson.write(object("decision", "APPROVE", "reviewSnapshotHash", snapshot, "comment", ""))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.state").value("APPROVED"));
        UUID reservation = UUID.fromString((String) product.workflows().reservePayment(ACTOR, f.id(), workflow).get("reservationId"));
        http.perform(post("/api/v1/quarantines").header("X-Synthetic-Session", "synthetic-session").header("Idempotency-Key", f.id().toString())
                .contentType(MediaType.APPLICATION_JSON).content(CanonicalJson.write(object("scope", "WORKFLOW", "workflowId", workflow.toString(),
                        "reasonCode", "SYNTHETIC_CONTAINMENT", "note", ""))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.state").value("ACTIVE"));
        String incident = product.store().snapshot().get(QUARANTINES).values().iterator().next().get("quarantineId").toString();
        http.perform(get("/api/v1/incidents/" + incident + "/impact").header("X-Synthetic-Session", "synthetic-session"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.actual.atRiskPendingAmountKrw").value(1000));
        assertEquals(0, product.workflows().get(ACTOR, workflow).get("reservedRisk"));
        assertEquals("DENY", product.workflows().commitPayment(ACTOR, f.id(), workflow, reservation).get("decision"));
        http.perform(post("/api/v1/quarantines/" + incident + "/release").header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", f.id().toString()).contentType(MediaType.APPLICATION_JSON)
                .content(CanonicalJson.write(object("remediation", object("safeDocumentId", DOCUMENT.toString(), "safeDocumentVersion", 2,
                        "checkEvidenceIds", List.of(ID_FACT.toString()), "note", "synthetic checked remediation")))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.state").value("RELEASED"));
        assertEquals("ON_HOLD", product.workflows().get(ACTOR, workflow).get("state"));
        http.perform(post("/api/v1/workflows/" + workflow + "/resume").header("X-Synthetic-Session", "synthetic-session")
                .header("Idempotency-Key", f.id().toString()).contentType(MediaType.APPLICATION_JSON)
                .content(CanonicalJson.write(object("expectedGeneration", 1, "reason", "synthetic explicit recovery"))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.generation").value(2))
                .andExpect(jsonPath("$.kycJobId").isString());
        assertEquals(List.of("LATE_RESULT_DISCARDED"), product.agentBridge().accept(ACTOR, f.id(), observation(original)).get("reasonCodes"));
        assertTrue(product.store().snapshot().getOrDefault(PAYMENTS, Map.of()).isEmpty());
    }
    @Test void registryCreateAdvanceAndQueryUseOneSyntheticExperiment() throws Exception {
        var f = new SimulationFixture(); var calls = new AtomicInteger(); var product = compose(f, calls); var http = http(product);
        http.perform(get("/api/v1/simulation/fixtures").header("X-Synthetic-Session", "synthetic-session"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.fixtureSets[0].caseIds[0]").value("synthetic-normal"));
        http.perform(post("/api/v1/experiments").header("X-Synthetic-Session", "synthetic-session").header("Idempotency-Key", f.id().toString())
                .contentType(MediaType.APPLICATION_JSON).content(CanonicalJson.write(object("fixtureSetId", "synthetic-suite",
                        "caseIds", List.of("synthetic-normal"), "mode", "PAIRED", "modelMode", "REPLAY", "repeatCount", 1))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("PENDING"));
        String id = product.store().snapshot().get("virtual_experiments").values().iterator().next().get("experimentId").toString();
        product.experiments().advance(ACTOR, f.id(), UUID.fromString(id));
        http.perform(get("/api/v1/experiments/" + id).header("X-Synthetic-Session", "synthetic-session"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("COMPLETED"))
                .andExpect(jsonPath("$.resultsSource").value("VIRTUAL_SIMULATION")).andExpect(jsonPath("$.liveRobustnessMeasured").value(false));
        assertEquals(2, calls.get());
    }
    @Test void authorityRevocationAppliesToComposedLibraryAndPublicQuery() throws Exception {
        var f = new SimulationFixture(); var product = compose(f, new AtomicInteger());
        UUID workflow = product.workflows().start(new WorkflowStartBoundary.Command(ACTOR, f.id(), f.app.request())).workflowId();
        f.permitted.set(false);
        assertEquals(403, assertThrows(SimulationFailure.class, () -> product.agentBridge().prepare(ACTOR, f.id(), workflow)).status());
        http(product).perform(get("/api/v1/workflows/" + workflow).header("X-Synthetic-Session", "synthetic-session"))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.reasonCodes[0]").value("FORBIDDEN"));
        assertEquals(0, f.rows(RUNS));
    }
    @Test void composedKycAdapterSharesObservationReplayAcrossFreshAdapterInstances() {
        var f = new SimulationFixture(); var product = compose(f, new AtomicInteger()); var calls = new AtomicInteger();
        UUID workflow = product.workflows().start(new WorkflowStartBoundary.Command(ACTOR, f.id(), f.app.request())).workflowId();
        var provider = new VirtualKycJobAdapter.ProviderPort() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public Map<String, Object> evaluate(VirtualKycJobAdapter.Delivery delivery, Map<String, Object> input) {
                calls.incrementAndGet(); return observation(input);
            }
        };
        var delivery = new VirtualKycJobAdapter.Delivery(f.id(), f.id(), workflow);
        assertEquals("WAIT_APPROVAL", product.kycJobs(provider).run(ACTOR, delivery).get("state"));
        assertEquals(true, product.kycJobs(provider).run(ACTOR, delivery).get("replayed"));
        assertEquals(1, calls.get()); assertEquals(2, product.store().snapshot().get(RESULTS).size());
        f.permitted.set(false);
        assertEquals(403, assertThrows(SimulationFailure.class, () -> product.kycJobs(provider).run(ACTOR, delivery)).status());
        assertEquals(1, calls.get());
    }
}
