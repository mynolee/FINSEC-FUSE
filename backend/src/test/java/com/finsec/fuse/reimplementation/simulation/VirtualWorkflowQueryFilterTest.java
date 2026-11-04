package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.http.PublicHttpAdvice;
import com.finsec.fuse.reimplementation.http.PublicHttpErrors;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Newly authored public-query regressions with synthetic state only. No tests or server have run. */
final class VirtualWorkflowQueryFilterTest {
    private record QueryFixture(SimulationFixture base, VirtualWorkflowService workflows,
                                VirtualQuarantineService quarantines, List<UUID> ids) {}

    private QueryFixture fixture(int count, SimulationAccess.Authority authority) {
        var base = new SimulationFixture(20, authority);
        var applications = new ArrayList<SimulationSpec.Application>();
        for (int index = 0; index < count; index++) {
            applications.add(new SimulationSpec.Application("synthetic-filter-" + index, "synthetic-filter-ref-" + index,
                    base.app.customerId(), 1000L + index, ACCOUNT, 5000L, 10000L, true, base.source));
        }
        var catalog = new SimulationSpec.Catalog(applications, base.catalog.factsFor(base.app.customerId(), base.clock.instant()));
        var workflows = new VirtualWorkflowService(base.store, catalog, new SimulationSpec.RiskTerms(
                "SYNTHETIC-POLICY-1", 1, 2, 3, 20, 5, 2, Duration.ofMinutes(5)), base.access, base.clock, base::id);
        var quarantines = new VirtualQuarantineService(base.store, catalog, base.access, workflows,
                (actor, target, remediation) -> true, base.clock, base::id);
        var ids = applications.stream().map(app ->
                workflows.start(new WorkflowStartBoundary.Command(ACTOR, base.id(), app.request())).workflowId()).toList();
        return new QueryFixture(base, workflows, quarantines, ids);
    }
    private void block(QueryFixture fixture, int index) {
        fixture.quarantines().create(ACTOR, fixture.base().id(), new VirtualQuarantineService.Target(
                VirtualQuarantineService.Scope.WORKFLOW, object("workflowId", fixture.ids().get(index).toString())),
                "SYNTHETIC_QUERY_HOLD", "");
    }
    @SuppressWarnings("unchecked") private List<String> ids(Map<String, Object> result) {
        return ((List<Map<String, Object>>) result.get("items")).stream().map(row -> (String) row.get("workflowId")).toList();
    }
    private SimulationApiController controller(QueryFixture fixture) {
        var base = fixture.base();
        var experiments = new VirtualExperimentService(base.store, base.access, List.of(), new VirtualExperimentService.PairEvaluator() {
            public String mode() { return VirtualTransactionalStore.MODE; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                    String caseId, int repeat, Map<String, Object> proposal) {
                return new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.WAIT_APPROVAL,
                        VirtualExperimentService.Reason.SYNTHETIC_REVIEW);
            }
        }, base::id);
        // Explicit synthetic actor double only; no real authentication provider is installed.
        return new SimulationApiController(fixture.workflows(), fixture.quarantines(), experiments, (http, operation, workflow) -> ACTOR);
    }
    private MockMvc mvc(SimulationApiController controller) {
        return MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new PublicHttpAdvice(new PublicHttpErrors())).build();
    }

    @Test void emptyStateAndLegacyServiceCallPreserveOrderingAndResponseShape() {
        var fixture = fixture(3, null); var before = fixture.base().store.snapshot();
        var legacy = fixture.workflows().list(ACTOR, 0, 20);
        assertEquals(legacy, fixture.workflows().list(ACTOR, "", 0, 20));
        assertEquals(fixture.ids().stream().map(UUID::toString).toList(), ids(legacy));
        assertEquals(java.util.Set.of("items", "total", "page", "size", "executionMode"), legacy.keySet());
        assertEquals(before, fixture.base().store.snapshot());
    }

    @Test void filteredTotalAndPaginationContainOnlyAuthorizedMatchingRows() {
        var hidden = new AtomicReference<UUID>();
        var fixture = fixture(5, (actor, operation, workflow, customer) ->
                operation != SimulationAccess.Operation.READ || workflow == null || !workflow.equals(hidden.get()));
        block(fixture, 0); block(fixture, 2); block(fixture, 3); hidden.set(fixture.ids().get(3));
        var first = fixture.workflows().list(ACTOR, "BLOCKED", 0, 1);
        var second = fixture.workflows().list(ACTOR, "BLOCKED", 1, 1);
        var beyond = fixture.workflows().list(ACTOR, "BLOCKED", 2, 1);
        assertEquals(2, first.get("total")); assertEquals(2, second.get("total")); assertEquals(2, beyond.get("total"));
        assertEquals(List.of(fixture.ids().get(0).toString()), ids(first));
        assertEquals(List.of(fixture.ids().get(2).toString()), ids(second)); assertEquals(List.of(), ids(beyond));
        assertEquals(List.of(fixture.ids().get(1).toString(), fixture.ids().get(4).toString()),
                ids(fixture.workflows().list(ACTOR, "KYC_PENDING", 0, 20)));
        var paid = fixture.workflows().list(ACTOR, "PAID", 0, 20);
        assertEquals(0, paid.get("total")); assertEquals(List.of(), ids(paid));
        assertEquals(4, fixture.workflows().list(ACTOR, 0, 20).get("total"));
    }

    @Test void acceptsOnlyExactPublicStatesWithoutTrimmingOrCaseNormalization() {
        var fixture = fixture(1, null); var before = fixture.base().store.snapshot();
        for (var state : WorkflowHttpController.State.values())
            assertDoesNotThrow(() -> fixture.workflows().list(ACTOR, state.name(), 0, 20));
        for (String invalid : List.of("paid", " PAID", "PAID ", "ALL", "PAID,BLOCKED", "synthetic-private-query-marker")) {
            var failure = assertThrows(SimulationFailure.class, () -> fixture.workflows().list(ACTOR, invalid, 0, 20));
            assertEquals(400, failure.status()); assertEquals("INVALID_REQUEST", failure.code());
        }
        assertEquals(400, assertThrows(SimulationFailure.class, () -> fixture.workflows().list(ACTOR, null, 0, 20)).status());
        assertEquals(before, fixture.base().store.snapshot());
    }

    @Test void stateFilterDoesNotExpandCallerAuthority() {
        var fixture = fixture(1, null); fixture.base().permitted.set(false);
        assertEquals(403, assertThrows(SimulationFailure.class,
                () -> fixture.workflows().list(ACTOR, "KYC_PENDING", 0, 20)).status());
        assertEquals(401, assertThrows(SimulationFailure.class,
                () -> fixture.workflows().list(null, "KYC_PENDING", 0, 20)).status());
    }

    @Test void existingPaginationBoundsAndLargeOffsetRemainSafe() {
        var fixture = fixture(1, null);
        assertEquals(400, assertThrows(SimulationFailure.class, () -> fixture.workflows().list(ACTOR, -1, 20)).status());
        assertEquals(400, assertThrows(SimulationFailure.class, () -> fixture.workflows().list(ACTOR, "PAID", 0, 0)).status());
        assertEquals(400, assertThrows(SimulationFailure.class, () -> fixture.workflows().list(ACTOR, "", 0, 101)).status());
        var beyond = fixture.workflows().list(ACTOR, "KYC_PENDING", Integer.MAX_VALUE, 100);
        assertEquals(List.of(), ids(beyond)); assertEquals(1, beyond.get("total"));
    }

    @Test void httpStateReachesServiceAndLegacyControllerCallStillWorks() throws Exception {
        var hidden = new AtomicReference<UUID>();
        var fixture = fixture(5, (actor, operation, workflow, customer) ->
                operation != SimulationAccess.Operation.READ || workflow == null || !workflow.equals(hidden.get()));
        block(fixture, 0); block(fixture, 2); block(fixture, 3); hidden.set(fixture.ids().get(3));
        var controller = controller(fixture); var http = mvc(controller);
        http.perform(get("/api/v1/workflows").param("state", "BLOCKED").param("page", "1").param("size", "1"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.total").value(2))
                .andExpect(jsonPath("$.page").value(1)).andExpect(jsonPath("$.size").value(1))
                .andExpect(jsonPath("$.items[0].workflowId").value(fixture.ids().get(2).toString()))
                .andExpect(jsonPath("$.items[0].state").value("BLOCKED"));
        http.perform(get("/api/v1/workflows")).andExpect(status().isOk()).andExpect(jsonPath("$.total").value(4));
        http.perform(get("/api/v1/workflows").param("state", "")).andExpect(status().isOk()).andExpect(jsonPath("$.total").value(4));
        assertEquals(fixture.workflows().list(ACTOR, 0, 20),
                controller.workflows(new MockHttpServletRequest("GET", "/api/v1/workflows"), 0, 20).getBody());
    }

    @Test void invalidHttpStateReturnsFixed400WithoutReflectingQueryText() throws Exception {
        var fixture = fixture(1, null); var before = fixture.base().store.snapshot();
        String marker = "synthetic-private-query-marker";
        mvc(controller(fixture)).perform(get("/api/v1/workflows").param("state", marker))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.decision").value("ERROR"))
                .andExpect(jsonPath("$.reasonCodes[0]").value("INVALID_REQUEST"))
                .andExpect(jsonPath("$.message").value("INVALID_REQUEST"))
                .andExpect(result -> assertFalse(result.getResponse().getContentAsString().contains(marker)));
        assertEquals(before, fixture.base().store.snapshot());
    }
}
