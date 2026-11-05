package com.finsec.fuse.reimplementation.http;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.WorkflowResumeBoundary;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.simulation.*;
import jakarta.servlet.http.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.http.LocalVirtualAuthenticationFilterTest.*;

/** Actual HTTP actor adapters and domain access share one registry-admitted request frame. */
class LocalVirtualHttpActorsTest {
    private static WorkflowHttpController controller(LocalVirtualHttpActors actors) {
        return new WorkflowHttpController(actors, new WorkflowHttpController.CommandPort() {
            public WorkflowHttpController.Receipt start(WorkflowStartBoundary.Command command) { throw new AssertionError("No command dispatch"); }
            public WorkflowHttpController.Receipt resume(WorkflowResumeBoundary.Command command) { throw new AssertionError("No command dispatch"); }
        });
    }
    @Test void startActorAndRealSimulationAccessAgreeOnlyInsideTheSameBoundFrame() throws Exception {
        var f = new Fixture(); ActorRef[] escaped = new ActorRef[1];
        f.invoke(f.request(), (request, response) -> {
            var actor = f.actors.authorize((HttpServletRequest) request, WorkflowHttpController.Operation.START, null, CUSTOMER);
            escaped[0] = actor; assertEquals("synthetic-http-actor", actor.actorId());
            assertDoesNotThrow(() -> new SimulationAccess(f.actors.authority()).require(actor, SimulationAccess.Operation.START, null, CUSTOMER));
        });
        assertNull(f.context.current());
        assertEquals(401, assertThrows(SimulationFailure.class,
            () -> new SimulationAccess(f.actors.authority()).require(escaped[0], SimulationAccess.Operation.START, null, CUSTOMER)).status());
    }
    @Test void startPortMapsOperationMismatchToController403InsteadOfRuntime503() throws Exception {
        var f = new Fixture();
        f.invoke(f.request(), (request, response) -> {
            var bound = (HttpServletRequest) request;
            f.actors.authorize(bound, WorkflowHttpController.Operation.START, null, CUSTOMER);
            var rejection = assertThrows(WorkflowHttpController.Rejection.class,
                () -> f.actors.authorize(bound, WorkflowHttpController.Operation.RESUME, null, CUSTOMER));
            var rendered = controller(f.actors).rejected(rejection);
            assertEquals(403, rendered.getStatusCode().value());
            assertEquals(java.util.List.of("FORBIDDEN"), rendered.getBody().get("reasonCodes"));
        });
    }
    @Test void serviceAuthorityCannotChangeActorOrCustomerEvenIfBothCustomersAreAssigned() throws Exception {
        var f = new Fixture();
        f.invoke(f.request(), (request, response) -> {
            var actor = f.actors.authorize((HttpServletRequest) request, WorkflowHttpController.Operation.START, null, CUSTOMER);
            var access = new SimulationAccess(f.actors.authority());
            assertEquals(403, assertThrows(SimulationFailure.class,
                () -> access.require(actor, SimulationAccess.Operation.START, null, OTHER)).status());
            assertEquals(403, assertThrows(SimulationFailure.class,
                () -> access.require(new ActorRef("synthetic-impostor"), SimulationAccess.Operation.START, null, CUSTOMER)).status());
        });
    }
    @Test void realHttpActorsLatchWorkflowAndMissingGlobalScopeIs503NotWildcardAuthority() throws Exception {
        var f = new Fixture();
        f.invoke(f.request(), (request, response) -> {
            var actor = f.actors.authorize((HttpServletRequest) request, SimulationAccess.Operation.READ, WORKFLOW);
            assertDoesNotThrow(() -> new SimulationAccess(f.actors.authority()).require(actor, SimulationAccess.Operation.READ, WORKFLOW, CUSTOMER));
            assertEquals(403, assertThrows(SimulationFailure.class,
                () -> f.actors.authorize((HttpServletRequest) request, SimulationAccess.Operation.READ, SECOND)).status());
        });
        var global = new Fixture();
        global.invoke(global.request(), (request, response) -> {
            assertEquals(503, assertThrows(SimulationFailure.class,
                () -> global.actors.authorize((HttpServletRequest) request, SimulationAccess.Operation.READ, null)).status());
        });
    }
    @Test void anExtraWrapperOrForeignContextCannotSubstituteForThePrivateBoundCarrier() throws Exception {
        var f = new Fixture(); var foreign = new Fixture();
        f.invoke(f.request(), (request, response) -> {
            var bound = (HttpServletRequest) request;
            var lost = new HttpServletRequestWrapper(bound);
            var rejected = assertThrows(WorkflowHttpController.Rejection.class,
                () -> f.actors.authorize(lost, WorkflowHttpController.Operation.START, null, CUSTOMER));
            assertEquals(401, controller(f.actors).rejected(rejected).getStatusCode().value());
            assertEquals(401, assertThrows(SimulationFailure.class,
                () -> foreign.actors.authorize(bound, SimulationAccess.Operation.READ, WORKFLOW)).status());
            // Denial did not erase the genuine current carrier or grant any extra scope.
            assertNotNull(f.context.current());
            assertNotNull(f.actors.authorize(bound, WorkflowHttpController.Operation.START, null, CUSTOMER));
        });
    }
    @Test void bareActorOrRequestAttributesWithoutARegistryAdmittedWrapperDoNotAuthenticate() {
        var f = new Fixture(); var raw = f.request();
        raw.setAttribute("actorId", "synthetic-http-actor"); raw.setAttribute("localVirtualAdmission", f.principal);
        var rejection = assertThrows(WorkflowHttpController.Rejection.class,
            () -> f.actors.authorize(raw, WorkflowHttpController.Operation.START, null, CUSTOMER));
        var rendered = controller(f.actors).rejected(rejection);
        assertEquals(401, rendered.getStatusCode().value());
        assertEquals(java.util.List.of("UNAUTHENTICATED"), rendered.getBody().get("reasonCodes"));
        assertEquals(401, assertThrows(SimulationFailure.class,
            () -> f.actors.authorize(raw, SimulationAccess.Operation.READ, WORKFLOW)).status());
        assertNull(f.context.current()); assertEquals(0, f.verifications.get());
    }
}
