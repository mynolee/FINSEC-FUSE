package com.finsec.fuse.testing;

import static org.junit.jupiter.api.Assertions.*;
import com.finsec.fuse.payment.PaymentFixture;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Exercises the startup harness's exact recovery query against the migrated PostgreSQL schema. */
class StartupAdmissionClaimIT extends PaymentFixture {
    @Test void claimQueryRequiresThePreparedWorkflowToBeAwaitingApproval() throws Exception {
        UUID readyWorkflow=ready102();
        UUID pendingWorkflow=start("customer-103");
        UUID preparedWorkflow=StartupAdmissionHarness.preparedWorkflowId(Map.of("workflowId",readyWorkflow.toString()));

        assertTrue(StartupAdmissionHarness.workflowAwaitingApproval(PostgresSupport.url(),preparedWorkflow));
        assertFalse(StartupAdmissionHarness.workflowAwaitingApproval(PostgresSupport.url(),pendingWorkflow),
            "Another workflow at WAIT_APPROVAL must not satisfy this pending workflow's recovery");
        assertFalse(StartupAdmissionHarness.workflowAwaitingApproval(PostgresSupport.url(),UUID.randomUUID()),
            "An absent workflow must not satisfy recovery");
    }

    @Test void preparationMustSupplyACanonicalWorkflowUuid() {
        UUID workflowId=UUID.randomUUID();
        assertEquals(workflowId,StartupAdmissionHarness.preparedWorkflowId(Map.of("workflowId",workflowId.toString())));
        assertThrows(AssertionError.class,()->StartupAdmissionHarness.preparedWorkflowId(Map.of()));
        assertThrows(AssertionError.class,()->StartupAdmissionHarness.preparedWorkflowId(Map.of("workflowId",102)));
        assertThrows(AssertionError.class,()->StartupAdmissionHarness.preparedWorkflowId(Map.of("workflowId","not-a-uuid")));
        assertThrows(AssertionError.class,()->StartupAdmissionHarness.preparedWorkflowId(Map.of("workflowId","1-1-1-1-1")));
    }
}
