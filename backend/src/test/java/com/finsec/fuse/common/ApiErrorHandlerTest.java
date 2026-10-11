package com.finsec.fuse.common;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.sql.SQLException;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Exercises Spring MVC exception selection, including connection loss during rollback. */
class ApiErrorHandlerTest {
    private static final String PRIVATE_DETAIL = "jdbc:postgresql://private-host/internal?password=do-not-expose";

    static Stream<RuntimeException> databaseFailures() {
        return Stream.of(
            new DataAccessResourceFailureException(PRIVATE_DETAIL),
            new CannotCreateTransactionException("Cannot start transaction: " + PRIVATE_DETAIL, new SQLException("Connection unavailable")),
            new TransactionSystemException("JDBC rollback failed: " + PRIVATE_DETAIL, new SQLException("Connection is closed")),
            new TransactionSystemException("JDBC commit outcome unknown: " + PRIVATE_DETAIL, new SQLException("Connection is closed")));
    }

    @ParameterizedTest
    @MethodSource("databaseFailures")
    void databaseFailuresAreSanitizedInfrastructureErrors(RuntimeException failure) throws Exception {
        var mvc = MockMvcBuilders.standaloneSetup(new FailingController(failure)).setControllerAdvice(new ApiErrorHandler()).build();
        mvc.perform(get("/failure-probe").header("Idempotency-Key", "00000000-0000-4000-8000-000000000999"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.decision").value("ERROR"))
            .andExpect(jsonPath("$.reasonCodes", contains("DEPENDENCY_UNAVAILABLE")))
            .andExpect(jsonPath("$.requestId").value("00000000-0000-4000-8000-000000000999"))
            .andExpect(jsonPath("$.state").value(nullValue()))
            .andExpect(jsonPath("$.workflowId").value(nullValue()))
            .andExpect(content().string(not(containsString("private-host"))))
            .andExpect(content().string(not(containsString("password"))))
            .andExpect(content().string(not(containsString("DENY"))));
    }

    @Test
    void explicitPolicyRejectionsKeepTheirExistingStatusAndDecision() throws Exception {
        var mvc = MockMvcBuilders.standaloneSetup(new FailingController(new ApiException(403, "ROLE_FORBIDDEN", "Forbidden")))
            .setControllerAdvice(new ApiErrorHandler()).build();
        mvc.perform(get("/failure-probe"))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.decision").value("DENY"))
            .andExpect(jsonPath("$.reasonCodes", contains("ROLE_FORBIDDEN")));
    }

    @RestController
    @org.springframework.context.annotation.Profile("handler-contract-test-only")
    static final class FailingController {
        private final RuntimeException failure;
        FailingController(RuntimeException failure) { this.failure = failure; }
        @GetMapping("/failure-probe")
        public String fail() { throw failure; }
    }
}
