package com.finsec.fuse.reimplementation.simulation;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Classpath regression source only. No build, class loading or test has been executed. */
final class VirtualResourceContractTest {
    @Test void reviewedMigrationsAndExplicitSyntheticFixtureAreClasspathInputs() throws Exception {
        for (String file : List.of("V1__fuse_core.sql", "V2__experiments.sql", "V3__immutable_agent_results.sql",
                "V4__pre_execution_quarantine_holds.sql", "V5__experiment_arm_bindings.sql",
                "V6__durable_demo_tokens.sql", "V7__protect_flyway_history.sql")) {
            try (InputStream input = getClass().getResourceAsStream("/db/migration/" + file)) {
                assertNotNull(input, file + " must be packaged as a reviewed SQL resource");
                assertTrue(input.readAllBytes().length > 0);
            }
        }
        try (InputStream input = getClass().getResourceAsStream("/evaluation/synthetic-public-v1.json")) {
            assertNotNull(input, "The explicitly registered synthetic fixture must be packaged");
            String body = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(body.contains("synthetic-public-v1"));
            assertTrue(body.contains("NEW_SYNTHETIC_CONTRACT_DATA"));
        }
    }
    @Test void excludedPolicyFilesAreNotAddedByTheSubsetResourceConfiguration() {
        assertNull(getClass().getResource("/security_policy.json"));
        assertNull(getClass().getResource("/demo_policy.json"));
        assertNull(getClass().getResource("/.env"));
    }
}
