package com.finsec.fuse.experiments;

import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.observation.QuarantineObservation;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.testing.PostgresSupport;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ExperimentQuarantineObservationIT {
    private ExperimentSandbox.Database database() { return new ExperimentSandbox.Database(PostgresSupport.url(), "postgres", ""); }

    @Test void allFiveQuarantineBypassScenariosPublishOnlyActualFuseDenialTiming() {
        for (String id : List.of("A_QUARANTINE_BYPASS_01", "A_QUARANTINE_BYPASS_02", "A_QUARANTINE_BYPASS_03",
                "A_QUARANTINE_BYPASS_04", "A_QUARANTINE_BYPASS_05")) {
            for (boolean baseline : List.of(true, false)) try (var sandbox = ExperimentSandbox.open(database(), baseline)) {
                var selection = sandbox.bean(ExperimentRegistry.class).select("security-evaluation-v1", List.of(id));
                var row = new ExperimentScenario(sandbox, baseline).run(selection.cases().getFirst(), selection.hash(), 1);
                var measurement = (Map<?, ?>) ((Map<?, ?>) row.get("trace")).get("quarantineMeasurement");
                assertEquals(QuarantineObservation.BOUNDARY_VERSION, measurement.get("boundaryVersion"));
                assertEquals("COMPLETED", row.get("status"));
                if (baseline) {
                    assertNull(row.get("quarantineLatencyMs"));assertEquals(0L, measurement.get("observedDenialCount"));
                } else {
                    assertEquals("BLOCKED", row.get("state"));assertEquals(0, row.get("forbiddenPaymentCount"));
                    assertTrue(((Number) row.get("quarantineLatencyMs")).doubleValue() >= 0.0);
                    assertEquals(1L, measurement.get("observedDenialCount"));
                    var incident = (QuarantineObservation.Incident) ((List<?>) measurement.get("incidents")).getFirst();
                    assertNotNull(incident.firstDenial());
                    assertEquals(incident.firstDenial().elapsedNanos(),
                        incident.firstDenial().executionDeniedNanos() - incident.commitObservedNanos());
                    var db = sandbox.bean(Db.class);
                    assertEquals("ACTIVE", db.required("select status from quarantine where id=?", incident.quarantineId()).get("status"));
                    assertEquals("FAILED", db.required("select state from workflow_job where id=?", incident.firstDenial().jobId()).get("state"));
                    assertTrue(sandbox.bean(Json.class).write(row).contains("commitObservedNanos"), "Timing provenance must serialize into raw trace");
                }
                assertFalse(QuarantineObservation.enabled(), "Scenario cleanup must not leak to another arm");
            }
        }
    }

    @Test void automaticQuarantineWithoutSubsequentExecutionKeepsNullRatherThanFabricatedZero() {
        try (var sandbox = ExperimentSandbox.open(database(), false)) {
            var selection = sandbox.bean(ExperimentRegistry.class).select("mvp-security-v1", List.of("T02_MISSING_EVIDENCE"));
            var row = new ExperimentScenario(sandbox, false).run(selection.cases().getFirst(), selection.hash(), 1);
            assertEquals("BLOCKED", row.get("state"));assertNull(row.get("quarantineLatencyMs"));
            var measurement = (Map<?, ?>) ((Map<?, ?>) row.get("trace")).get("quarantineMeasurement");
            assertEquals(1, measurement.get("committedQuarantineCount"));assertEquals(0L, measurement.get("observedDenialCount"));
        }
    }
}
