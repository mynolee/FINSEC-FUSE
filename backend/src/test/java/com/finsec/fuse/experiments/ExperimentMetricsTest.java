package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import static org.junit.jupiter.api.Assertions.*;

/** Pure aggregation tests: no Spring context, database, workflow or model execution. */
class ExperimentMetricsTest {
    private static final Json JSON = new Json(new JsonConfiguration().jsonMapper());
    private static final String HASH = "a".repeat(64);

    @TestFactory
    Stream<DynamicTest> matchesSharedPythonArithmeticVectors() throws Exception {
        Path vectorsPath = Stream.of(
                Path.of("../evaluation/tests/fixtures/metrics-parity.json"),
                Path.of("evaluation/tests/fixtures/metrics-parity.json"))
            .filter(Files::isRegularFile).findFirst().orElseThrow();
        Map<String, Object> source = JSON.map(Files.readAllBytes(vectorsPath));
        Map<String, Object> defaults = object(source.get("defaults"));
        return objects(source.get("vectors")).stream().map(vector -> DynamicTest.dynamicTest(
            vector.get("name").toString(), () -> {
                List<Map<String, Object>> rows = new ArrayList<>();
                for (Map<String, Object> overrides : objects(vector.get("rows"))) {
                    Map<String, Object> row = new LinkedHashMap<>(defaults);
                    row.putAll(overrides);
                    rows.add(row);
                }
                var selection = new ExperimentRegistry.Selection("arithmetic-test-only",
                    source.get("fixtureHash").toString(), objects(vector.get("cases")));
                Map<String, Object> actual = ExperimentMetrics.calculate(selection, rows,
                    ((Number) vector.get("repeatCount")).intValue(), vector.get("modelMode").toString());
                assertJsonEquivalent(vector.get("expected"), actual, vector.get("name").toString());
            }));
    }

    @Test
    void rejectsDuplicateEnvironmentResults() {
        Map<String, Object> row = identity("C", "FUSE", 1);
        assertThrows(IllegalArgumentException.class,
            () -> ExperimentMetrics.calculate(selection(), List.of(row, row), 1, "REPLAY"));
    }

    @Test
    void rejectsUnregisteredResults() {
        assertThrows(IllegalArgumentException.class,
            () -> ExperimentMetrics.calculate(selection(), List.of(identity("UNREGISTERED", "FUSE", 1)), 1, "REPLAY"));
    }

    @Test
    void rejectsRepeatsBelowThePlan() {
        assertThrows(IllegalArgumentException.class,
            () -> ExperimentMetrics.calculate(selection(), List.of(identity("C", "FUSE", 0)), 1, "REPLAY"));
    }

    @Test
    void rejectsRepeatsBeyondThePlan() {
        assertThrows(IllegalArgumentException.class,
            () -> ExperimentMetrics.calculate(selection(), List.of(identity("C", "FUSE", 2)), 1, "REPLAY"));
    }

    @Test
    void rejectsZeroPlannedRepeats() {
        assertThrows(IllegalArgumentException.class,
            () -> ExperimentMetrics.calculate(selection(), List.of(), 0, "REPLAY"));
    }

    @Test
    void rejectsNegativePlannedRepeats() {
        assertThrows(IllegalArgumentException.class,
            () -> ExperimentMetrics.calculate(selection(), List.of(), -1, "REPLAY"));
    }

    private static ExperimentRegistry.Selection selection() {
        return new ExperimentRegistry.Selection("arithmetic-test-only", HASH,
            List.of(Json.ordered("caseId", "C", "kind", "ATTACK")));
    }

    private static Map<String, Object> identity(String caseId, String environment, int repeat) {
        return Json.ordered("caseId", caseId, "environment", environment, "repeat", repeat);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> objects(Object value) {
        return (List<Map<String, Object>>) value;
    }

    private static void assertJsonEquivalent(Object expected, Object actual, String path) {
        if (expected instanceof Number expectedNumber && actual instanceof Number actualNumber) {
            // JSON has one numeric domain; Java's int/long/double wrappers should not
            // make matching integer-valued aggregates differ from Python's values.
            assertEquals(0, new BigDecimal(expectedNumber.toString())
                .compareTo(new BigDecimal(actualNumber.toString())), path);
        } else if (expected instanceof Map<?, ?> expectedMap) {
            assertInstanceOf(Map.class, actual, path);
            Map<?, ?> actualMap = (Map<?, ?>) actual;
            assertEquals(expectedMap.keySet(), actualMap.keySet(), path);
            expectedMap.forEach((key, value) -> assertJsonEquivalent(value, actualMap.get(key), path + "." + key));
        } else if (expected instanceof List<?> expectedList) {
            assertInstanceOf(List.class, actual, path);
            List<?> actualList = (List<?>) actual;
            assertEquals(expectedList.size(), actualList.size(), path);
            for (int i = 0; i < expectedList.size(); i++) {
                assertJsonEquivalent(expectedList.get(i), actualList.get(i), path + "[" + i + "]");
            }
        } else {
            assertEquals(expected, actual, path);
        }
    }
}
