package com.finsec.fuse.testing;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.common.Json;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

/** Full-row oracle for deliberate fixture administration, separate from zero-write HTTP assertions. */
public final class DemoTokenFixtureOracle {
    private final DemoTokenTestFixture fixture;
    private final Json json;
    private final Supplier<Map<String, List<String>>> snapshot;
    public DemoTokenFixtureOracle(DemoTokenTestFixture fixture, Json json,
            Supplier<Map<String, List<String>>> snapshot) {
        this.fixture = fixture;
        this.json = json;
        this.snapshot = snapshot;
    }

    public Map<String, List<String>> issue(String token, Actor actor) {
        var before = snapshot.get();
        Instant lower = fixture.authorityNow();
        fixture.issue(token, actor);
        Instant upper = fixture.authorityNow();
        var after = snapshot.get();
        unchangedOtherTables(before, after);
        var oldRows = before.get("demo_token");
        var newRows = after.get("demo_token");
        assertEquals(oldRows.size() + 1, newRows.size());
        assertTrue(newRows.containsAll(oldRows), "Issuance cannot alter any existing credential");
        var added = new ArrayList<>(newRows);
        added.removeAll(oldRows);
        assertEquals(1, added.size());
        var row = json.map(added.getFirst());
        Instant issued = Instant.parse((String) row.get("issued_at"));
        assertFalse(issued.isBefore(lower));
        assertFalse(issued.isAfter(upper));
        assertEquals(issued.plusSeconds(7200), Instant.parse((String) row.get("expires_at")));
        var expected = new LinkedHashMap<String, Object>();
        expected.put("fingerprint", "\\x" + DevActorRegistry.fingerprint(token));
        expected.put("registry_id", json.map(after.get("demo_auth_registry").getFirst()).get("registry_id"));
        expected.put("actor_id", actor.actorId());
        expected.put("role", actor.role());
        expected.put("initial_scope", actor.customerIds().stream().sorted().toList());
        expected.put("current_scope", actor.customerIds().stream().sorted().toList());
        expected.put("issued_at", row.get("issued_at"));
        expected.put("expires_at", row.get("expires_at"));
        expected.put("security_policy", "FUSE-SECURITY-1");
        expected.put("issuance_ttl_seconds", 7200);
        expected.put("status", "ACTIVE");
        expected.put("revoked_at", null);
        expected.put("revision", 0);
        assertEquals(expected, row, "Exactly one fully specified synthetic credential may be added");
        return after;
    }

    public Map<String, List<String>> updateScope(String actorId, Set<String> scope) {
        return mutate(actorId, scope, false);
    }
    public Map<String, List<String>> revoke(String actorId) {
        return mutate(actorId, null, true);
    }
    private Map<String, List<String>> mutate(String actorId, Set<String> scope, boolean revoke) {
        var before = snapshot.get();
        Instant lower = fixture.authorityNow();
        if (revoke) fixture.revoke(actorId); else fixture.updateScope(actorId, scope);
        Instant upper = fixture.authorityNow();
        var after = snapshot.get();
        unchangedOtherTables(before, after);
        var actual = byFingerprint(after.get("demo_token"));
        var expected = byFingerprint(before.get("demo_token"));
        assertEquals(expected.keySet(), actual.keySet(), "Administration cannot issue or erase a credential");
        int selected = 0;
        for (var row : expected.values()) {
            if (!actorId.equals(row.get("actor_id"))) continue;
            selected++;
            if (revoke && "REVOKED".equals(row.get("status"))) continue;
            if (!revoke && scope.stream().sorted().toList().equals(row.get("current_scope"))) continue;
            if (revoke) {
                var revoked = actual.get(row.get("fingerprint")).get("revoked_at");
                assertNotNull(revoked);
                Instant at = Instant.parse((String) revoked);
                assertFalse(at.isBefore(lower));
                assertFalse(at.isAfter(upper));
                row.put("status", "REVOKED");
                row.put("revoked_at", revoked);
            } else row.put("current_scope", scope.stream().sorted().toList());
            row.put("revision", ((Number) row.get("revision")).longValue() + 1);
        }
        assertTrue(selected > 0, "The fixture must target existing credentials");
        assertEquals(json.map(json.write(expected)), json.map(json.write(actual)),
                "Only the selected scope/status, first revocation timestamp and exact revision increment may change");
        return after;
    }
    private Map<String, Map<String, Object>> byFingerprint(List<String> rows) {
        var result = new LinkedHashMap<String, Map<String, Object>>();
        for (String value : rows) {
            var row = json.map(value);
            assertNull(result.put((String) row.get("fingerprint"), row));
        }
        return result;
    }
    private void unchangedOtherTables(Map<String, List<String>> before, Map<String, List<String>> after) {
        assertEquals(before.keySet(), after.keySet());
        assertTrue(before.keySet().containsAll(List.of("demo_auth_registry", "demo_token")));
        for (String table : before.keySet())
            if (!table.equals("demo_token")) assertEquals(before.get(table), after.get(table),
                    "Explicit auth administration must preserve every other row in " + table);
    }
}
