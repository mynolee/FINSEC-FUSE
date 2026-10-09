package com.finsec.fuse.observation;

import static com.finsec.fuse.observation.SecurityCheckObservation.Check.*;
import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.policy.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

/** Local fakes exercise existing boundaries; there are no databases, model calls, or new scenarios. */
class PolicyObservationTest {
    private final Json json = new Json(new JsonConfiguration().jsonMapper());
    private final FusePolicy policy = policy();
    private final AtomicLong clock = new AtomicLong();
    private final Instant now = Instant.parse("2026-10-09T04:00:00Z");

    @Test void verifiedEvidenceDenialIncludesItsRegistryReads() {
        var db = new ReadOnlyDb(sql -> {
            clock.addAndGet(30);
            return List.of();
        });
        var validator = new EvidenceValidator(db, policy, json);
        var session = SecurityCheckObservation.begin(clock::get);
        try (session) {
            assertEquals("EVIDENCE_MISSING", validator.validate("VERIFIED", List.of(), UUID.randomUUID(), "customer-102", now).reasonCode());
        }
        assertEquals(30, session.result().elapsedNanos());
        assertEquals(1L, session.result().completedChecks().get(VERIFIED_EVIDENCE));
    }

    @Test void baselineSharedNonVerifiedAndCustomerPrechecksAreExcluded() {
        var db = new ReadOnlyDb(sql -> {
            clock.addAndGet(30);
            return List.of();
        });
        var validator = new EvidenceValidator(db, policy, json);
        var session = SecurityCheckObservation.begin(clock::get);
        try (session) {
            assertEquals("MANUAL_REVIEW_REQUIRED", validator.validate("NEEDS_REVIEW", List.of(), UUID.randomUUID(), "customer-102", now).reasonCode());
            assertEquals("EVIDENCE_MISSING", validator.validateForCustomer("customer-102", List.of(), now).reasonCode());
        }
        assertEquals(0, session.result().elapsedNanos());
        assertEquals(0, session.result().completedCheckCount());
    }

    @Test void storedEvidenceNestedValidationCountsEachReadOnce() {
        UUID run = UUID.randomUUID();
        var db = new ReadOnlyDb(sql -> {
            if (sql.startsWith("SELECT r.*,a.customer_id")) {
                clock.addAndGet(15);
                return List.of(Map.of("status", "VALIDATED", "body_json", "{\"status\":\"VERIFIED\",\"evidenceIds\":[]}",
                        "run_id", run, "customer_id", "customer-102"));
            }
            clock.addAndGet(30);
            return List.of();
        });
        var validator = new EvidenceValidator(db, policy, json);
        var session = SecurityCheckObservation.begin(clock::get);
        try (session) {
            assertEquals("EVIDENCE_MISSING", validator.validateStored(UUID.randomUUID(), now).reasonCode());
        }
        assertEquals(45, session.result().elapsedNanos());
        assertEquals(2L, session.result().completedChecks().get(VERIFIED_EVIDENCE));
    }

    @Test void quarantineWorkflowAndAncestorReadsDoNotDoubleCount() {
        UUID run = UUID.randomUUID();
        var db = new ReadOnlyDb(sql -> {
            clock.addAndGet(5);
            return sql.startsWith("SELECT r.id FROM agent_run") ? List.of(Map.of("id", run)) : List.of();
        });
        var matcher = new QuarantineMatcher(db);
        var session = SecurityCheckObservation.begin(clock::get);
        try (session) { assertFalse(matcher.workflowQuarantined(UUID.randomUUID())); }
        assertEquals(20, session.result().elapsedNanos());
        assertEquals(2L, session.result().completedChecks().get(QUARANTINE_MATCH));
    }

    @Test void sharedCryptographicDenialIsExcludedFromAdditionalPolicyTiming() {
        var codec = new GrantCodec(json, new SigningKeyProvider("local-test", Map.of("local-test", new byte[32])));
        var db = new ReadOnlyDb(sql -> { throw new AssertionError("Invalid transport must be denied before a database read"); });
        var delegation = new DelegationService(db, json, policy, codec, new EnvelopeValidator(),
                new EvidenceValidator(db, policy, json), new QuarantineMatcher(db));
        var session = SecurityCheckObservation.begin(() -> clock.getAndAdd(200));
        try (session) {
            assertEquals("SIGNATURE_INVALID", assertThrows(PolicyException.class,
                    () -> delegation.validate(null, "FUSE", UUID.randomUUID(), UUID.randomUUID(), "EVALUATE_KYC", now)).reasonCode());
        }
        assertEquals(0, session.result().elapsedNanos());
        assertEquals(0, session.result().completedCheckCount());
    }

    @Test void authenticatedDelegationContextDenialStillMeasuresTheFuseFailurePath() {
        var codec = new GrantCodec(json, new SigningKeyProvider("local-test", Map.of("local-test", new byte[32])));
        var db = new ReadOnlyDb(sql -> { throw new AssertionError("Wrong workflow is denied before a database read"); });
        var delegation = new DelegationService(db, json, policy, codec, new EnvelopeValidator(),
                new EvidenceValidator(db, policy, json), new QuarantineMatcher(db));
        byte[] body=json.bytes(Map.of("amountKrw",1_000_000));
        var claims=new GrantClaims(UUID.randomUUID(),UUID.randomUUID(),1,UUID.randomUUID(),"customer-102",
                "LOAN_APPLICATION","FUSE","FUSE","KYC",null,UUID.randomUUID(),"EVALUATE_KYC","customer-102",
                1_000_000,UUID.randomUUID(),null,null,null,1,UUID.randomUUID(),Json.sha256(body),"FUSE-MVP-2",
                UUID.randomUUID(),null,now.plusSeconds(60).toEpochMilli());
        var transport=codec.sign(claims,body);
        var session = SecurityCheckObservation.begin(() -> clock.getAndAdd(200));
        try (session) {
            assertEquals("CONTEXT_MISMATCH", assertThrows(PolicyException.class,
                    () -> delegation.validate(transport, "FUSE", UUID.randomUUID(), claims.targetRunId(), "EVALUATE_KYC", now)).reasonCode());
        }
        assertEquals(200, session.result().elapsedNanos());
        assertEquals(1L, session.result().completedChecks().get(DELEGATION_VALIDATION));
    }

    private FusePolicy policy() {
        try (var input = new ClassPathResource("config/demo_policy.json").getInputStream()) {
            return json.read(input.readAllBytes(), FusePolicy.class);
        } catch (java.io.IOException error) { throw new AssertionError(error); }
    }

    private static final class ReadOnlyDb extends Db {
        private final Function<String, List<Map<String, Object>>> read;
        private ReadOnlyDb(Function<String, List<Map<String, Object>>> read) {
            super(null);
            this.read = read;
        }
        @Override public List<Map<String, Object>> query(String sql, Object... args) { return read.apply(sql); }
        @Override public int update(String sql, Object... args) { throw new AssertionError("Policy timing must remain read-only"); }
    }
}
