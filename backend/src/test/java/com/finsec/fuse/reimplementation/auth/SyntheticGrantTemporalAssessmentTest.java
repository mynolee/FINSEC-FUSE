package com.finsec.fuse.reimplementation.auth;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import java.util.Set;

/** Independent synthetic fact vectors; SOURCE ONLY / NOT_RUN.
 * No clock, keys, role lookup, persistence, authority or consumption.
 * Expectations derive from the separately frozen semantic vectors, not implementation helpers.
 */
final class SyntheticGrantTemporalAssessmentTest {
    @Test void issue_equality_admitted() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void just_before_issue() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(99L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(false, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.NOT_YET_VALID), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void last_second() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(199L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void expiry_equality() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(200L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(false, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.EXPIRED), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void after_expiry() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(201L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(false, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.EXPIRED), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void child_equal_parent_cap() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void child_over_parent_cap() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 199L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(false, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.PARENT_EXPIRY_EXCEEDED), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void child_parent_expiry_equality() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(150L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 150L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(false, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.PARENT_EXPIRY_EXCEEDED, SyntheticGrantTemporalAssessment.Blocker.PARENT_EXPIRED), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void all_time_blockers_applicable() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(200L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 150L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(false, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.EXPIRED, SyntheticGrantTemporalAssessment.Blocker.PARENT_EXPIRY_EXCEEDED, SyntheticGrantTemporalAssessment.Blocker.PARENT_EXPIRED), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void long_max_boundary() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(9223372036854775806L, 0L, 9223372036854775807L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void long_max_expired() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(9223372036854775807L, 0L, 9223372036854775807L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(false, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.EXPIRED), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void grantRevoked_active() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.GRANT_REVOKED_ACTIVE), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void grantRevoked_unknown() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.GRANT_REVOKED_UNKNOWN), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void rootAuthorizationRevoked_active() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.ROOT_AUTHORIZATION_REVOKED_ACTIVE), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void rootAuthorizationRevoked_unknown() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.ROOT_AUTHORIZATION_REVOKED_UNKNOWN), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void keyRevoked_active() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.KEY_REVOKED_ACTIVE), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void keyRevoked_unknown() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.KEY_REVOKED_UNKNOWN), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void parentRevoked_active() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.PARENT_REVOKED_ACTIVE), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void parentRevoked_unknown() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.PARENT_REVOKED_UNKNOWN), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void workflowQuarantined_active() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.WORKFLOW_QUARANTINED_ACTIVE), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void workflowQuarantined_unknown() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.WORKFLOW_QUARANTINED_UNKNOWN), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void sourceVersionQuarantined_active() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.SOURCE_VERSION_QUARANTINED_ACTIVE), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void sourceVersionQuarantined_unknown() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.SOURCE_VERSION_QUARANTINED_UNKNOWN), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void agentVersionQuarantined_active() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.AGENT_VERSION_QUARANTINED_ACTIVE), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void agentVersionQuarantined_unknown() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.AGENT_VERSION_QUARANTINED_UNKNOWN), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void ancestorRunQuarantined_active() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.ANCESTOR_RUN_QUARANTINED_ACTIVE), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void ancestorRunQuarantined_unknown() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.CLEAR));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.ANCESTOR_RUN_QUARANTINED_UNKNOWN), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void ancestorResultQuarantined_active() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.ACTIVE));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.ANCESTOR_RESULT_QUARANTINED_ACTIVE), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void ancestorResultQuarantined_unknown() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.UNKNOWN));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.ANCESTOR_RESULT_QUARANTINED_UNKNOWN), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void all_facts_active() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.ACTIVE));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.GRANT_REVOKED_ACTIVE, SyntheticGrantTemporalAssessment.Blocker.ROOT_AUTHORIZATION_REVOKED_ACTIVE, SyntheticGrantTemporalAssessment.Blocker.KEY_REVOKED_ACTIVE, SyntheticGrantTemporalAssessment.Blocker.PARENT_REVOKED_ACTIVE, SyntheticGrantTemporalAssessment.Blocker.WORKFLOW_QUARANTINED_ACTIVE, SyntheticGrantTemporalAssessment.Blocker.SOURCE_VERSION_QUARANTINED_ACTIVE, SyntheticGrantTemporalAssessment.Blocker.AGENT_VERSION_QUARANTINED_ACTIVE, SyntheticGrantTemporalAssessment.Blocker.ANCESTOR_RUN_QUARANTINED_ACTIVE, SyntheticGrantTemporalAssessment.Blocker.ANCESTOR_RESULT_QUARANTINED_ACTIVE), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void all_facts_unknown() {
        var result = SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
            new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.UNKNOWN));
        assertEquals(true, result.timeWithinWindow());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.GRANT_REVOKED_UNKNOWN, SyntheticGrantTemporalAssessment.Blocker.ROOT_AUTHORIZATION_REVOKED_UNKNOWN, SyntheticGrantTemporalAssessment.Blocker.KEY_REVOKED_UNKNOWN, SyntheticGrantTemporalAssessment.Blocker.PARENT_REVOKED_UNKNOWN, SyntheticGrantTemporalAssessment.Blocker.WORKFLOW_QUARANTINED_UNKNOWN, SyntheticGrantTemporalAssessment.Blocker.SOURCE_VERSION_QUARANTINED_UNKNOWN, SyntheticGrantTemporalAssessment.Blocker.AGENT_VERSION_QUARANTINED_UNKNOWN, SyntheticGrantTemporalAssessment.Blocker.ANCESTOR_RUN_QUARANTINED_UNKNOWN, SyntheticGrantTemporalAssessment.Blocker.ANCESTOR_RESULT_QUARANTINED_UNKNOWN), result.blockers());
        assertFalse(result.authorizationEstablished());
    }

    @Test void negative_now() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(-1L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void negative_issue() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, -1L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void negative_expiry() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, -1L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void expiry_equals_issue() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 100L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void expiry_before_issue() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 99L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void root_with_parent() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, 200L),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void child_missing_parent() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, null),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void child_negative_parent() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, -1L),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void null_chain() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, null, null),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void root_parent_active_invalid() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.ACTIVE, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void root_parent_unknown_invalid() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.UNKNOWN, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void null_grantRevoked() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
                new SyntheticGrantTemporalAssessment.RevocationFacts(null, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void null_rootAuthorizationRevoked() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, null, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void null_keyRevoked() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, null, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void null_parentRevoked() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, null, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void null_workflowQuarantined() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, null, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void null_sourceVersionQuarantined() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, null, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void null_agentVersionQuarantined() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, null, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void null_ancestorRunQuarantined() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, null, SyntheticGrantTemporalAssessment.Fact.CLEAR)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void null_ancestorResultQuarantined() {
        var error = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L, SyntheticGrantTemporalAssessment.ChainPosition.CHILD, 200L),
                new SyntheticGrantTemporalAssessment.RevocationFacts(SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR, null)));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void nullWholeInputsUseFixedFailure() {
        var time = new SyntheticGrantTemporalAssessment.TemporalFacts(100L, 100L, 200L,
            SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null);
        var clear = new SyntheticGrantTemporalAssessment.RevocationFacts(
            SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR,
            SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR,
            SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR,
            SyntheticGrantTemporalAssessment.Fact.CLEAR, SyntheticGrantTemporalAssessment.Fact.CLEAR,
            SyntheticGrantTemporalAssessment.Fact.CLEAR);
        var first = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(null, clear));
        var second = assertThrows(IllegalArgumentException.class, () ->
            SyntheticGrantTemporalAssessment.assess(time, null));
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", first.getMessage());
        assertEquals("INVALID_GRANT_TEMPORAL_FACTS", second.getMessage());
        assertNull(first.getCause()); assertNull(second.getCause());
        var result = SyntheticGrantTemporalAssessment.assess(time, clear);
        assertThrows(UnsupportedOperationException.class, () -> result.blockers().add(
            SyntheticGrantTemporalAssessment.Blocker.EXPIRED));
        assertThrows(UnsupportedOperationException.class, () -> result.blockers().clear());
        var again = SyntheticGrantTemporalAssessment.assess(time, clear);
        assertEquals(result.timeWithinWindow(), again.timeWithinWindow());
        assertEquals(result.blockers(), again.blockers());
        assertTrue(again.blockers().isEmpty());
        assertFalse(result.authorizationEstablished()); assertFalse(again.authorizationEstablished());
        assertEquals(100L, time.nowEpochSecond());
        assertEquals(SyntheticGrantTemporalAssessment.Fact.CLEAR, clear.grantRevoked());
        assertEquals("TemporalFacts[REDACTED]", time.toString());
        assertEquals("RevocationFacts[REDACTED]", clear.toString());
        assertEquals("Assessment[NON_AUTHORIZING]", result.toString());
    }
}
