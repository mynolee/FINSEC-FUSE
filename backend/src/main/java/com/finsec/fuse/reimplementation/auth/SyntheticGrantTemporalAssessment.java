package com.finsec.fuse.reimplementation.auth;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/** Unselected synthetic policy candidate; caller assertions are not authoritative facts.
 * No IO, clock, key, authority, consumption, cache or persistence.
 */
public final class SyntheticGrantTemporalAssessment {
    private SyntheticGrantTemporalAssessment() {}
    public enum ChainPosition { ROOT, CHILD }
    public enum Fact { CLEAR, ACTIVE, UNKNOWN }
    public enum Blocker {
        NOT_YET_VALID,
        EXPIRED,
        PARENT_EXPIRY_EXCEEDED,
        PARENT_EXPIRED,
        GRANT_REVOKED_ACTIVE,
        GRANT_REVOKED_UNKNOWN,
        ROOT_AUTHORIZATION_REVOKED_ACTIVE,
        ROOT_AUTHORIZATION_REVOKED_UNKNOWN,
        KEY_REVOKED_ACTIVE,
        KEY_REVOKED_UNKNOWN,
        PARENT_REVOKED_ACTIVE,
        PARENT_REVOKED_UNKNOWN,
        WORKFLOW_QUARANTINED_ACTIVE,
        WORKFLOW_QUARANTINED_UNKNOWN,
        SOURCE_VERSION_QUARANTINED_ACTIVE,
        SOURCE_VERSION_QUARANTINED_UNKNOWN,
        AGENT_VERSION_QUARANTINED_ACTIVE,
        AGENT_VERSION_QUARANTINED_UNKNOWN,
        ANCESTOR_RUN_QUARANTINED_ACTIVE,
        ANCESTOR_RUN_QUARANTINED_UNKNOWN,
        ANCESTOR_RESULT_QUARANTINED_ACTIVE,
        ANCESTOR_RESULT_QUARANTINED_UNKNOWN
    }
    public record TemporalFacts(long nowEpochSecond, long issuedAtEpochSecond,
            long expiresAtEpochSecond, ChainPosition chainPosition, Long parentExpiresAtEpochSecond) {
        @Override public String toString() { return "TemporalFacts[REDACTED]"; }
    }
    public record RevocationFacts(Fact grantRevoked,
            Fact rootAuthorizationRevoked,
            Fact keyRevoked,
            Fact parentRevoked,
            Fact workflowQuarantined,
            Fact sourceVersionQuarantined,
            Fact agentVersionQuarantined,
            Fact ancestorRunQuarantined,
            Fact ancestorResultQuarantined) {
        @Override public String toString() { return "RevocationFacts[REDACTED]"; }
    }
    public static final class Assessment {
        private final boolean timeWithinWindow;
        private final Set<Blocker> blockers;
        private Assessment(boolean within, EnumSet<Blocker> values) {
            timeWithinWindow = within;
            blockers = Collections.unmodifiableSet(values.clone());
        }
        public boolean timeWithinWindow() { return timeWithinWindow; }
        public Set<Blocker> blockers() { return blockers; }
        public boolean authorizationEstablished() { return false; }
        @Override public String toString() { return "Assessment[NON_AUTHORIZING]"; }
    }
    public static Assessment assess(TemporalFacts t, RevocationFacts r) {
        if (t == null || r == null || t.chainPosition() == null
                || t.nowEpochSecond() < 0 || t.issuedAtEpochSecond() < 0
                || t.expiresAtEpochSecond() <= t.issuedAtEpochSecond()
                || (t.parentExpiresAtEpochSecond() != null && t.parentExpiresAtEpochSecond() < 0)
                || (t.chainPosition() == ChainPosition.ROOT
                    && (t.parentExpiresAtEpochSecond() != null || r.parentRevoked() != Fact.CLEAR))
                || (t.chainPosition() == ChainPosition.CHILD && t.parentExpiresAtEpochSecond() == null)) {
            throw invalid();
        }
        // Validate every fact before constructing a result; no partial assessment escapes.
        if (r.grantRevoked() == null
                || r.rootAuthorizationRevoked() == null
                || r.keyRevoked() == null
                || r.parentRevoked() == null
                || r.workflowQuarantined() == null
                || r.sourceVersionQuarantined() == null
                || r.agentVersionQuarantined() == null
                || r.ancestorRunQuarantined() == null
                || r.ancestorResultQuarantined() == null) throw invalid();
        EnumSet<Blocker> b = EnumSet.noneOf(Blocker.class);
        if (t.nowEpochSecond() < t.issuedAtEpochSecond()) b.add(Blocker.NOT_YET_VALID);
        if (t.nowEpochSecond() >= t.expiresAtEpochSecond()) b.add(Blocker.EXPIRED);
        if (t.chainPosition() == ChainPosition.CHILD) {
            long parentExpiry = t.parentExpiresAtEpochSecond();
            if (t.expiresAtEpochSecond() > parentExpiry) b.add(Blocker.PARENT_EXPIRY_EXCEEDED);
            if (t.nowEpochSecond() >= parentExpiry) b.add(Blocker.PARENT_EXPIRED);
        }
        boolean within = b.isEmpty();
        add(b, r.grantRevoked(), Blocker.GRANT_REVOKED_ACTIVE, Blocker.GRANT_REVOKED_UNKNOWN);
        add(b, r.rootAuthorizationRevoked(), Blocker.ROOT_AUTHORIZATION_REVOKED_ACTIVE, Blocker.ROOT_AUTHORIZATION_REVOKED_UNKNOWN);
        add(b, r.keyRevoked(), Blocker.KEY_REVOKED_ACTIVE, Blocker.KEY_REVOKED_UNKNOWN);
        add(b, r.parentRevoked(), Blocker.PARENT_REVOKED_ACTIVE, Blocker.PARENT_REVOKED_UNKNOWN);
        add(b, r.workflowQuarantined(), Blocker.WORKFLOW_QUARANTINED_ACTIVE, Blocker.WORKFLOW_QUARANTINED_UNKNOWN);
        add(b, r.sourceVersionQuarantined(), Blocker.SOURCE_VERSION_QUARANTINED_ACTIVE, Blocker.SOURCE_VERSION_QUARANTINED_UNKNOWN);
        add(b, r.agentVersionQuarantined(), Blocker.AGENT_VERSION_QUARANTINED_ACTIVE, Blocker.AGENT_VERSION_QUARANTINED_UNKNOWN);
        add(b, r.ancestorRunQuarantined(), Blocker.ANCESTOR_RUN_QUARANTINED_ACTIVE, Blocker.ANCESTOR_RUN_QUARANTINED_UNKNOWN);
        add(b, r.ancestorResultQuarantined(), Blocker.ANCESTOR_RESULT_QUARANTINED_ACTIVE, Blocker.ANCESTOR_RESULT_QUARANTINED_UNKNOWN);
        return new Assessment(within, b);
    }
    private static void add(EnumSet<Blocker> b, Fact fact, Blocker active, Blocker unknown) {
        if (fact == Fact.ACTIVE) b.add(active);
        else if (fact == Fact.UNKNOWN) b.add(unknown);
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_GRANT_TEMPORAL_FACTS");
    }
}
