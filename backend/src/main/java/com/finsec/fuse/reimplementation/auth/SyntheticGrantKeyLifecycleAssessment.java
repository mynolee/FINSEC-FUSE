package com.finsec.fuse.reimplementation.auth;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Supplied key-lifecycle consistency under issuance-only retirement.
 * No key, binding, current fact, chronology, clock or store is acquired; no key
 * transition, retention, destruction, grant operation or disclosure is performed.
 */
public final class SyntheticGrantKeyLifecycleAssessment {
    public static final String PROFILE = "RETIRE_ISSUANCE_ONLY_VERIFY_OUTSTANDING_V1";
    private SyntheticGrantKeyLifecycleAssessment() { }

    public enum Lifecycle { ACTIVE, RETIRED, REVOKED, UNKNOWN }
    public enum UseKind { NEW_ISSUANCE, OUTSTANDING_NEW_WORK, EXACT_COMMITTED_RECEIPT_READ }
    public enum Ordering { BEFORE_RETIREMENT, AT_RETIREMENT, AFTER_RETIREMENT, UNKNOWN }
    public enum MaterialFact { AVAILABLE, UNAVAILABLE, UNKNOWN }
    public enum Blocker {
        KEY_BINDING_UNCONFIRMED, KEY_BINDING_MISMATCH, KEY_STATE_UNKNOWN, KEY_REVOKED,
        KEY_RETIRED_FOR_ISSUANCE, ISSUANCE_BINDING_CHANGED_ACTIVE, ISSUANCE_BINDING_CHANGED_UNKNOWN,
        MATERIAL_UNAVAILABLE, MATERIAL_UNKNOWN, GRANT_NOT_ISSUED, GRANT_LIFECYCLE_UNKNOWN,
        RETIREMENT_ORDER_NOT_BEFORE, RETIREMENT_ORDER_UNKNOWN,
        CREDENTIAL_INVALID_ACTIVE, CREDENTIAL_INVALID_UNKNOWN,
        ACTOR_MISMATCH_ACTIVE, ACTOR_MISMATCH_UNKNOWN,
        OWNER_DENIED_ACTIVE, OWNER_DENIED_UNKNOWN,
        OPERATION_DENIED_ACTIVE, OPERATION_DENIED_UNKNOWN,
        ANCESTOR_EXPIRY_BLOCKED_ACTIVE, ANCESTOR_EXPIRY_BLOCKED_UNKNOWN,
        OTHER_APPLICABLE_GATE_BLOCKED_ACTIVE, OTHER_APPLICABLE_GATE_BLOCKED_UNKNOWN,
        HISTORICAL_RECEIPT_UNCONFIRMED, TRANSITION_NOT_ALLOWED
    }

    /** Exact opaque identifiers only; no algorithm choice, path or key bytes. */
    public record KeyBinding(String kid, String issuer, String algorithm, String keyVersion) {
        public KeyBinding {
            text(kid); text(issuer); text(algorithm); text(keyVersion);
        }
        @Override public String toString() { return "KeyBinding[SUPPLIED_REDACTED]"; }
    }

    /** Missing binding is representable only for an unresolved key snapshot. */
    public record KeySnapshot(KeyBinding binding, Lifecycle lifecycle) {
        public KeySnapshot {
            if (lifecycle == null || (binding == null && lifecycle != Lifecycle.UNKNOWN)) throw invalid();
        }
        @Override public String toString() { return "KeySnapshot[SUPPLIED_REDACTED]"; }
    }

    /** Already-applicable current gates, never defaulted to CLEAR or acquired here. */
    public record CurrentUseFacts(SyntheticGrantTemporalAssessment.Fact credentialInvalid,
                                  SyntheticGrantTemporalAssessment.Fact actorMismatch,
                                  SyntheticGrantTemporalAssessment.Fact ownerDenied,
                                  SyntheticGrantTemporalAssessment.Fact operationDenied,
                                  SyntheticGrantTemporalAssessment.Fact ancestorExpiryBlocked,
                                  SyntheticGrantTemporalAssessment.Fact otherApplicableGateBlocked) {
        public CurrentUseFacts {
            if (credentialInvalid == null || actorMismatch == null || ownerDenied == null
                    || operationDenied == null || ancestorExpiryBlocked == null
                    || otherApplicableGateBlocked == null) throw invalid();
        }
        @Override public String toString() { return "CurrentUseFacts[SUPPLIED_REDACTED]"; }
    }

    public static final class Assessment {
        private final UseKind purpose;
        private final Set<Blocker> blockers;
        private final Set<SyntheticGrantTemporalAssessment.Blocker> temporalBlockers;
        private final Set<SyntheticGrantReplayAssessment.Blocker> historicalReadBlockers;
        private final boolean ownExpiryExceptionApplied;

        private Assessment(UseKind purpose, Set<Blocker> blockers,
                           Set<SyntheticGrantTemporalAssessment.Blocker> temporal,
                           Set<SyntheticGrantReplayAssessment.Blocker> history, boolean ownExpiry) {
            this.purpose = purpose;
            this.blockers = immutable(blockers, Blocker.class);
            this.temporalBlockers = immutable(temporal, SyntheticGrantTemporalAssessment.Blocker.class);
            this.historicalReadBlockers = immutable(history, SyntheticGrantReplayAssessment.Blocker.class);
            this.ownExpiryExceptionApplied = ownExpiry;
        }
        public UseKind purpose() { return purpose; }
        public Set<Blocker> blockers() { return blockers; }
        public Set<SyntheticGrantTemporalAssessment.Blocker> temporalBlockers() { return temporalBlockers; }
        public Set<SyntheticGrantReplayAssessment.Blocker> historicalReadBlockers() { return historicalReadBlockers; }
        public boolean ownExpiryExceptionApplied() { return ownExpiryExceptionApplied; }
        public boolean suppliedConditionsSatisfied() {
            return blockers.isEmpty() && temporalBlockers.isEmpty() && historicalReadBlockers.isEmpty();
        }
        public boolean authorizationEstablished() { return false; }
        public boolean keyBindingEstablished() { return false; }
        public boolean keyTransitionEstablished() { return false; }
        public boolean materialRetentionEstablished() { return false; }
        public boolean materialDestructionEstablished() { return false; }
        public boolean executionAuthorityGranted() { return false; }
        @Override public String toString() { return "KeyLifecycleAssessment[SUPPLIED_NON_AUTHORIZING]"; }
    }

    public static final class TransitionAssessment {
        private final Set<Blocker> blockers;
        private TransitionAssessment(Set<Blocker> blockers) {
            this.blockers = immutable(blockers, Blocker.class);
        }
        public Set<Blocker> blockers() { return blockers; }
        public boolean suppliedTransitionConsistent() { return blockers.isEmpty(); }
        public boolean authorizationEstablished() { return false; }
        public boolean keyBindingEstablished() { return false; }
        public boolean keyTransitionEstablished() { return false; }
        public boolean materialRetentionEstablished() { return false; }
        public boolean materialDestructionEstablished() { return false; }
        public boolean executionAuthorityGranted() { return false; }
        @Override public String toString() { return "KeyTransitionAssessment[SUPPLIED_NON_AUTHORIZING]"; }
    }

    /** bindingChanged models the required current issuance-commit fence as supplied data. */
    public static Assessment assessNewIssuance(KeyBinding expected, KeySnapshot supplied,
            SyntheticGrantTemporalAssessment.Fact bindingChanged, MaterialFact material,
            SyntheticGrantTemporalAssessment.TemporalFacts time,
            SyntheticGrantTemporalAssessment.RevocationFacts revocation, CurrentUseFacts current) {
        if (bindingChanged == null || material == null || current == null) throw invalid();
        var blockers = binding(expected, supplied);
        if (supplied.lifecycle() == Lifecycle.RETIRED) blockers.add(Blocker.KEY_RETIRED_FOR_ISSUANCE);
        add(blockers, bindingChanged, Blocker.ISSUANCE_BINDING_CHANGED_ACTIVE, Blocker.ISSUANCE_BINDING_CHANGED_UNKNOWN);
        material(blockers, material);
        current(blockers, current);
        var temporal = temporal(time, revocation);
        return new Assessment(UseKind.NEW_ISSUANCE, blockers, temporal.blockers(),
                EnumSet.noneOf(SyntheticGrantReplayAssessment.Blocker.class), false);
    }

    public static Assessment assessOutstanding(KeyBinding expected, KeySnapshot supplied,
            SyntheticGrantReplayAssessment.GrantLifecycle grantLifecycle, Ordering ordering,
            MaterialFact material, SyntheticGrantTemporalAssessment.TemporalFacts time,
            SyntheticGrantTemporalAssessment.RevocationFacts revocation, CurrentUseFacts current) {
        if (grantLifecycle == null || ordering == null || material == null || current == null) throw invalid();
        var blockers = binding(expected, supplied);
        if (grantLifecycle == SyntheticGrantReplayAssessment.GrantLifecycle.UNKNOWN)
            blockers.add(Blocker.GRANT_LIFECYCLE_UNKNOWN);
        else if (grantLifecycle != SyntheticGrantReplayAssessment.GrantLifecycle.ISSUED)
            blockers.add(Blocker.GRANT_NOT_ISSUED);
        if (supplied.lifecycle() == Lifecycle.RETIRED) {
            if (ordering == Ordering.UNKNOWN) blockers.add(Blocker.RETIREMENT_ORDER_UNKNOWN);
            else if (ordering != Ordering.BEFORE_RETIREMENT) blockers.add(Blocker.RETIREMENT_ORDER_NOT_BEFORE);
        }
        material(blockers, material);
        current(blockers, current);
        var temporal = temporal(time, revocation);
        return new Assessment(UseKind.OUTSTANDING_NEW_WORK, blockers, temporal.blockers(),
                EnumSet.noneOf(SyntheticGrantReplayAssessment.Blocker.class), false);
    }

    /**
     * Original key binding and time/revocation facts are supplied as pertaining to
     * this exact receipt identity; the relationship is not authenticated here.
     * No new material argument or MAC re-verification duty is introduced.
     */
    public static Assessment assessHistoricalRead(KeyBinding expected, KeySnapshot supplied,
            SyntheticGrantReplayAssessment.CommandIdentity requested,
            SyntheticGrantReplayAssessment.SuppliedReceipt receipt,
            SyntheticGrantTemporalAssessment.TemporalFacts time,
            SyntheticGrantTemporalAssessment.RevocationFacts revocation,
            SyntheticGrantReplayAssessment.CurrentReadFacts current) {
        var blockers = binding(expected, supplied);
        final SyntheticGrantReplayAssessment.Assessment history;
        try {
            history = SyntheticGrantReplayAssessment.assessHistoricalRead(requested, receipt, time, revocation, current);
        } catch (IllegalArgumentException | NullPointerException malformed) {
            throw invalid();
        }
        if (history.identityOutcome() != SyntheticGrantReplayAssessment.IdentityOutcome.EXACT_SUPPLIED_COMMITTED_BINDING)
            blockers.add(Blocker.HISTORICAL_RECEIPT_UNCONFIRMED);
        return new Assessment(UseKind.EXACT_COMMITTED_RECEIPT_READ, blockers, history.temporalBlockers(),
                history.blockers(), history.ownExpiryExceptionApplied());
    }

    /** Allowed directed edges only; this never changes a key or persists a transition. */
    public static TransitionAssessment assessTransition(KeySnapshot before, KeySnapshot after) {
        if (before == null || after == null) throw invalid();
        var blockers = EnumSet.noneOf(Blocker.class);
        if (before.binding() == null || after.binding() == null) blockers.add(Blocker.KEY_BINDING_UNCONFIRMED);
        else if (!before.binding().equals(after.binding())) blockers.add(Blocker.KEY_BINDING_MISMATCH);
        if (before.lifecycle() == Lifecycle.UNKNOWN || after.lifecycle() == Lifecycle.UNKNOWN)
            blockers.add(Blocker.KEY_STATE_UNKNOWN);
        boolean edge = before.lifecycle() == Lifecycle.ACTIVE
                && (after.lifecycle() == Lifecycle.RETIRED || after.lifecycle() == Lifecycle.REVOKED)
                || before.lifecycle() == Lifecycle.RETIRED && after.lifecycle() == Lifecycle.REVOKED;
        if (!edge) blockers.add(Blocker.TRANSITION_NOT_ALLOWED);
        return new TransitionAssessment(blockers);
    }

    private static EnumSet<Blocker> binding(KeyBinding expected, KeySnapshot supplied) {
        if (expected == null || supplied == null) throw invalid();
        var blockers = EnumSet.noneOf(Blocker.class);
        if (supplied.binding() == null) blockers.add(Blocker.KEY_BINDING_UNCONFIRMED);
        else if (!expected.equals(supplied.binding())) blockers.add(Blocker.KEY_BINDING_MISMATCH);
        if (supplied.lifecycle() == Lifecycle.UNKNOWN) blockers.add(Blocker.KEY_STATE_UNKNOWN);
        if (supplied.lifecycle() == Lifecycle.REVOKED) blockers.add(Blocker.KEY_REVOKED);
        return blockers;
    }
    private static void material(EnumSet<Blocker> blockers, MaterialFact fact) {
        if (fact == MaterialFact.UNAVAILABLE) blockers.add(Blocker.MATERIAL_UNAVAILABLE);
        else if (fact == MaterialFact.UNKNOWN) blockers.add(Blocker.MATERIAL_UNKNOWN);
    }
    private static void current(EnumSet<Blocker> blockers, CurrentUseFacts f) {
        add(blockers, f.credentialInvalid(), Blocker.CREDENTIAL_INVALID_ACTIVE, Blocker.CREDENTIAL_INVALID_UNKNOWN);
        add(blockers, f.actorMismatch(), Blocker.ACTOR_MISMATCH_ACTIVE, Blocker.ACTOR_MISMATCH_UNKNOWN);
        add(blockers, f.ownerDenied(), Blocker.OWNER_DENIED_ACTIVE, Blocker.OWNER_DENIED_UNKNOWN);
        add(blockers, f.operationDenied(), Blocker.OPERATION_DENIED_ACTIVE, Blocker.OPERATION_DENIED_UNKNOWN);
        add(blockers, f.ancestorExpiryBlocked(), Blocker.ANCESTOR_EXPIRY_BLOCKED_ACTIVE, Blocker.ANCESTOR_EXPIRY_BLOCKED_UNKNOWN);
        add(blockers, f.otherApplicableGateBlocked(), Blocker.OTHER_APPLICABLE_GATE_BLOCKED_ACTIVE,
                Blocker.OTHER_APPLICABLE_GATE_BLOCKED_UNKNOWN);
    }
    private static SyntheticGrantTemporalAssessment.Assessment temporal(
            SyntheticGrantTemporalAssessment.TemporalFacts time,
            SyntheticGrantTemporalAssessment.RevocationFacts revocation) {
        try {
            return SyntheticGrantTemporalAssessment.assess(time, revocation);
        } catch (IllegalArgumentException | NullPointerException malformed) {
            throw invalid();
        }
    }
    private static void add(EnumSet<Blocker> blockers, SyntheticGrantTemporalAssessment.Fact fact,
                            Blocker active, Blocker unknown) {
        if (fact == SyntheticGrantTemporalAssessment.Fact.ACTIVE) blockers.add(active);
        else if (fact == SyntheticGrantTemporalAssessment.Fact.UNKNOWN) blockers.add(unknown);
    }
    private static <E extends Enum<E>> Set<E> immutable(Set<E> source, Class<E> type) {
        var copy = EnumSet.noneOf(type);
        copy.addAll(source);
        return Collections.unmodifiableSet(copy);
    }
    private static void text(String value) { if (value == null || value.isEmpty()) throw invalid(); }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_SYNTHETIC_GRANT_KEY_LIFECYCLE", null);
    }
}
