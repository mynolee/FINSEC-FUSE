package com.finsec.fuse.reimplementation.auth;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;

/**
 * Historical-read consistency of supplied snapshots only. No receipt, identity,
 * current permission or clock is acquired. The existing new-work temporal API
 * remains unchanged; these diagnostics authorize neither disclosure nor work.
 */
public final class SyntheticGrantReplayAssessment {
    private SyntheticGrantReplayAssessment() { }

    public enum ReceiptState { COMMITTED, PENDING, ABSENT, UNCONFIRMED }
    public enum GrantLifecycle { ISSUED, CONSUMED, REVOKED, EXPIRED, UNKNOWN }
    public enum IdentityOutcome { EXACT_SUPPLIED_COMMITTED_BINDING, CONFLICT, UNCONFIRMED }
    public enum Blocker {
        RECEIPT_ABSENT, RECEIPT_PENDING, RECEIPT_UNCONFIRMED,
        IDENTITY_UNCONFIRMED, IDENTITY_CONFLICT, GRANT_NOT_CONSUMED,
        CREDENTIAL_INVALID_ACTIVE, CREDENTIAL_INVALID_UNKNOWN,
        ACTOR_MISMATCH_ACTIVE, ACTOR_MISMATCH_UNKNOWN,
        OWNER_DENIED_ACTIVE, OWNER_DENIED_UNKNOWN,
        OPERATION_DENIED_ACTIVE, OPERATION_DENIED_UNKNOWN,
        DISCLOSURE_DENIED_ACTIVE, DISCLOSURE_DENIED_UNKNOWN,
        ANCESTOR_EXPIRY_BLOCKED_ACTIVE, ANCESTOR_EXPIRY_BLOCKED_UNKNOWN,
        RESULT_INVALIDATION_DISCLOSURE_BLOCKED_ACTIVE,
        RESULT_INVALIDATION_DISCLOSURE_BLOCKED_UNKNOWN
    }

    /** Opaque admitted digest/version values; no algorithm or normalization is inferred. */
    public record CommandIdentity(String actorId, UUID globalRequestId, String operation,
                                  String canonicalizationVersion, String canonicalBodyDigest,
                                  UUID grantId, UUID actionId, UUID targetRunId, UUID workflowId,
                                  int generation, String customerId) {
        public CommandIdentity {
            text(actorId); text(operation); text(canonicalizationVersion);
            text(canonicalBodyDigest); text(customerId);
            if (globalRequestId == null || grantId == null || actionId == null
                    || targetRunId == null || workflowId == null || generation < 1) throw invalid();
        }
        @Override public String toString() { return "ReplayIdentity[SUPPLIED_REDACTED]"; }
    }

    /**
     * ABSENT has neither identity nor lifecycle. PENDING/UNCONFIRMED may carry
     * either optional snapshot independently; missing facts are not defaulted.
     * COMMITTED requires both, but a non-CONSUMED lifecycle remains unconfirmed.
     * Every state is supplied data, never trusted commit or absence evidence.
     */
    public record SuppliedReceipt(ReceiptState state, CommandIdentity identity, GrantLifecycle lifecycle) {
        public SuppliedReceipt {
            if (state == null
                    || (state == ReceiptState.ABSENT && (identity != null || lifecycle != null))
                    || (state == ReceiptState.COMMITTED && (identity == null || lifecycle == null))) throw invalid();
        }
        @Override public String toString() { return "ReceiptSnapshot[SUPPLIED_REDACTED]"; }
    }

    /** CLEAR means no supplied blocker; ACTIVE/UNKNOWN remain blocking, not acquired facts. */
    public record CurrentReadFacts(SyntheticGrantTemporalAssessment.Fact credentialInvalid,
                                   SyntheticGrantTemporalAssessment.Fact actorMismatch,
                                   SyntheticGrantTemporalAssessment.Fact ownerDenied,
                                   SyntheticGrantTemporalAssessment.Fact operationDenied,
                                   SyntheticGrantTemporalAssessment.Fact disclosureDenied,
                                   SyntheticGrantTemporalAssessment.Fact ancestorExpiryBlocked,
                                   SyntheticGrantTemporalAssessment.Fact resultInvalidationDisclosureBlocked) {
        public CurrentReadFacts {
            if (credentialInvalid == null || actorMismatch == null || ownerDenied == null
                    || operationDenied == null || disclosureDenied == null || ancestorExpiryBlocked == null
                    || resultInvalidationDisclosureBlocked == null) throw invalid();
        }
        @Override public String toString() { return "CurrentReadFacts[SUPPLIED_REDACTED]"; }
    }

    public static final class Assessment {
        private final IdentityOutcome identityOutcome;
        private final Set<Blocker> blockers;
        private final Set<SyntheticGrantTemporalAssessment.Blocker> temporalBlockers;
        private final boolean ownExpiryExceptionApplied;
        private final boolean originalTimeWithinWindow;

        private Assessment(IdentityOutcome outcome, EnumSet<Blocker> blockers,
                           EnumSet<SyntheticGrantTemporalAssessment.Blocker> temporal,
                           boolean omitted, boolean originalWithin) {
            this.identityOutcome = outcome;
            this.blockers = Collections.unmodifiableSet(blockers.clone());
            this.temporalBlockers = Collections.unmodifiableSet(temporal.clone());
            this.ownExpiryExceptionApplied = omitted;
            this.originalTimeWithinWindow = originalWithin;
        }
        public IdentityOutcome identityOutcome() { return identityOutcome; }
        /** Supplied receipt/identity/current-read blockers; temporal blockers are separate. */
        public Set<Blocker> blockers() { return blockers; }
        public Set<SyntheticGrantTemporalAssessment.Blocker> temporalBlockers() { return temporalBlockers; }
        /** Own EXPIRED was omitted; all other blockers still apply, including current access. */
        public boolean ownExpiryExceptionApplied() { return ownExpiryExceptionApplied; }
        public boolean originalTimeWithinWindow() { return originalTimeWithinWindow; }
        public boolean suppliedHistoricalReadConditionsSatisfied() {
            return identityOutcome == IdentityOutcome.EXACT_SUPPLIED_COMMITTED_BINDING
                    && blockers.isEmpty() && temporalBlockers.isEmpty();
        }
        public boolean authorizationEstablished() { return false; }
        public boolean authoritativeReceiptEstablished() { return false; }
        public boolean executionAuthorityGranted() { return false; }
        @Override public String toString() { return "ReplayAssessment[SUPPLIED_NON_AUTHORIZING]"; }
    }

    /**
     * Time/revocation snapshots are supplied as pertaining to this identity; that
     * relationship and all actual trust facts must be acquired outside this API.
     * The result never returns a receipt body or performs a new consumption.
     */
    public static Assessment assessHistoricalRead(CommandIdentity requested, SuppliedReceipt receipt,
            SyntheticGrantTemporalAssessment.TemporalFacts time,
            SyntheticGrantTemporalAssessment.RevocationFacts revocation,
            CurrentReadFacts current) {
        if (requested == null || receipt == null || time == null || revocation == null || current == null) throw invalid();
        final SyntheticGrantTemporalAssessment.Assessment original;
        try {
            original = SyntheticGrantTemporalAssessment.assess(time, revocation);
        } catch (IllegalArgumentException | NullPointerException malformed) {
            throw invalid();
        }
        EnumSet<Blocker> blockers = EnumSet.noneOf(Blocker.class);
        if (receipt.state() == ReceiptState.ABSENT) blockers.add(Blocker.RECEIPT_ABSENT);
        else if (receipt.state() == ReceiptState.PENDING) blockers.add(Blocker.RECEIPT_PENDING);
        else if (receipt.state() == ReceiptState.UNCONFIRMED) blockers.add(Blocker.RECEIPT_UNCONFIRMED);
        boolean exact = receipt.identity() != null && requested.equals(receipt.identity());
        if (receipt.identity() == null) blockers.add(Blocker.IDENTITY_UNCONFIRMED);
        else if (!exact) blockers.add(Blocker.IDENTITY_CONFLICT);
        if (receipt.lifecycle() != GrantLifecycle.CONSUMED) blockers.add(Blocker.GRANT_NOT_CONSUMED);
        IdentityOutcome outcome = !exact && receipt.identity() != null ? IdentityOutcome.CONFLICT
                : receipt.state() == ReceiptState.COMMITTED && exact
                    && receipt.lifecycle() == GrantLifecycle.CONSUMED
                    ? IdentityOutcome.EXACT_SUPPLIED_COMMITTED_BINDING : IdentityOutcome.UNCONFIRMED;
        add(blockers, current.credentialInvalid(), Blocker.CREDENTIAL_INVALID_ACTIVE, Blocker.CREDENTIAL_INVALID_UNKNOWN);
        add(blockers, current.actorMismatch(), Blocker.ACTOR_MISMATCH_ACTIVE, Blocker.ACTOR_MISMATCH_UNKNOWN);
        add(blockers, current.ownerDenied(), Blocker.OWNER_DENIED_ACTIVE, Blocker.OWNER_DENIED_UNKNOWN);
        add(blockers, current.operationDenied(), Blocker.OPERATION_DENIED_ACTIVE, Blocker.OPERATION_DENIED_UNKNOWN);
        add(blockers, current.disclosureDenied(), Blocker.DISCLOSURE_DENIED_ACTIVE, Blocker.DISCLOSURE_DENIED_UNKNOWN);
        add(blockers, current.ancestorExpiryBlocked(), Blocker.ANCESTOR_EXPIRY_BLOCKED_ACTIVE, Blocker.ANCESTOR_EXPIRY_BLOCKED_UNKNOWN);
        add(blockers, current.resultInvalidationDisclosureBlocked(),
                Blocker.RESULT_INVALIDATION_DISCLOSURE_BLOCKED_ACTIVE,
                Blocker.RESULT_INVALIDATION_DISCLOSURE_BLOCKED_UNKNOWN);
        var temporal = EnumSet.noneOf(SyntheticGrantTemporalAssessment.Blocker.class);
        temporal.addAll(original.blockers());
        boolean omitted = outcome == IdentityOutcome.EXACT_SUPPLIED_COMMITTED_BINDING
                && temporal.remove(SyntheticGrantTemporalAssessment.Blocker.EXPIRED);
        return new Assessment(outcome, blockers, temporal, omitted, original.timeWithinWindow());
    }

    private static void add(EnumSet<Blocker> values, SyntheticGrantTemporalAssessment.Fact fact,
                            Blocker active, Blocker unknown) {
        if (fact == SyntheticGrantTemporalAssessment.Fact.ACTIVE) values.add(active);
        else if (fact == SyntheticGrantTemporalAssessment.Fact.UNKNOWN) values.add(unknown);
    }
    private static void text(String value) { if (value == null || value.isBlank()) throw invalid(); }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_SYNTHETIC_GRANT_REPLAY", null);
    }
}
