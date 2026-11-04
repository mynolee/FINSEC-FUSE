package com.finsec.fuse.reimplementation.auth;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.RecordComponent;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.*;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.ChainPosition;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.Fact;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.RevocationFacts;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.TemporalFacts;
import static org.junit.jupiter.api.Assertions.*;

/** Supplied historical-read consistency only; no receipt or permission is acquired. */
final class SyntheticGrantReplayAssessmentTest {
    private static UUID id(long n) { return new UUID(9, n); }
    private static CommandIdentity identity() {
        return new CommandIdentity("synthetic-actor", id(1), "synthetic-operation", "synthetic-version",
                "opaque-admitted-digest", id(2), id(3), id(4), id(5), 1, "synthetic-customer");
    }
    private static RevocationFacts clearRevocation() {
        return new RevocationFacts(Fact.CLEAR, Fact.CLEAR, Fact.CLEAR, Fact.CLEAR, Fact.CLEAR,
                Fact.CLEAR, Fact.CLEAR, Fact.CLEAR, Fact.CLEAR);
    }
    private static CurrentReadFacts clearCurrent() {
        return new CurrentReadFacts(Fact.CLEAR, Fact.CLEAR, Fact.CLEAR, Fact.CLEAR, Fact.CLEAR, Fact.CLEAR, Fact.CLEAR);
    }
    private static TemporalFacts childTime(long now) { return new TemporalFacts(now, 100, 200, ChainPosition.CHILD, 1000L); }
    private static SuppliedReceipt committed(CommandIdentity identity) {
        return new SuppliedReceipt(ReceiptState.COMMITTED, identity, GrantLifecycle.CONSUMED);
    }
    private static SyntheticGrantReplayAssessment.Assessment exact(long now) {
        return assessHistoricalRead(identity(), committed(identity()), childTime(now), clearRevocation(), clearCurrent());
    }
    @SuppressWarnings("unchecked")
    private static <T extends Record> T changed(T original, String field, Object replacement) throws Exception {
        RecordComponent[] components = original.getClass().getRecordComponents();
        var types = new Class<?>[components.length]; var values = new Object[components.length]; boolean found = false;
        for (int i = 0; i < components.length; i++) {
            types[i] = components[i].getType(); values[i] = components[i].getAccessor().invoke(original);
            if (components[i].getName().equals(field)) { values[i] = replacement; found = true; }
        }
        assertTrue(found);
        try { return (T) original.getClass().getConstructor(types).newInstance(values); }
        catch (InvocationTargetException wrapped) {
            if (wrapped.getCause() instanceof RuntimeException rejected) throw rejected;
            throw wrapped;
        }
    }
    private static void noAuthority(SyntheticGrantReplayAssessment.Assessment result) {
        assertFalse(result.authorizationEstablished()); assertFalse(result.authoritativeReceiptEstablished());
        assertFalse(result.executionAuthorityGranted());
    }
    private static void rejected(Executable operation) {
        var failure = assertThrows(IllegalArgumentException.class, operation);
        assertEquals("INVALID_SYNTHETIC_GRANT_REPLAY", failure.getMessage()); assertNull(failure.getCause());
    }

    @Test void exactSuppliedCommittedIdentityBeforeExpiryIsConsistentButNotAuthoritative() {
        var result = exact(150); assertEquals(IdentityOutcome.EXACT_SUPPLIED_COMMITTED_BINDING, result.identityOutcome());
        assertTrue(result.suppliedHistoricalReadConditionsSatisfied()); assertTrue(result.originalTimeWithinWindow());
        assertFalse(result.ownExpiryExceptionApplied()); assertEquals(Set.of(), result.blockers());
        assertEquals(Set.of(), result.temporalBlockers()); noAuthority(result);
    }

    @Test void everyFullElevenFieldIdentityMismatchIncludingNewRequestConflicts() throws Exception {
        String[] fields = {"actorId", "globalRequestId", "operation", "canonicalizationVersion", "canonicalBodyDigest",
                "grantId", "actionId", "targetRunId", "workflowId", "generation", "customerId"};
        Object[] replacements = {"other-actor", id(99), "other-operation", "other-version", "other-opaque-digest",
                id(99), id(99), id(99), id(99), 2, "other-customer"};
        for (int i = 0; i < fields.length; i++) {
            var different = changed(identity(), fields[i], replacements[i]);
            var result = assessHistoricalRead(different, committed(identity()), childTime(200), clearRevocation(), clearCurrent());
            assertEquals(IdentityOutcome.CONFLICT, result.identityOutcome(), fields[i]);
            assertTrue(result.blockers().contains(Blocker.IDENTITY_CONFLICT));
            assertTrue(result.temporalBlockers().contains(SyntheticGrantTemporalAssessment.Blocker.EXPIRED));
            assertFalse(result.ownExpiryExceptionApplied()); assertFalse(result.suppliedHistoricalReadConditionsSatisfied()); noAuthority(result);
        }
    }

    @Test void pendingAbsentAndUnconfirmedAreNeverCommittedReplayEvenWithMatchingHints() {
        for (var receipt : List.of(new SuppliedReceipt(ReceiptState.PENDING, identity(), GrantLifecycle.CONSUMED),
                new SuppliedReceipt(ReceiptState.UNCONFIRMED, identity(), GrantLifecycle.CONSUMED),
                new SuppliedReceipt(ReceiptState.ABSENT, null, null),
                new SuppliedReceipt(ReceiptState.PENDING, null, null),
                new SuppliedReceipt(ReceiptState.UNCONFIRMED, null, GrantLifecycle.CONSUMED))) {
            var result = assessHistoricalRead(identity(), receipt, childTime(200), clearRevocation(), clearCurrent());
            assertEquals(IdentityOutcome.UNCONFIRMED, result.identityOutcome());
            assertFalse(result.suppliedHistoricalReadConditionsSatisfied()); assertFalse(result.ownExpiryExceptionApplied());
            assertTrue(result.temporalBlockers().contains(SyntheticGrantTemporalAssessment.Blocker.EXPIRED)); noAuthority(result);
        }
    }

    @Test void nonConsumedLifecycleDoesNotUseOwnExpiryException() {
        for (var lifecycle : GrantLifecycle.values()) if (lifecycle != GrantLifecycle.CONSUMED) {
            var result = assessHistoricalRead(identity(), new SuppliedReceipt(ReceiptState.COMMITTED, identity(), lifecycle),
                    childTime(300), clearRevocation(), clearCurrent());
            assertEquals(IdentityOutcome.UNCONFIRMED, result.identityOutcome());
            assertTrue(result.blockers().contains(Blocker.GRANT_NOT_CONSUMED));
            assertFalse(result.ownExpiryExceptionApplied()); assertFalse(result.suppliedHistoricalReadConditionsSatisfied()); noAuthority(result);
        }
    }

    @Test void equalityAndAfterOwnExpiryOmitOnlyHistoricalExpiredWithoutWeakeningNewWork() {
        for (long now : new long[] {200, 300}) {
            var result = exact(now); assertTrue(result.ownExpiryExceptionApplied());
            assertFalse(result.originalTimeWithinWindow()); assertTrue(result.suppliedHistoricalReadConditionsSatisfied());
            assertFalse(result.temporalBlockers().contains(SyntheticGrantTemporalAssessment.Blocker.EXPIRED)); noAuthority(result);
            var newWork = SyntheticGrantTemporalAssessment.assess(childTime(now), clearRevocation());
            assertTrue(newWork.blockers().contains(SyntheticGrantTemporalAssessment.Blocker.EXPIRED));
            assertFalse(newWork.timeWithinWindow()); assertFalse(newWork.authorizationEstablished());
        }
    }

    @Test void notYetValidParentExpiredAndParentCapRemainIndependentBlockers() {
        var future = assessHistoricalRead(identity(), committed(identity()), childTime(99), clearRevocation(), clearCurrent());
        assertTrue(future.temporalBlockers().contains(SyntheticGrantTemporalAssessment.Blocker.NOT_YET_VALID));
        assertFalse(future.suppliedHistoricalReadConditionsSatisfied()); noAuthority(future);
        for (var time : List.of(new TemporalFacts(300, 100, 200, ChainPosition.CHILD, 150L),
                new TemporalFacts(300, 100, 400, ChainPosition.CHILD, 250L))) {
            var result = assessHistoricalRead(identity(), committed(identity()), time, clearRevocation(), clearCurrent());
            assertTrue(result.temporalBlockers().contains(SyntheticGrantTemporalAssessment.Blocker.PARENT_EXPIRED));
            assertTrue(result.temporalBlockers().contains(SyntheticGrantTemporalAssessment.Blocker.PARENT_EXPIRY_EXCEEDED));
            assertFalse(result.suppliedHistoricalReadConditionsSatisfied()); noAuthority(result);
        }
    }

    @Test void allNineRevocationAndQuarantineFactsBlockForActiveAndUnknown() throws Exception {
        String[] fields = {"grantRevoked", "rootAuthorizationRevoked", "keyRevoked", "parentRevoked", "workflowQuarantined",
                "sourceVersionQuarantined", "agentVersionQuarantined", "ancestorRunQuarantined", "ancestorResultQuarantined"};
        String[] names = {"GRANT_REVOKED", "ROOT_AUTHORIZATION_REVOKED", "KEY_REVOKED", "PARENT_REVOKED", "WORKFLOW_QUARANTINED",
                "SOURCE_VERSION_QUARANTINED", "AGENT_VERSION_QUARANTINED", "ANCESTOR_RUN_QUARANTINED", "ANCESTOR_RESULT_QUARANTINED"};
        for (int i = 0; i < fields.length; i++) for (Fact fact : List.of(Fact.ACTIVE, Fact.UNKNOWN)) {
            var revocation = changed(clearRevocation(), fields[i], fact);
            var result = assessHistoricalRead(identity(), committed(identity()), childTime(300), revocation, clearCurrent());
            var blocker = SyntheticGrantTemporalAssessment.Blocker.valueOf(names[i] + "_" + fact.name());
            assertEquals(Set.of(blocker), result.temporalBlockers(), fields[i]);
            assertTrue(result.ownExpiryExceptionApplied()); assertFalse(result.suppliedHistoricalReadConditionsSatisfied()); noAuthority(result);
        }
    }

    @Test void allSevenCurrentReadFactsBlockForActiveAndUnknownDespiteExactHistory() throws Exception {
        String[] fields = {"credentialInvalid", "actorMismatch", "ownerDenied", "operationDenied", "disclosureDenied",
                "ancestorExpiryBlocked", "resultInvalidationDisclosureBlocked"};
        String[] names = {"CREDENTIAL_INVALID", "ACTOR_MISMATCH", "OWNER_DENIED", "OPERATION_DENIED", "DISCLOSURE_DENIED",
                "ANCESTOR_EXPIRY_BLOCKED", "RESULT_INVALIDATION_DISCLOSURE_BLOCKED"};
        for (int i = 0; i < fields.length; i++) for (Fact fact : List.of(Fact.ACTIVE, Fact.UNKNOWN)) {
            var result = assessHistoricalRead(identity(), committed(identity()), childTime(300), clearRevocation(),
                    changed(clearCurrent(), fields[i], fact));
            assertEquals(IdentityOutcome.EXACT_SUPPLIED_COMMITTED_BINDING, result.identityOutcome());
            assertEquals(Set.of(Blocker.valueOf(names[i] + "_" + fact.name())), result.blockers(), fields[i]);
            assertTrue(result.ownExpiryExceptionApplied()); assertFalse(result.suppliedHistoricalReadConditionsSatisfied()); noAuthority(result);
        }
    }

    @Test void returnedBlockerSetsAreImmutableAndIndependentAcrossAssessments() throws Exception {
        var denied = assessHistoricalRead(identity(), committed(identity()), childTime(300),
                changed(clearRevocation(), "keyRevoked", Fact.ACTIVE), changed(clearCurrent(), "ownerDenied", Fact.ACTIVE));
        assertThrows(UnsupportedOperationException.class, () -> denied.blockers().clear());
        assertThrows(UnsupportedOperationException.class, () -> denied.temporalBlockers().clear());
        assertTrue(exact(300).suppliedHistoricalReadConditionsSatisfied());
        assertEquals(Set.of(Blocker.OWNER_DENIED_ACTIVE), denied.blockers());
        assertEquals(Set.of(SyntheticGrantTemporalAssessment.Blocker.KEY_REVOKED_ACTIVE), denied.temporalBlockers());
    }

    @Test void opaqueDigestAndEqualOrDifferentSemanticUuidValuesDoNotCreateAuthority() throws Exception {
        assertEquals("opaque-admitted-digest", identity().canonicalBodyDigest());
        assertNotEquals(identity().globalRequestId(), identity().actionId());
        var equal = changed(identity(), "globalRequestId", identity().actionId());
        var result = assessHistoricalRead(equal, committed(equal), childTime(300), clearRevocation(), clearCurrent());
        assertTrue(result.suppliedHistoricalReadConditionsSatisfied()); noAuthority(result);
        assertTrue(exact(300).suppliedHistoricalReadConditionsSatisfied());
    }

    @Test void strictIdentityAndReceiptShapesUseOneFixedCauseFreeError() {
        for (String field : List.of("actorId", "globalRequestId", "operation", "canonicalizationVersion", "canonicalBodyDigest",
                "grantId", "actionId", "targetRunId", "workflowId", "customerId")) rejected(() -> changed(identity(), field, null));
        rejected(() -> changed(identity(), "generation", 0)); rejected(() -> changed(identity(), "generation", -1));
        rejected(() -> changed(identity(), "actorId", " "));
        rejected(() -> new SuppliedReceipt(null, null, null));
        rejected(() -> new SuppliedReceipt(ReceiptState.ABSENT, identity(), null));
        rejected(() -> new SuppliedReceipt(ReceiptState.ABSENT, null, GrantLifecycle.CONSUMED));
        rejected(() -> new SuppliedReceipt(ReceiptState.COMMITTED, null, GrantLifecycle.CONSUMED));
        rejected(() -> new SuppliedReceipt(ReceiptState.COMMITTED, identity(), null));
    }

    @Test void nullCurrentFactsAndMalformedTemporalFactsCannotBeHiddenByReceiptFailure() {
        for (String field : List.of("credentialInvalid", "actorMismatch", "ownerDenied", "operationDenied", "disclosureDenied",
                "ancestorExpiryBlocked", "resultInvalidationDisclosureBlocked")) rejected(() -> changed(clearCurrent(), field, null));
        var absent = new SuppliedReceipt(ReceiptState.ABSENT, null, null);
        rejected(() -> assessHistoricalRead(null, absent, childTime(300), clearRevocation(), clearCurrent()));
        rejected(() -> assessHistoricalRead(identity(), null, childTime(300), clearRevocation(), clearCurrent()));
        rejected(() -> assessHistoricalRead(identity(), absent, null, clearRevocation(), clearCurrent()));
        rejected(() -> assessHistoricalRead(identity(), absent, childTime(300), null, clearCurrent()));
        rejected(() -> assessHistoricalRead(identity(), absent, childTime(300), clearRevocation(), null));
        rejected(() -> assessHistoricalRead(identity(), absent, new TemporalFacts(300, 100, 200, ChainPosition.CHILD, null),
                clearRevocation(), clearCurrent()));
        rejected(() -> assessHistoricalRead(identity(), absent, childTime(300),
                changed(clearRevocation(), "keyRevoked", null), clearCurrent()));
    }

    @Test void diagnosticsDoNotRevealIdentityDigestCustomerOrPretendStoredReceiptBody() {
        var identity = identity(); var receipt = committed(identity); var current = clearCurrent(); var result = exact(300);
        for (Object diagnostic : List.of(identity, receipt, current, result)) {
            assertFalse(diagnostic.toString().contains("synthetic-actor"));
            assertFalse(diagnostic.toString().contains("opaque-admitted-digest"));
            assertFalse(diagnostic.toString().contains("synthetic-customer"));
        }
        noAuthority(result);
    }
}
