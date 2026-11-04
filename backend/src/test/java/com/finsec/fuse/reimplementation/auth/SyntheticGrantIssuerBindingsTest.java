package com.finsec.fuse.reimplementation.auth;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantIssuerBindings.*;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit synthetic descriptor consistency, never real assignment or issuer authority. */
final class SyntheticGrantIssuerBindingsTest {
    private static UUID id(long n) { return new UUID(10, n); }
    private static Limits limits() { return new Limits(8, 128); }
    private static GrantStorageShape.AllowedAction action(Stage stage) {
        return switch (stage) {
            case KYC_EVALUATOR -> GrantStorageShape.AllowedAction.EVALUATE_KYC;
            case LOAN_RECOMMENDER -> GrantStorageShape.AllowedAction.CREATE_LOAN_RECOMMENDATION;
            case MOCK_PAYMENT_EXECUTOR -> GrantStorageShape.AllowedAction.EXECUTE_MOCK_PAYMENT;
        };
    }
    private static Binding binding(Stage stage) {
        return new Binding("synthetic-subject", id(1), "synthetic-principal", "synthetic-independent-issuer",
                stage, action(stage), "synthetic-customer", id(2), id(3), "synthetic-intent",
                new KeyReference("synthetic-key-ref", "synthetic-explicit-algorithm", "synthetic-key-owner-ref"));
    }
    @SuppressWarnings("unchecked")
    private static <T extends Record> T changed(T value, Map<String, Object> changes) throws Exception {
        RecordComponent[] fields = value.getClass().getRecordComponents();
        var types = new Class<?>[fields.length]; var values = new Object[fields.length]; int matched = 0;
        for (int i = 0; i < fields.length; i++) {
            types[i] = fields[i].getType(); values[i] = fields[i].getAccessor().invoke(value);
            if (changes.containsKey(fields[i].getName())) { values[i] = changes.get(fields[i].getName()); matched++; }
        }
        assertEquals(changes.size(), matched);
        try { return (T) value.getClass().getConstructor(types).newInstance(values); }
        catch (InvocationTargetException wrapped) {
            if (wrapped.getCause() instanceof RuntimeException rejected) throw rejected;
            throw wrapped;
        }
    }
    private static <T extends Record> T changed(T value, String field, Object replacement) throws Exception {
        return changed(value, Collections.singletonMap(field, replacement));
    }
    private static void rejected(Executable operation) {
        var failure = assertThrows(IllegalArgumentException.class, operation);
        assertEquals("INVALID_SYNTHETIC_GRANT_ISSUER_BINDINGS", failure.getMessage()); assertNull(failure.getCause());
    }
    private static void suppliedOnly(Assessment result, boolean matches) {
        assertEquals(matches ? Outcome.SUPPLIED_EXACT_MATCH : Outcome.NO_SUPPLIED_MATCH, result.outcome());
        assertEquals(matches, result.suppliedConsistencyMatched());
        assertFalse(result.actualAuthorizationEstablished()); assertFalse(result.actualRoleAssignmentEstablished());
        assertFalse(result.actualKeyOwnershipEstablished()); assertFalse(result.currentGatesEstablished());
        assertFalse(result.executionAuthorityGranted());
    }

    @Test void completeExplicitThreeStageMatrixMatchesOnlySuppliedDescriptors() {
        var rows = List.of(binding(Stage.KYC_EVALUATOR), binding(Stage.LOAN_RECOMMENDER), binding(Stage.MOCK_PAYMENT_EXECUTOR));
        var prepared = prepare("synthetic-profile-v1", rows, limits());
        assertEquals(rows, prepared.bindings()); assertEquals("synthetic-profile-v1", prepared.profileVersion());
        assertFalse(prepared.bootstrapProvenanceEstablished());
        for (var row : rows) suppliedOnly(prepared.assess(row), true);
    }

    @Test void everyIdentityCustomerIntentAndKeyComponentUsesExactEquality() throws Exception {
        var row = binding(Stage.KYC_EVALUATOR); var prepared = prepare("synthetic-v1", List.of(row), limits());
        String[] fields = {"subjectId", "actorId", "principalId", "issuerId", "customerId", "rootAuthorizationId", "workflowId", "intent"};
        Object[] replacements = {"other-subject", id(99), "other-principal", "other-issuer", "other-customer", id(99), id(99), "other-intent"};
        for (int i = 0; i < fields.length; i++) suppliedOnly(prepared.assess(changed(row, fields[i], replacements[i])), false);
        for (String field : List.of("keyId", "algorithmId", "ownerReference")) {
            var otherKey = changed(row.keyReference(), field, "synthetic-other");
            suppliedOnly(prepared.assess(changed(row, "keyReference", otherKey)), false);
        }
    }

    @Test void stageAndActionMustBeOneOfTheClosedCorrespondingPairs() throws Exception {
        for (Stage stage : Stage.values()) for (var allowed : GrantStorageShape.AllowedAction.values()) {
            var row = binding(stage);
            if (allowed == action(stage)) assertNotNull(row);
            else rejected(() -> changed(row, "action", allowed));
        }
        var kyc = binding(Stage.KYC_EVALUATOR); var prepared = prepare("synthetic-v1", List.of(kyc), limits());
        var loan = changed(kyc, Map.of("stage", Stage.LOAN_RECOMMENDER, "action", action(Stage.LOAN_RECOMMENDER)));
        suppliedOnly(prepared.assess(loan), false);
    }

    @Test void duplicateRoutesAndConflictingKeyOwnerOrAlgorithmRefuseWholePreparation() throws Exception {
        var row = binding(Stage.KYC_EVALUATOR);
        rejected(() -> prepare("synthetic-v1", List.of(row, row), limits()));
        for (String field : List.of("algorithmId", "ownerReference")) {
            var conflict = changed(row, "keyReference", changed(row.keyReference(), field, "synthetic-conflict"));
            rejected(() -> prepare("synthetic-v1", List.of(row, conflict), limits()));
        }
        // Different stage does not repair a profile-global conflicting key reference.
        var loan = binding(Stage.LOAN_RECOMMENDER);
        var conflict = changed(loan, "keyReference", changed(loan.keyReference(), "ownerReference", "synthetic-other-owner"));
        rejected(() -> prepare("synthetic-v1", List.of(row, conflict), limits()));
    }

    @Test void explicitDistinctKeysAndSubjectAssociationsRemainSeparateExactRoutes() throws Exception {
        var first = binding(Stage.KYC_EVALUATOR);
        var secondKey = changed(first, "keyReference", changed(first.keyReference(), "keyId", "synthetic-second-key"));
        var secondSubject = changed(first, Map.of("subjectId", "synthetic-other-subject", "actorId", id(99),
                                                "principalId", "synthetic-other-principal"));
        var prepared = prepare("synthetic-v1", List.of(first, secondKey, secondSubject), limits());
        assertEquals(3, prepared.bindings().size());
        for (var row : List.of(first, secondKey, secondSubject)) suppliedOnly(prepared.assess(row), true);
        var absentCombination = changed(secondSubject, "keyReference", secondKey.keyReference());
        suppliedOnly(prepared.assess(absentCombination), false);
    }

    @Test void noWildcardCasefoldTrimOrIssuerPrincipalEqualityIsInvented() throws Exception {
        var wildcard = changed(binding(Stage.KYC_EVALUATOR), "customerId", "*");
        var prepared = prepare("synthetic-v1", List.of(wildcard), limits());
        suppliedOnly(prepared.assess(wildcard), true);
        suppliedOnly(prepared.assess(binding(Stage.KYC_EVALUATOR)), false);
        var row = binding(Stage.KYC_EVALUATOR); assertNotEquals(row.issuerId(), row.principalId());
        var exact = prepare("synthetic-v1", List.of(row), limits()); suppliedOnly(exact.assess(row), true);
        suppliedOnly(exact.assess(changed(row, "customerId", " synthetic-customer ")), false);
        suppliedOnly(exact.assess(changed(row, "customerId", "SYNTHETIC-CUSTOMER")), false);
    }

    @Test void emptyMissingAndUnknownDescriptorComponentsNeverDefaultToUnrestricted() {
        rejected(() -> prepare("synthetic-v1", List.of(), limits()));
        rejected(() -> prepare("synthetic-v1", null, limits()));
        rejected(() -> prepare("synthetic-v1", Arrays.asList((Binding) null), limits()));
        var row = binding(Stage.KYC_EVALUATOR);
        for (String field : List.of("subjectId", "actorId", "principalId", "issuerId", "stage", "action",
                "customerId", "rootAuthorizationId", "workflowId", "intent", "keyReference")) rejected(() -> changed(row, field, null));
        for (String field : List.of("keyId", "algorithmId", "ownerReference")) {
            rejected(() -> changed(row.keyReference(), field, null));
            rejected(() -> changed(row.keyReference(), field, " "));
        }
        var prepared = prepare("synthetic-v1", List.of(row), limits());
        rejected(() -> prepared.assess(null));
    }

    @Test void listMutationAndAttemptedReturnedMutationCannotAlterSealedSnapshot() throws Exception {
        var row = binding(Stage.KYC_EVALUATOR); var supplied = new ArrayList<Binding>(); supplied.add(row);
        var prepared = prepare("synthetic-v1", supplied, limits()); supplied.clear();
        supplied.add(binding(Stage.MOCK_PAYMENT_EXECUTOR));
        assertEquals(List.of(row), prepared.bindings()); suppliedOnly(prepared.assess(row), true);
        suppliedOnly(prepared.assess(binding(Stage.MOCK_PAYMENT_EXECUTOR)), false);
        assertThrows(UnsupportedOperationException.class, () -> prepared.bindings().clear());
        var later = changed(row, "customerId", "synthetic-later");
        suppliedOnly(prepared.assess(later), false); assertEquals(List.of(row), prepared.bindings());
    }

    @Test void callerLimitsArePositiveAndExactCountBoundaryIsInclusive() {
        rejected(() -> new Limits(0, 1)); rejected(() -> new Limits(1, 0));
        rejected(() -> new Limits(-1, 128)); rejected(() -> prepare("synthetic-v1", List.of(binding(Stage.KYC_EVALUATOR)), null));
        var rows = List.of(binding(Stage.KYC_EVALUATOR), binding(Stage.LOAN_RECOMMENDER));
        assertEquals(2, prepare("synthetic-v1", rows, new Limits(2, 128)).bindings().size());
        rejected(() -> prepare("synthetic-v1", rows, new Limits(1, 128)));
    }

    @Test void explicitTextCharacterCapAppliesToEveryFieldAndQueries() throws Exception {
        var row = binding(Stage.KYC_EVALUATOR);
        assertNotNull(prepare("x".repeat(128), List.of(row), limits()));
        rejected(() -> prepare("x".repeat(129), List.of(row), limits()));
        for (String field : List.of("subjectId", "principalId", "issuerId", "customerId", "intent")) {
            var longRow = changed(row, field, "x".repeat(129));
            rejected(() -> prepare("synthetic-v1", List.of(longRow), limits()));
            var prepared = prepare("synthetic-v1", List.of(row), limits()); rejected(() -> prepared.assess(longRow));
        }
        for (String field : List.of("keyId", "algorithmId", "ownerReference")) {
            var longRow = changed(row, "keyReference", changed(row.keyReference(), field, "x".repeat(129)));
            rejected(() -> prepare("synthetic-v1", List.of(longRow), limits()));
        }
        var utf16 = changed(row, "customerId", "가".repeat(128));
        assertNotNull(prepare("synthetic-v1", List.of(utf16), limits()));
    }

    @Test void opaqueKeyAlgorithmAndZeroUuidAreStructuralValuesNotActualKeyOwnership() throws Exception {
        var row = binding(Stage.KYC_EVALUATOR);
        var opaque = changed(row, Map.of("actorId", new UUID(0, 0), "rootAuthorizationId", new UUID(0, 0),
                                        "workflowId", new UUID(0, 0), "keyReference",
                                        new KeyReference("literal/not-a-key-file", "unassigned-algorithm-label", "unresolved-owner-label")));
        var prepared = prepare("synthetic-v1", List.of(opaque), limits());
        suppliedOnly(prepared.assess(opaque), true); assertFalse(prepared.bootstrapProvenanceEstablished());
    }

    @Test void exactMatchingNeverCachesCurrentGatesOrClaimsBootstrapTrust() {
        var row = binding(Stage.KYC_EVALUATOR); var prepared = prepare("synthetic-v1", List.of(row), limits());
        var first = prepared.assess(row); var again = prepared.assess(row);
        suppliedOnly(first, true); suppliedOnly(again, true);
        assertFalse(first.currentGatesEstablished()); assertFalse(again.currentGatesEstablished());
        assertFalse(prepared.bootstrapProvenanceEstablished());
    }

    @Test void fixedErrorsAndAllPublicDiagnosticsRedactSuppliedLabels() {
        var row = binding(Stage.KYC_EVALUATOR); var prepared = prepare("synthetic-private-profile", List.of(row), limits());
        for (Object value : List.of(row.keyReference(), row, prepared, prepared.assess(row))) {
            for (String marker : List.of("synthetic-subject", "synthetic-independent-issuer", "synthetic-key-owner-ref", "synthetic-private-profile"))
                assertFalse(value.toString().contains(marker));
        }
        rejected(() -> prepare(" ", List.of(row), limits()));
        rejected(() -> changed(row, "customerId", " "));
    }
}
