package com.finsec.fuse.reimplementation.auth;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Pure consistency of explicit supplied bindings; never an authorization decision. */
public final class SyntheticGrantIssuerBindings {
    public enum Stage { KYC_EVALUATOR, LOAN_RECOMMENDER, MOCK_PAYMENT_EXECUTOR }
    public enum Outcome { SUPPLIED_EXACT_MATCH, NO_SUPPLIED_MATCH }

    public record Limits(int maximumBindings, int maximumTextCharacters) {
        public Limits {
            if (maximumBindings <= 0 || maximumTextCharacters <= 0) throw invalid();
        }
    }

    public record KeyReference(String keyId, String algorithmId, String ownerReference) {
        public KeyReference {
            text(keyId); text(algorithmId); text(ownerReference);
        }
        @Override public String toString() { return "KeyReference[REDACTED]"; }
    }

    public record Binding(String subjectId, UUID actorId, String principalId, String issuerId,
                          Stage stage, GrantStorageShape.AllowedAction action, String customerId,
                          UUID rootAuthorizationId, UUID workflowId, String intent,
                          KeyReference keyReference) {
        public Binding {
            text(subjectId); text(principalId); text(issuerId); text(customerId); text(intent);
            if (actorId == null || stage == null || action == null || rootAuthorizationId == null
                    || workflowId == null || keyReference == null || expected(stage) != action) throw invalid();
        }
        @Override public String toString() { return "Binding[REDACTED]"; }
    }

    public static final class Assessment {
        private final Outcome outcome;
        private Assessment(Outcome outcome) { this.outcome = outcome; }
        public Outcome outcome() { return outcome; }
        public boolean suppliedConsistencyMatched() { return outcome == Outcome.SUPPLIED_EXACT_MATCH; }
        public boolean actualAuthorizationEstablished() { return false; }
        public boolean actualRoleAssignmentEstablished() { return false; }
        public boolean actualKeyOwnershipEstablished() { return false; }
        public boolean currentGatesEstablished() { return false; }
        public boolean executionAuthorityGranted() { return false; }
        @Override public String toString() { return "Assessment[" + outcome + "]"; }
    }

    public static final class Prepared {
        private final String profileVersion;
        private final Limits limits;
        private final List<Binding> bindings;
        private Prepared(String version, Limits limits, List<Binding> bindings) {
            this.profileVersion = version;
            this.limits = limits;
            this.bindings = List.copyOf(bindings);
        }
        public String profileVersion() { return profileVersion; }
        public List<Binding> bindings() { return bindings; }
        public Assessment assess(Binding supplied) {
            if (supplied == null) throw invalid();
            bounded(supplied, limits.maximumTextCharacters());
            return new Assessment(bindings.contains(supplied) ? Outcome.SUPPLIED_EXACT_MATCH : Outcome.NO_SUPPLIED_MATCH);
        }
        public boolean bootstrapProvenanceEstablished() { return false; }
        @Override public String toString() { return "Prepared[REDACTED]"; }
    }

    private record Route(String subject, UUID actor, String principal, String issuer, Stage stage,
                         GrantStorageShape.AllowedAction action, String customer, UUID root,
                         UUID workflow, String intent, String keyId) {}

    private SyntheticGrantIssuerBindings() {}

    public static Prepared prepare(String profileVersion, List<Binding> supplied, Limits limits) {
        text(profileVersion);
        if (limits == null || supplied == null || supplied.isEmpty()
                || supplied.size() > limits.maximumBindings()
                || profileVersion.length() > limits.maximumTextCharacters()) throw invalid();
        List<Binding> copy = new ArrayList<>();
        Set<Route> routes = new HashSet<>();
        Map<String, KeyReference> keys = new HashMap<>();
        for (Binding binding : supplied) {
            if (binding == null) throw invalid();
            bounded(binding, limits.maximumTextCharacters());
            KeyReference prior = keys.putIfAbsent(binding.keyReference().keyId(), binding.keyReference());
            if (prior != null && !prior.equals(binding.keyReference())) throw invalid();
            Route route = new Route(binding.subjectId(), binding.actorId(), binding.principalId(),
                    binding.issuerId(), binding.stage(), binding.action(), binding.customerId(),
                    binding.rootAuthorizationId(), binding.workflowId(), binding.intent(), binding.keyReference().keyId());
            if (!routes.add(route)) throw invalid();
            copy.add(binding);
        }
        return new Prepared(profileVersion, limits, copy);
    }

    private static void bounded(Binding b, int maximum) {
        String[] fields = { b.subjectId(), b.principalId(), b.issuerId(), b.customerId(), b.intent(),
                b.keyReference().keyId(), b.keyReference().algorithmId(), b.keyReference().ownerReference() };
        for (String field : fields) if (field.length() > maximum) throw invalid();
    }
    private static GrantStorageShape.AllowedAction expected(Stage stage) {
        return switch (stage) {
            case KYC_EVALUATOR -> GrantStorageShape.AllowedAction.EVALUATE_KYC;
            case LOAN_RECOMMENDER -> GrantStorageShape.AllowedAction.CREATE_LOAN_RECOMMENDATION;
            case MOCK_PAYMENT_EXECUTOR -> GrantStorageShape.AllowedAction.EXECUTE_MOCK_PAYMENT;
        };
    }
    private static void text(String value) {
        if (value == null || value.isBlank()) throw invalid();
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_SYNTHETIC_GRANT_ISSUER_BINDINGS");
    }
}
