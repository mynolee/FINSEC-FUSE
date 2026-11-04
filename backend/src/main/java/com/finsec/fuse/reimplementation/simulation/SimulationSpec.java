package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Explicit synthetic inputs only. These records contain no production policy defaults. */
public final class SimulationSpec {
    private SimulationSpec() {}

    public record Source(UUID documentId, int documentVersion, String text,
                         String contentHash, boolean reviewedSafe) {
        public Source {
            Objects.requireNonNull(documentId); Objects.requireNonNull(text);
            CanonicalJson.write(text); // rejects unpaired UTF-16 surrogates before UTF-8 hashing
            if (documentVersion < 1 || text.getBytes(StandardCharsets.UTF_8).length > 16384
                    || !rawHash(text).equals(contentHash))
                throw new IllegalArgumentException("Invalid synthetic source");
        }
    }

    public record Application(String fixtureId, String businessReference, String customerId,
                              long amountKrw, UUID payoutAccountId, long monthlyIncomeKrw,
                              long maxLoanAmountKrw, boolean ownsActiveAccount, Source source) {
        public Application {
            synthetic(fixtureId); synthetic(customerId);
            new WorkflowStartBoundary.Request(businessReference, customerId, amountKrw, payoutAccountId);
            if (monthlyIncomeKrw < 0 || maxLoanAmountKrw < 0) throw new IllegalArgumentException("Invalid synthetic loan data");
            Objects.requireNonNull(source);
        }
        public WorkflowStartBoundary.Request request() {
            return new WorkflowStartBoundary.Request(businessReference, customerId, amountKrw, payoutAccountId);
        }
    }

    public enum Kind { ID_DOC, FACE_MATCH }
    public enum Outcome { PASS, FAIL }
    public enum KycStatus { VERIFIED, NOT_VERIFIED, NEEDS_REVIEW }
    public record Fact(UUID evidenceId, String customerId, Kind kind, Outcome result,
                       boolean active, Instant issuedAt, Instant expiresAt) {
        public Fact {
            Objects.requireNonNull(evidenceId); synthetic(customerId);
            Objects.requireNonNull(kind); Objects.requireNonNull(result);
            Objects.requireNonNull(issuedAt); Objects.requireNonNull(expiresAt);
            if (!issuedAt.isBefore(expiresAt)) throw new IllegalArgumentException("Invalid evidence interval");
        }
        public boolean usable(Instant now) {
            return active && !now.isBefore(issuedAt) && now.isBefore(expiresAt);
        }
    }

    public record RiskTerms(String policyVersion, int kycPoints, int loanPoints, int payPoints,
                            int baseLimit, int additionalApprovalLimit,
                            int maxAutomaticKycRuns, Duration approvalLifetime) {
        public RiskTerms {
            if (policyVersion == null || policyVersion.isBlank() || policyVersion.length() > 64
                    || kycPoints < 0 || loanPoints < 0 || payPoints < 1 || baseLimit < 0
                    || additionalApprovalLimit < 0 || maxAutomaticKycRuns < 1 || maxAutomaticKycRuns > 2
                    || approvalLifetime == null || approvalLifetime.isZero() || approvalLifetime.isNegative())
                throw new IllegalArgumentException("Explicit synthetic risk terms are required");
            Math.addExact(baseLimit, additionalApprovalLimit);
        }
    }

    public record Observation(UUID requestId, UUID workflowId, int generation, UUID runId,
                              String inputSnapshotHash, KycStatus status, List<UUID> evidenceIds) {
        public Observation {
            Objects.requireNonNull(requestId); Objects.requireNonNull(workflowId); Objects.requireNonNull(runId);
            Objects.requireNonNull(status); evidenceIds = List.copyOf(Objects.requireNonNull(evidenceIds));
            if (generation < 1 || !hash(inputSnapshotHash) || evidenceIds.size() > 10
                    || evidenceIds.stream().distinct().count() != evidenceIds.size())
                throw new IllegalArgumentException("Invalid synthetic observation");
        }
    }

    public static final class Catalog {
        private final Map<String, Application> applications;
        private final Map<String, Source> sources;
        private final Map<String, Fact> facts;

        public Catalog(List<Application> applications, List<Fact> facts) {
            var apps = new LinkedHashMap<String, Application>();
            var docs = new LinkedHashMap<String, Source>();
            for (Application value : List.copyOf(applications)) {
                if (apps.putIfAbsent(value.businessReference(), value) != null)
                    throw new IllegalArgumentException("Duplicate synthetic application");
                String key = sourceKey(value.source().documentId(), value.source().documentVersion());
                Source previous = docs.putIfAbsent(key, value.source());
                if (previous != null && !previous.equals(value.source()))
                    throw new IllegalArgumentException("Conflicting synthetic source");
            }
            var evidence = new LinkedHashMap<String, Fact>();
            for (Fact value : List.copyOf(facts)) {
                if (evidence.putIfAbsent(value.evidenceId().toString(), value) != null)
                    throw new IllegalArgumentException("Duplicate synthetic evidence");
            }
            this.applications = Map.copyOf(apps); this.sources = Map.copyOf(docs); this.facts = Map.copyOf(evidence);
        }
        public Application application(WorkflowStartBoundary.Request request) {
            Application app = applications.get(request.businessReference());
            if (app == null || !app.request().equals(request)) throw SimulationFailure.invalid();
            return app;
        }
        public Source source(UUID id, int version) { return sources.get(sourceKey(id, version)); }
        public Fact fact(UUID id) { return facts.get(id.toString()); }
        public List<Fact> factsFor(String customer, Instant now) {
            return facts.values().stream().filter(f -> f.customerId().equals(customer) && f.usable(now))
                    .sorted(java.util.Comparator.comparing(f -> f.evidenceId().toString())).toList();
        }
        public List<Application> applications() {
            return applications.values().stream().sorted(java.util.Comparator.comparing(Application::fixtureId)).toList();
        }
    }

    public static String sourceKey(UUID id, int version) { return id + ":" + version; }
    public static void synthetic(String value) {
        if (value == null || !value.startsWith("synthetic-") || value.length() > 64)
            throw new IllegalArgumentException("Only explicit synthetic identities are accepted");
    }
    public static boolean hash(String value) { return value != null && value.matches("[0-9a-f]{64}"); }
    public static String rawHash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    public static Map<String, Object> object(Object... entries) {
        if (entries.length % 2 != 0) throw new IllegalArgumentException("Invalid object entries");
        var value = new LinkedHashMap<String, Object>();
        for (int i = 0; i < entries.length; i += 2) {
            if (!(entries[i] instanceof String key) || value.containsKey(key)) throw new IllegalArgumentException("Invalid object keys");
            value.put(key, entries[i + 1]);
        }
        return CanonicalJson.immutableObject(value);
    }
}
