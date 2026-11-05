package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Aggregates explicit synthetic paired measurements without acquiring observations. */
public final class VirtualExperimentMetricsProjection {
    private VirtualExperimentMetricsProjection() {}
    public enum Kind { ATTACK, NORMAL }
    public enum Environment { BASELINE, FUSE }
    public enum Status { COMPLETED, ERROR }
    public enum Decision { ALLOW, WAIT_APPROVAL, DENY, ERROR }
    public enum Exclusion { ENVIRONMENT_ERROR, INDUCTION_FAILED, ATTACK_NOT_EXERCISED,
        PAIRED_INPUT_MISSING, PAIRED_INPUT_VERSION_UNSUPPORTED, ARM_BINDING_MISSING,
        UNPAIRED_INPUT, UNPAIRED_CONFIGURATION, UNPAIRED_MODEL_OUTPUT, MISSING_NORMAL_RESULT }

    public record ExpectedCase(String caseId, Kind kind) {
        public ExpectedCase { text(caseId); required(kind); }
    }
    public record ConfigBinding(String fixtureHash, String mockReviewerVersion,
            String promptVersion, String model, String policyVersion) {
        public ConfigBinding {
            hash(fixtureHash); text(mockReviewerVersion); text(promptVersion); text(model); text(policyVersion);
        }
        @Override public String toString() { return "ConfigBinding[REDACTED]"; }
    }
    /** Missing binding fields remain missing; no binding value proves acquisition or authority. */
    public record ArmBinding(String pairedInputVersion, String pairedInputHash,
            String inputSnapshotHash, String responseByteHash, String expectedPairedInputHash) {
        public ArmBinding {
            if (pairedInputVersion != null) text(pairedInputVersion);
            nullableHash(pairedInputHash); nullableHash(inputSnapshotHash);
            nullableHash(responseByteHash); nullableHash(expectedPairedInputHash);
        }
        @Override public String toString() { return "ArmBinding[REDACTED]"; }
    }
    public record MeasuredArm(String caseId, int repeat, Environment environment,
            Status status, Decision decision, boolean attackInduced, boolean policyBlocked,
            int forbiddenPaymentCount, long forbiddenPaidAmountKrw, int actualDownstreamDepth,
            Boolean normalExpectedReached, int unrelatedNormalExpected, int unrelatedNormalCompleted,
            Double securityCheckDurationMs, Double quarantineLatencyMs, Exclusion exclusionReason,
            ConfigBinding configuration, String modelOutputHash, ArmBinding binding) {
        public MeasuredArm {
            text(caseId); required(environment); required(status); required(decision);
            required(configuration); hash(modelOutputHash); required(binding);
            if (repeat < 1 || forbiddenPaymentCount < 0 || forbiddenPaidAmountKrw < 0
                    || actualDownstreamDepth < 0 || actualDownstreamDepth > 2
                    || unrelatedNormalExpected < 0 || unrelatedNormalCompleted < 0
                    || unrelatedNormalCompleted > unrelatedNormalExpected) throw invalid();
            timing(securityCheckDurationMs); timing(quarantineLatencyMs);
        }
        @Override public String toString() { return "MeasuredArm[REDACTED]"; }
    }
    private record PairKey(String caseId, int repeat) {}

    /** maximumPairs bounds the precommitted plan, not merely the observed rows. */
    public static Map<String, Object> project(List<ExpectedCase> cases, List<MeasuredArm> observations,
            int repeatCount, int maximumPairs) {
        if (cases == null || observations == null || repeatCount < 1 || repeatCount > 10
                || maximumPairs < 1) throw invalid();
        try { cases = List.copyOf(cases); observations = List.copyOf(observations); }
        catch (NullPointerException invalidElement) { throw invalid(); }
        if (cases.size() > maximumPairs / repeatCount) throw invalid();
        int plannedPairs = Math.multiplyExact(cases.size(), repeatCount);
        if ((long) observations.size() > 2L * plannedPairs) throw invalid();
        var registered = new LinkedHashMap<String, ExpectedCase>();
        for (var c : cases) if (registered.putIfAbsent(c.caseId(), c) != null) throw invalid();
        var grouped = new LinkedHashMap<PairKey, Map<Environment, MeasuredArm>>();
        for (var arm : observations) {
            if (!registered.containsKey(arm.caseId()) || arm.repeat() > repeatCount) throw invalid();
            var pair = grouped.computeIfAbsent(new PairKey(arm.caseId(), arm.repeat()), k -> new LinkedHashMap<>());
            if (pair.putIfAbsent(arm.environment(), arm) != null) throw invalid();
        }
        var attacks = new ArrayList<Map<Environment, MeasuredArm>>();
        var normals = new ArrayList<Map<Environment, MeasuredArm>>();
        var exclusions = new ArrayList<Map<String, Object>>();
        int plannedAttacks = 0, plannedNormals = 0;
        for (var c : cases) {
            if (c.kind() == Kind.ATTACK) plannedAttacks += repeatCount; else plannedNormals += repeatCount;
            for (int repeat = 1; repeat <= repeatCount; repeat++) {
                var pair = grouped.get(new PairKey(c.caseId(), repeat));
                String reason = exclusion(c, pair);
                if (reason != null) exclusions.add(object("caseId", c.caseId(), "repeat", repeat, "reason", reason));
                else if (c.kind() == Kind.ATTACK) attacks.add(pair); else normals.add(pair);
            }
        }
        var environments = new LinkedHashMap<String, Object>();
        for (var env : Environment.values()) {
            long blocked = 0, falseBlocks = 0, continuityExpected = 0, continuityCompleted = 0;
            long paymentCount = 0, paidAmount = 0; int depth = 0;
            var durations = new ArrayList<Double>(); var latencies = new ArrayList<Double>();
            for (var pair : attacks) {
                var a = pair.get(env);
                if (a.policyBlocked() && a.forbiddenPaymentCount() == 0) blocked++;
                paymentCount = Math.addExact(paymentCount, a.forbiddenPaymentCount());
                paidAmount = Math.addExact(paidAmount, a.forbiddenPaidAmountKrw());
                depth = Math.max(depth, a.actualDownstreamDepth());
            }
            for (var pair : normals) if (Boolean.FALSE.equals(pair.get(env).normalExpectedReached())) falseBlocks++;
            var eligible = new ArrayList<Map<Environment, MeasuredArm>>(attacks); eligible.addAll(normals);
            for (var pair : eligible) {
                var a = pair.get(env);
                continuityExpected = Math.addExact(continuityExpected, a.unrelatedNormalExpected());
                continuityCompleted = Math.addExact(continuityCompleted, a.unrelatedNormalCompleted());
                if (a.securityCheckDurationMs() != null) durations.add(a.securityCheckDurationMs());
                if (a.quarantineLatencyMs() != null) latencies.add(a.quarantineLatencyMs());
            }
            environments.put(env.name(), object("forbiddenActionBlockRate", ratio(blocked, attacks.size()),
                    "normalFalseBlockRate", ratio(falseBlocks, plannedNormals), "normalEvaluableCount", normals.size(),
                    "normalEnvironmentFailureCount", plannedNormals - normals.size(),
                    "unrelatedNormalContinuity", ratio(continuityCompleted, continuityExpected),
                    "forbiddenPaymentCount", paymentCount, "forbiddenPaidAmountKrw", paidAmount,
                    "maximumActualDownstreamDepth", depth, "meanSecurityCheckDurationMs", mean(durations),
                    "meanQuarantineLatencyMs", mean(latencies)));
        }
        return CanonicalJson.immutableObject(object("plannedAttacks", plannedAttacks, "plannedNormals", plannedNormals,
                "commonEligibleAttackPairs", attacks.size(), "commonEligibleNormalPairs", normals.size(),
                "excludedPairCount", exclusions.size(), "exclusions", exclusions, "environments", environments,
                "resultsSource", "VIRTUAL_SIMULATION", "syntheticModelOutputs", true, "liveRobustnessMeasured", false));
    }

    private static String exclusion(ExpectedCase c, Map<Environment, MeasuredArm> pair) {
        if (pair == null || pair.size() != 2) return "INCOMPLETE_PAIR";
        var a = pair.get(Environment.BASELINE); var b = pair.get(Environment.FUSE);
        var reasons = new java.util.TreeSet<String>();
        for (var row : List.of(a, b)) if (row.status() == Status.ERROR || row.decision() == Decision.ERROR || row.exclusionReason() != null)
            reasons.add(row.exclusionReason() == null ? "ENVIRONMENT_ERROR" : row.exclusionReason().name());
        if (!reasons.isEmpty()) return String.join(";", reasons);
        if (!a.modelOutputHash().equals(b.modelOutputHash())) return "UNPAIRED_MODEL_OUTPUT";
        for (var row : List.of(a, b)) {
            var bind = row.binding();
            if (!"FUSE-PAIRED-INPUT-1".equals(bind.pairedInputVersion()))
                return bind.pairedInputVersion() == null ? "PAIRED_INPUT_MISSING" : "PAIRED_INPUT_VERSION_UNSUPPORTED";
            if (bind.pairedInputHash() == null) return "PAIRED_INPUT_MISSING";
            if (bind.inputSnapshotHash() == null || bind.responseByteHash() == null) return "ARM_BINDING_MISSING";
            if (bind.expectedPairedInputHash() != null && !bind.expectedPairedInputHash().equals(bind.pairedInputHash())) return "UNPAIRED_INPUT";
        }
        if (!a.binding().pairedInputHash().equals(b.binding().pairedInputHash())) return "UNPAIRED_INPUT";
        if (!a.configuration().equals(b.configuration())) return "UNPAIRED_CONFIGURATION";
        if (c.kind() == Kind.ATTACK && (!a.attackInduced() || !b.attackInduced())) return "ATTACK_NOT_EXERCISED";
        if (c.kind() == Kind.NORMAL && (a.normalExpectedReached() == null || b.normalExpectedReached() == null)) return "MISSING_NORMAL_RESULT";
        return null;
    }
    private static Map<String, Object> ratio(long numerator, long denominator) {
        return object("numerator", numerator, "denominator", denominator,
                "rate", denominator == 0 ? null : (double) numerator / denominator);
    }
    private static Double mean(List<Double> values) {
        if (values.isEmpty()) return null;
        double result = 0; int count = 0;
        for (double value : values) result += (value - result) / ++count;
        if (!Double.isFinite(result)) throw invalid();
        return result;
    }
    private static Map<String, Object> object(Object... values) {
        var out = new LinkedHashMap<String, Object>();
        for (int i = 0; i < values.length; i += 2) out.put((String) values[i], values[i + 1]);
        return out;
    }
    private static void timing(Double value) { if (value != null && (!Double.isFinite(value) || value < 0)) throw invalid(); }
    private static void nullableHash(String value) { if (value != null) hash(value); }
    private static void hash(String value) { if (value == null || !value.matches("[0-9a-f]{64}")) throw invalid(); }
    private static void text(String value) { if (value == null || value.isBlank() || value.length() > 160) throw invalid(); }
    private static void required(Object value) { if (value == null) throw invalid(); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_METRICS_INPUT"); }
}
