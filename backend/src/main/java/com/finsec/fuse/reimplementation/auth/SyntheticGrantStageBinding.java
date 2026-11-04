package com.finsec.fuse.reimplementation.auth;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Supplied snapshot consistency only. No authoritative finality, body-hash
 * verification, issuer, current gates or committed transaction is established.
 */
public final class SyntheticGrantStageBinding {
    private SyntheticGrantStageBinding() {}

    public enum AgentRole { KYC, LOAN, PAYMENT, UNKNOWN }
    public enum RunStatus { QUEUED, RUNNING, PROPOSED, VALIDATED, BLOCKED, FAILED, INVALIDATED, SUCCEEDED, UNKNOWN }
    public enum ResultStatus { PROPOSED, VALIDATED, INVALIDATED, UNKNOWN }
    public enum BusinessConclusion { POSITIVE, NEGATIVE, UNCONFIRMED }

    /** Explicit caller allocation bound only; no selected runtime default. */
    public record BindingProfile(int maxBodyBytes) {
        public BindingProfile { if (maxBodyBytes < 1) throw invalid(); }
    }
    public record Scope(UUID workflowId, int generation, String customerId) {
        @Override public String toString() { return "StageScope[REDACTED]"; }
    }
    public record StageCommand(String actorId, UUID globalRequestId, String operation,
                               String canonicalizationVersion, String canonicalBodyDigest,
                               UUID grantId, UUID actionId, UUID targetRunId, Scope scope) {
        @Override public String toString() { return "StageCommand[SUPPLIED_REDACTED]"; }
    }
    public record WorkflowSnapshot(Scope scope) {
        @Override public String toString() { return "WorkflowSnapshot[SUPPLIED_REDACTED]"; }
    }
    public record RunSnapshot(UUID runId, UUID actionId, Scope scope, AgentRole role, RunStatus status) {
        @Override public String toString() { return "RunSnapshot[SUPPLIED_REDACTED]"; }
    }
    public record BodyBinding(String canonicalizationVersion, byte[] canonicalBody, String digest,
                              String inputSnapshotHash, String evidenceBundleHash,
                              UUID sourceRunId, UUID sourceResultId, String validationReference) {
        public BodyBinding { canonicalBody = canonicalBody == null ? null : canonicalBody.clone(); }
        @Override public byte[] canonicalBody() { return canonicalBody == null ? null : canonicalBody.clone(); }
        @Override public String toString() { return "BodyBinding[SUPPLIED_REDACTED]"; }
    }
    public record ResultSnapshot(UUID resultId, UUID runId, UUID workflowId, int generation,
                                 ResultStatus status, BusinessConclusion businessConclusion, BodyBinding binding) {
        @Override public String toString() { return "ResultSnapshot[SUPPLIED_REDACTED]"; }
    }
    public record ExpectedResultBinding(UUID resultId, BodyBinding binding) {
        @Override public String toString() { return "ExpectedResultBinding[SUPPLIED_REDACTED]"; }
    }

    public static final class PreparedStage {
        private final SyntheticGrantChainStructure.PreparedChain chain;
        private final BusinessConclusion businessConclusion;
        private PreparedStage(SyntheticGrantChainStructure.PreparedChain chain, BusinessConclusion conclusion) {
            this.chain = chain; this.businessConclusion = conclusion;
        }
        public SyntheticGrantChainStructure.PreparedChain chain() { return chain; }
        public BusinessConclusion businessConclusion() { return businessConclusion; }
        public boolean suppliedBindingConsistent() { return true; }
        public boolean authorizationEstablished() { return false; }
        public boolean authoritativeFinalityEstablished() { return false; }
        public boolean bodyHashVerified() { return false; }
        @Override public String toString() { return "PreparedStage[UNSIGNED_SUPPLIED_BINDING_ONLY]"; }
    }

    static PreparedStage bind(SyntheticGrantChainStructure.PreparedChain chain,
                              List<SyntheticGrantChainStructure.Node> nodes, BindingProfile profile,
                              StageCommand command, RunSnapshot run, ResultSnapshot result,
                              WorkflowSnapshot workflow, ExpectedResultBinding expected) {
        if (profile == null || command == null || run == null || result == null || workflow == null
                || expected == null || nodes == null || nodes.isEmpty()) throw invalid();
        var leaf = nodes.get(nodes.size() - 1).claims();
        AgentRole role = switch (leaf.allowedAction()) {
            case EVALUATE_KYC -> AgentRole.KYC;
            case CREATE_LOAN_RECOMMENDATION -> AgentRole.LOAN;
            default -> throw invalid();
        };
        scope(command.scope()); scope(run.scope()); scope(workflow.scope());
        text(command.actorId()); text(command.operation()); text(command.canonicalizationVersion());
        digest(command.canonicalBodyDigest());
        if (command.globalRequestId() == null || !Objects.equals(command.grantId(), leaf.grantId())
                || !Objects.equals(command.actionId(), leaf.actionId())
                || !Objects.equals(command.targetRunId(), leaf.targetRunId())
                || !Objects.equals(command.scope(), run.scope()) || !Objects.equals(command.scope(), workflow.scope())
                || !Objects.equals(command.scope().workflowId(), leaf.workflowId())
                || command.scope().generation() != leaf.generation()
                || !Objects.equals(command.scope().customerId(), leaf.customerId())
                || !Objects.equals(run.runId(), command.targetRunId())
                || !Objects.equals(run.actionId(), command.actionId()) || run.role() != role
                || run.status() != RunStatus.VALIDATED || result.status() != ResultStatus.VALIDATED
                || result.resultId() == null || !Objects.equals(result.resultId(), expected.resultId())
                || !Objects.equals(result.runId(), run.runId())
                || !Objects.equals(result.workflowId(), command.scope().workflowId())
                || result.generation() != command.scope().generation()
                || (result.businessConclusion() != BusinessConclusion.POSITIVE
                    && result.businessConclusion() != BusinessConclusion.NEGATIVE)) throw invalid();
        BodyBinding actual = result.binding(), wanted = expected.binding();
        body(actual, profile); body(wanted, profile);
        if (!Objects.equals(actual.canonicalizationVersion(), wanted.canonicalizationVersion())
                || !Arrays.equals(actual.canonicalBody, wanted.canonicalBody)
                || !Objects.equals(actual.digest(), wanted.digest())
                || !Objects.equals(actual.inputSnapshotHash(), wanted.inputSnapshotHash())
                || !Objects.equals(actual.evidenceBundleHash(), wanted.evidenceBundleHash())
                || !Objects.equals(actual.sourceRunId(), wanted.sourceRunId())
                || !Objects.equals(actual.sourceResultId(), wanted.sourceResultId())
                || !Objects.equals(actual.validationReference(), wanted.validationReference())
                || !Objects.equals(actual.sourceRunId(), leaf.sourceRunId())
                || !Objects.equals(actual.sourceResultId(), leaf.sourceResultId())
                || (leaf.evidenceBundleHash() != null
                    && !Objects.equals(actual.evidenceBundleHash(), leaf.evidenceBundleHash()))) throw invalid();
        return new PreparedStage(chain, result.businessConclusion());
    }

    private static void scope(Scope scope) {
        if (scope == null || scope.workflowId() == null || scope.generation() < 1) throw invalid();
        text(scope.customerId());
    }
    private static void body(BodyBinding value, BindingProfile profile) {
        if (value == null || value.canonicalBody == null || value.canonicalBody.length < 1
                || value.canonicalBody.length > profile.maxBodyBytes()) throw invalid();
        text(value.canonicalizationVersion()); text(value.validationReference());
        digest(value.digest()); digest(value.inputSnapshotHash()); digest(value.evidenceBundleHash());
    }
    private static void text(String text) { if (text == null || text.isBlank()) throw invalid(); }
    private static void digest(String digest) {
        if (digest == null || !digest.matches("[0-9a-f]{64}")) throw invalid();
    }
    static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_SYNTHETIC_GRANT_STAGE"); }
}
