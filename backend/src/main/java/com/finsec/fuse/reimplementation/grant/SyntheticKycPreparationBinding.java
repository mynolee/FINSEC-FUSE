package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;

/** Explicit synthetic preparation data; no dispatch, actual issuer or authority proof. */
public final class SyntheticKycPreparationBinding {
    private SyntheticKycPreparationBinding() { }
    public enum Decision { PREPARED, ON_HOLD }
    public enum Refusal { NONE, KYC_PRECONDITION_FAILED, RISK_LIMIT_EXCEEDED }
    public enum PreparationEffect { NO_NEW_PREPARATION_ATTEMPT_THIS_INVOCATION, COMMITTED_IN_PROCESS, UNKNOWN }
    public record SourceCoordinate(UUID documentId, int documentVersion) {
        public SourceCoordinate { if (documentId == null || documentVersion < 1) throw invalid(); }
        @Override public String toString() { return "SourceCoordinate[REDACTED]"; }
    }
    public record SourceReference(UUID documentId, int documentVersion, String contentHash) {
        public SourceReference { if (documentId == null || documentVersion < 1 || !SimulationSpec.hash(contentHash)) throw invalid(); }
        @Override public String toString() { return "SourceReference[REDACTED]"; }
    }
    public record PreparationCommand(CommandIdentity identity, SimulationSpec.Source source,
                                     List<SimulationSpec.Fact> facts, SimulationSpec.RiskTerms terms, Instant preparedAt) {
        public PreparationCommand {
            if (identity == null || source == null || facts == null || terms == null || preparedAt == null) throw invalid();
            if (facts.stream().anyMatch(Objects::isNull)) throw invalid();
            facts = List.copyOf(facts);
            if (facts.size() > 10) throw invalid();
        }
        @Override public String toString() { return "PreparationCommand[REDACTED]"; }
    }
    public record InputDescriptor(SourceReference source, List<SimulationSpec.Fact> facts,
                                  SimulationSpec.RiskTerms terms, Instant preparedAt) {
        public InputDescriptor {
            if (source == null || facts == null || terms == null || preparedAt == null) throw invalid();
            if (facts.stream().anyMatch(Objects::isNull)) throw invalid();
            facts = List.copyOf(facts);
        }
        @Override public String toString() { return "InputDescriptor[REDACTED]"; }
    }
    public static final class PreparedInput {
        private final Map<String, Object> canonicalInput;
        private final Map<String, Object> modelInput;
        private final String inputSnapshotHash;
        private PreparedInput(Map<String, Object> canonical) {
            canonicalInput = CanonicalJson.immutableObject(canonical);
            inputSnapshotHash = CanonicalJson.orderedSha256(canonicalInput);
            var input = new LinkedHashMap<String, Object>();
            canonicalInput.forEach((key, value) -> {
                if (key.equals("evidenceFacts")) input.put("inputSnapshotHash", inputSnapshotHash);
                input.put(key, value);
            });
            modelInput = CanonicalJson.immutableObject(input);
        }
        /** Explicit internal synthetic model input, including source text; never a receipt projection. */
        public Map<String, Object> canonicalInput() { return canonicalInput; }
        public Map<String, Object> modelInput() { return modelInput; }
        public String inputSnapshotHash() { return inputSnapshotHash; }
        @Override public String toString() { return "PreparedInput[REDACTED]"; }
    }
    public record FreshBindings(GrantSnapshot grant, String workflowState,
                                VirtualGrantEvaluationAccounting.Counters counters, int riskLimit,
                                SourceCoordinate currentSource, SimulationSpec.RiskTerms riskTerms, boolean held) {
        public FreshBindings {
            if (grant == null || workflowState == null || counters == null || riskLimit < 0
                    || currentSource == null || riskTerms == null) throw invalid();
        }
        @Override public String toString() { return "FreshBindings[SUPPLIED_REDACTED]"; }
    }
    public record ResolvedPreparation(FreshBindings bindings, PreparedInput input) {
        public ResolvedPreparation { if (bindings == null || input == null) throw invalid(); }
        @Override public String toString() { return "ResolvedPreparation[REDACTED]"; }
    }
    public record PreparationMarker(CommandIdentity identity, String inputSnapshotHash, Instant preparedAt,
                                    int chargedPoints, int kycRunsAfter, int usedRiskAfter) {
        public PreparationMarker {
            if (identity == null || !SimulationSpec.hash(inputSnapshotHash) || preparedAt == null || chargedPoints < 0
                    || kycRunsAfter < 1 || usedRiskAfter < 0) throw invalid();
        }
        @Override public String toString() { return "PreparationMarker[REDACTED]"; }
    }
    public record PreparationReceipt(CommandIdentity identity, InputDescriptor descriptor, String inputSnapshotHash,
                                     Decision decision, Refusal refusal, int chargedPoints, int kycRunsAfter, int usedRiskAfter) {
        public PreparationReceipt {
            if (identity == null || descriptor == null || !SimulationSpec.hash(inputSnapshotHash) || decision == null || refusal == null
                    || chargedPoints < 0 || kycRunsAfter < 0 || usedRiskAfter < 0
                    || (decision == Decision.PREPARED) != (refusal == Refusal.NONE)
                    || decision == Decision.PREPARED && kycRunsAfter < 1
                    || decision == Decision.ON_HOLD && chargedPoints != 0) throw invalid();
        }
        public boolean actualAuthority() { return false; }
        @Override public String toString() { return "PreparationReceipt[VIRTUAL_REDACTED]"; }
    }
    public record PreparationOutcome(Status status, PreparationReceipt receipt, PreparationEffect effect) {
        public PreparationOutcome {
            if (status == null || effect == null) throw invalid();
            boolean committed = status == Status.VIRTUAL_COMMITTED_IN_PROCESS || status == Status.VIRTUAL_REPLAYED_IN_PROCESS;
            boolean unknown = status == Status.COMMIT_UNKNOWN || status == Status.RECONCILIATION_UNCONFIRMED
                    || status == Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH || status == Status.TRANSACTION_INVARIANT_UNCONFIRMED;
            if (committed && (receipt == null || effect != PreparationEffect.COMMITTED_IN_PROCESS)
                    || !committed && receipt != null || unknown && effect != PreparationEffect.UNKNOWN
                    || !committed && !unknown && effect != PreparationEffect.NO_NEW_PREPARATION_ATTEMPT_THIS_INVOCATION) throw invalid();
        }
        public boolean actualAuthority() { return false; }
        public boolean durable() { return false; }
        public boolean executionAuthorityGranted() { return false; }
        @Override public String toString() { return "PreparationOutcome[VIRTUAL_NON_AUTHORIZING]"; }
    }
    /** Must verify current credential/I/K/source/catalog facts under this same owned context; no provider IO. */
    public interface PreparationResolver {
        Gate current(ServerContext context, PreparationCommand command, OwnedKycPreparationPort.OwnedPreparationTx tx);
    }
    public static InputDescriptor descriptor(PreparationCommand command) {
        if (command == null) throw invalid();
        var source = command.source();
        return new InputDescriptor(new SourceReference(source.documentId(), source.documentVersion(), source.contentHash()),
                command.facts().stream().sorted(java.util.Comparator.comparing(f -> f.evidenceId().toString())).toList(),
                command.terms(), command.preparedAt());
    }
    public static PreparedInput prepareRequested(PreparationCommand command) {
        if (command == null || !command.source().reviewedSafe()) throw invalid();
        var i = command.identity(); var source = command.source();
        var facts = descriptor(command).facts();
        if (facts.stream().map(SimulationSpec.Fact::evidenceId).distinct().count() != facts.size()
                || facts.stream().anyMatch(f -> !f.customerId().equals(i.customerId()) || !f.usable(command.preparedAt()))) throw invalid();
        return new PreparedInput(object("requestId", i.globalRequestId().toString(), "workflowId", i.workflowId().toString(),
                "generation", i.generation(), "runId", i.targetRunId().toString(), "customerId", i.customerId(),
                "policyVersion", command.terms().policyVersion(),
                "evidenceFacts", facts.stream().map(f -> object("evidenceId", f.evidenceId().toString(),
                        "kind", f.kind().name(), "result", f.result().name())).toList(),
                "documents", List.of(object("documentId", source.documentId().toString(), "documentVersion", source.documentVersion(),
                        "contentHash", source.contentHash(), "text", source.text()))));
    }
    public static void checkBindings(PreparationCommand command, FreshBindings binding) {
        if (command == null || binding == null) throw invalid();
        var i = command.identity(); var g = binding.grant();
        if (!i.grantId().equals(g.grantId()) || !i.actionId().equals(g.actionId()) || !i.targetRunId().equals(g.targetRunId())
                || !i.workflowId().equals(g.workflowId()) || i.generation() != g.generation() || !i.customerId().equals(g.customerId())
                || g.action() != AllowedAction.EVALUATE_KYC || g.state() != GrantState.ISSUED
                || !command.terms().equals(binding.riskTerms())
                || !command.source().documentId().equals(binding.currentSource().documentId())
                || command.source().documentVersion() != binding.currentSource().documentVersion()) throw invalid();
    }
    public static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_KYC_PREPARATION", null); }
}
