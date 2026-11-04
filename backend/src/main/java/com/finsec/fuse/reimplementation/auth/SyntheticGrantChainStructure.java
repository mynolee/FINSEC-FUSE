package com.finsec.fuse.reimplementation.auth;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Optional unsigned complete-chain structure, not trusted ancestry or grant admission.
 * Logical stages follow the selected action/depth relation; agent/issuer names do
 * not authenticate those stages. No lifecycle, result-store or key is resolved.
 */
public final class SyntheticGrantChainStructure {
    private SyntheticGrantChainStructure() {}

    /** Existing scalar-only records; null fields are rejected by prepareChain. */
    public record Node(SyntheticGrantV2Codec.Claims claims, SyntheticGrantV2Codec.Action action) {
        @Override public String toString() { return "GrantChain.Node[REDACTED]"; }
    }

    /** A successful structural preparation only. No issuance or consumption occurred. */
    public static final class PreparedChain {
        private final List<SyntheticGrantV2Codec.Prepared> frames;
        private PreparedChain(List<SyntheticGrantV2Codec.Prepared> frames) {
            this.frames = List.copyOf(frames);
        }
        public List<SyntheticGrantV2Codec.Prepared> frames() { return frames; }
        public int depth() { return frames.size(); }
        public boolean structuralSatisfied() { return true; }
        public boolean authorizationEstablished() { return false; }
        @Override public String toString() { return "PreparedChain[UNSIGNED_NON_AUTHORIZING]"; }
    }

    static List<Node> freezeNodes(List<Node> nodes) {
        if (nodes == null || nodes.size() < 1 || nodes.size() > 3) throw invalid();
        var copy = new ArrayList<Node>(nodes);
        if (copy.size() < 1 || copy.size() > 3) throw invalid();
        Set<UUID> grants = new HashSet<>(), actions = new HashSet<>(), targets = new HashSet<>();
        SyntheticGrantV2Codec.Claims parent = null;
        for (int index = 0; index < copy.size(); index++) {
            Node node = copy.get(index);
            if (node == null || node.claims() == null || node.action() == null) throw invalid();
            var child = node.claims();
            GrantStorageShape.AllowedAction expected = switch (index) {
                case 0 -> GrantStorageShape.AllowedAction.EVALUATE_KYC;
                case 1 -> GrantStorageShape.AllowedAction.CREATE_LOAN_RECOMMENDATION;
                case 2 -> GrantStorageShape.AllowedAction.EXECUTE_MOCK_PAYMENT;
                default -> throw invalid();
            };
            if (child.depth() != index + 1 || child.allowedAction() != expected
                    || child.grantId() == null || child.actionId() == null || child.targetRunId() == null
                    || !grants.add(child.grantId()) || !actions.add(child.actionId())
                    || !targets.add(child.targetRunId())) throw invalid();
            if (parent != null && (!Objects.equals(child.parentGrantId(), parent.grantId())
                    || !Objects.equals(child.sourceRunId(), parent.targetRunId())
                    || !Objects.equals(child.workflowId(), parent.workflowId())
                    || child.generation() != parent.generation()
                    || !Objects.equals(child.customerId(), parent.customerId()))) throw invalid();
            parent = child;
        }
        // Per-row preparation additionally checks all existing source/approval null
        // shapes and canonical action bindings. No parent result row is invented.
        return List.copyOf(copy);
    }

    static PreparedChain finish(List<SyntheticGrantV2Codec.Prepared> frames) {
        return new PreparedChain(frames);
    }

    static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_SYNTHETIC_GRANT_CHAIN");
    }
}
