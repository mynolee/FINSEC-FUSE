package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;

/**
 * Synchronous synthetic-only delivery adapter. It owns no client, worker, thread,
 * executor, timer, model, service credential, prompt, or environment provider.
 * The store and bridge must belong to the same virtual product assembly.
 *
 * Delivery claims prevent overlapping calls through this adapter. A returned,
 * validated synthetic response is cached before acceptance so retries reuse it.
 * If the provider throws or validation fails before a response is cached, retry
 * may invoke that side-effect-free provider again with the same delivery key.
 * Process restart loses claims, responses and action receipts. This is not
 * durable exactly-once execution or an operating timeout guarantee.
 */
public final class VirtualKycJobAdapter {
    static final String TABLE = "virtual_kyc_deliveries";
    private static final String SKIP_OPERATION = "SIM_SKIP_KYC_DELIVERY";

    public record Delivery(UUID prepareAction, UUID observationAction, UUID workflowId, UUID expectedJobId, int expectedGeneration) {
        public Delivery(UUID prepareAction, UUID observationAction, UUID workflowId) {
            this(prepareAction, observationAction, workflowId, null, 0);
        }
        public Delivery {
            Objects.requireNonNull(prepareAction); Objects.requireNonNull(observationAction);
            Objects.requireNonNull(workflowId);
            if (prepareAction.equals(observationAction) || (expectedJobId == null ? expectedGeneration != 0 : expectedGeneration < 1))
                throw SimulationFailure.invalid();
        }
    }

    /**
     * Mandatory deterministic, side-effect-free synthetic port.
     * Must not access a real model/network/database, grant authority, or reenter
     * the adapter. Stable delivery identifiers must yield the same proposal.
     */
    public interface ProviderPort {
        String mode();
        Map<String, Object> evaluate(Delivery delivery, Map<String, Object> immutableInput);
    }

    private final TransactionalStore store;
    private final VirtualAgentBridge bridge;
    private final ProviderPort provider;
    private final ActionJournal journal;

    public VirtualKycJobAdapter(TransactionalStore sharedStore, VirtualAgentBridge sharedBridge,
                               ProviderPort provider) {
        if (sharedStore == null || sharedBridge == null || provider == null) throw SimulationFailure.invalid();
        this.store = sharedStore; this.bridge = sharedBridge; this.provider = provider;
        try {
            if (!VirtualTransactionalStore.MODE.equals(store.mode())
                    || !VirtualTransactionalStore.MODE.equals(provider.mode())) throw SimulationFailure.invalid();
            this.journal = new ActionJournal(store);
        } catch (RuntimeException invalidMode) {
            throw SimulationFailure.invalid();
        }
    }

    /**
     * Rechecks current KYC authority through prepare even for a saved delivery.
     * A prepare DENY returns its prepare-action receipt and never calls a provider.
     * Otherwise the final receipt is bound to observationAction.
     */
    public Map<String, Object> run(ActorRef actor, Delivery delivery) {
        try {
            return perform(actor, delivery);
        } catch (SimulationFailure fixed) {
            throw fixed;
        } catch (ActionJournal.ActionConflictException conflict) {
            throw SimulationFailure.invalid();
        } catch (RuntimeException unavailable) {
            throw SimulationFailure.unavailable();
        }
    }

    private Map<String, Object> perform(ActorRef actor, Delivery delivery) {
        if (delivery == null) throw SimulationFailure.invalid();
        Map<String, Object> prepared = delivery.expectedJobId() == null
                ? bridge.prepare(actor, delivery.prepareAction(), delivery.workflowId())
                : bridge.prepare(actor, delivery.prepareAction(), delivery.workflowId(), delivery.expectedJobId(), delivery.expectedGeneration());
        if (!prepared.containsKey("input")) return withoutInput(prepared);
        Map<String, Object> input = input(prepared.get("input"), delivery);
        String fingerprint = CanonicalJson.orderedSha256(input);
        Claim claim = claim(actor, delivery, input, fingerprint);
        if (claim.skipped()) return skip(actor, delivery, fingerprint);
        if (claim.response() != null) return bridge.accept(actor, delivery.observationAction(), claim.response());

        Map<String, Object> response;
        try {
            Map<String, Object> raw;
            try {
                if (!VirtualTransactionalStore.MODE.equals(provider.mode())) throw SimulationFailure.unavailable();
                raw = provider.evaluate(delivery, input);
                if (!VirtualTransactionalStore.MODE.equals(provider.mode())) throw SimulationFailure.unavailable();
            }
            catch (RuntimeException unavailable) { throw SimulationFailure.unavailable(); }
            response = normalize(raw, input);
            cacheResponse(actor, delivery, fingerprint, response);
        } catch (RuntimeException failure) {
            retryable(actor, delivery, fingerprint);
            if (failure instanceof SimulationFailure fixed) throw fixed;
            throw SimulationFailure.unavailable();
        } catch (Error failure) {
            // A terminated evaluation must not retain a live delivery claim.
            // Cleanup changes only IN_FLIGHT, never an already cached response.
            // Preserve the original fatal error even if best-effort cleanup fails.
            try { retryable(actor, delivery, fingerprint); }
            catch (RuntimeException | Error cleanupFailure) {
                // Do not allocate suppressed-error storage while preserving a
                // fatal error: even that allocation may fail and mask it.
            }
            throw failure;
        }
        // Authority and correlation are rechecked again after a response arrives.
        // Keep the response on rejection/unavailability so a retry never needs a
        // second successful provider evaluation for this delivery.
        return bridge.accept(actor, delivery.observationAction(), response);
    }

    private Claim claim(ActorRef actor, Delivery delivery, Map<String, Object> input, String fingerprint) {
        return store.transaction(tx -> {
            Map<String, Object> existing = tx.get(TABLE, delivery.prepareAction().toString());
            if (existing != null) {
                bound(existing, actor, delivery, fingerprint);
                String phase = (String) existing.get("phase");
                if ("RESPONDED".equals(phase)) return new Claim(nested(existing, "response"), false);
                if ("SKIPPED".equals(phase)) return new Claim(null, true);
                if ("IN_FLIGHT".equals(phase)) throw SimulationFailure.unavailable();
                if (!"RETRYABLE".equals(phase)) throw SimulationFailure.unavailable();
            }
            if (!eligible(tx, delivery, input)) return new Claim(null, true);
            tx.put(TABLE, delivery.prepareAction().toString(), row(actor, delivery, fingerprint, "IN_FLIGHT"));
            return new Claim(null, false);
        });
    }

    private void cacheResponse(ActorRef actor, Delivery delivery, String fingerprint, Map<String, Object> response) {
        store.transaction(tx -> {
            Map<String, Object> existing = tx.get(TABLE, delivery.prepareAction().toString());
            if (existing == null) throw SimulationFailure.unavailable();
            bound(existing, actor, delivery, fingerprint);
            if (!"IN_FLIGHT".equals(existing.get("phase"))) throw SimulationFailure.unavailable();
            Map<String, Object> cached = new java.util.LinkedHashMap<>(row(actor, delivery, fingerprint, "RESPONDED"));
            cached.put("response", response);
            tx.put(TABLE, delivery.prepareAction().toString(), cached);
            return null;
        });
    }

    private void retryable(ActorRef actor, Delivery delivery, String fingerprint) {
        store.transaction(tx -> {
            Map<String, Object> existing = tx.get(TABLE, delivery.prepareAction().toString());
            if (existing != null) {
                bound(existing, actor, delivery, fingerprint);
                if ("IN_FLIGHT".equals(existing.get("phase")))
                    tx.put(TABLE, delivery.prepareAction().toString(), row(actor, delivery, fingerprint, "RETRYABLE"));
            }
            return null;
        });
    }

    private Map<String, Object> skip(ActorRef actor, Delivery delivery, String fingerprint) {
        return journal.execute(actor.actorId(), delivery.observationAction(), SKIP_OPERATION,
                CanonicalJson.sha256(row(actor, delivery, fingerprint, "SKIPPED")), tx -> {
            Map<String, Object> existing = tx.get(TABLE, delivery.prepareAction().toString());
            if (existing != null) bound(existing, actor, delivery, fingerprint);
            Map<String, Object> workflow = tx.get(VirtualWorkflowService.WORKFLOWS, delivery.workflowId().toString());
            if (workflow == null) throw SimulationFailure.invalid();
            tx.put(TABLE, delivery.prepareAction().toString(), row(actor, delivery, fingerprint, "SKIPPED"));
            return object("requestId", delivery.observationAction().toString(), "workflowId", delivery.workflowId().toString(),
                    "generation", workflow.get("generation"), "state", workflow.get("state"), "decision", "DENY",
                    "reasonCodes", List.of("LATE_RESULT_DISCARDED"), "message", "LATE_RESULT_DISCARDED", "replayed", false);
        });
    }

    private static boolean eligible(TransactionalStore.Tx tx, Delivery delivery, Map<String, Object> input) {
        Map<String, Object> workflow = tx.get(VirtualWorkflowService.WORKFLOWS, delivery.workflowId().toString());
        if (workflow == null || !"KYC_PENDING".equals(workflow.get("state"))
                || !(workflow.get("activeJobId") instanceof String jobId)
                || !Objects.equals(workflow.get("generation"), input.get("generation"))) return false;
        Map<String, Object> job = tx.get(VirtualWorkflowService.JOBS, jobId);
        if (job == null || !"RUNNING".equals(job.get("state")) || !"KYC".equals(job.get("phase"))
                || !delivery.workflowId().toString().equals(job.get("workflowId"))
                || !Objects.equals(workflow.get("generation"), job.get("generation"))
                || !(job.get("runId") instanceof String runId) || !runId.equals(input.get("runId"))) return false;
        Map<String, Object> run = tx.get(VirtualWorkflowService.RUNS, runId);
        return run != null && delivery.prepareAction().toString().equals(run.get("requestId"))
                && delivery.workflowId().toString().equals(run.get("workflowId"))
                && workflow.get("generation").equals(run.get("generation"))
                && Objects.equals(input.get("inputSnapshotHash"), run.get("inputSnapshotHash"));
    }

    private static Map<String, Object> row(ActorRef actor, Delivery delivery, String fingerprint, String phase) {
        var value = new java.util.LinkedHashMap<>(object("actorId", actor.actorId(), "prepareAction", delivery.prepareAction().toString(),
                "observationAction", delivery.observationAction().toString(), "workflowId", delivery.workflowId().toString(),
                "inputHash", fingerprint, "phase", phase, "executionMode", VirtualTransactionalStore.MODE));
        if (delivery.expectedJobId() != null) {
            value.put("expectedJobId", delivery.expectedJobId().toString()); value.put("expectedGeneration", delivery.expectedGeneration());
        }
        return com.finsec.fuse.reimplementation.persistence.CanonicalJson.immutableObject(value);
    }

    private static void bound(Map<String, Object> existing, ActorRef actor, Delivery delivery, String fingerprint) {
        if (delivery.expectedJobId() == null) {
            if (existing.containsKey("expectedJobId") || existing.containsKey("expectedGeneration")) throw SimulationFailure.invalid();
        } else if (!delivery.expectedJobId().toString().equals(existing.get("expectedJobId"))
                || !Integer.valueOf(delivery.expectedGeneration()).equals(existing.get("expectedGeneration"))) throw SimulationFailure.invalid();
        if (!actor.actorId().equals(existing.get("actorId"))
                || !delivery.prepareAction().toString().equals(existing.get("prepareAction"))
                || !delivery.observationAction().toString().equals(existing.get("observationAction"))
                || !delivery.workflowId().toString().equals(existing.get("workflowId"))
                || !fingerprint.equals(existing.get("inputHash"))) throw SimulationFailure.invalid();
    }

    private record Claim(Map<String, Object> response, boolean skipped) {}

    private static Map<String, Object> input(Object value, Delivery delivery) {
        if (!(value instanceof Map<?, ?> raw) || raw.keySet().stream().anyMatch(key -> !(key instanceof String)))
            throw SimulationFailure.unavailable();
        @SuppressWarnings("unchecked") Map<String, Object> copy = CanonicalJson.immutableObject((Map<String, Object>) raw);
        if (!delivery.prepareAction().toString().equals(copy.get("requestId"))
                || !delivery.workflowId().toString().equals(copy.get("workflowId"))
                || !(copy.get("generation") instanceof Integer generation) || generation < 1
                || !canonicalUuid(copy.get("runId")) || !SimulationSpec.hash(text(copy, "inputSnapshotHash")))
            throw SimulationFailure.unavailable();
        return copy;
    }

    /**
     * Validates the existing public DTO before retaining a response, then drops
     * untrusted model/explanation text. Only fixed synthetic metadata is cached.
     */
    private static Map<String, Object> normalize(Map<String, Object> response, Map<String, Object> input) {
        if (response == null) throw SimulationFailure.invalid();
        // Check sizes/closed fields before traversing or copying any provider-owned tree.
        closed(response, Set.of("requestId", "workflowId", "generation", "runId", "inputSnapshotHash", "proposal", "modelMetadata"));
        for (String key : List.of("requestId", "workflowId", "generation", "runId", "inputSnapshotHash"))
            if (!Objects.equals(input.get(key), response.get(key))) throw SimulationFailure.invalid();
        Map<String, Object> proposal = nestedClosed(response, "proposal", Set.of("status", "evidenceIds", "explanation"));
        String status = text(proposal, "status");
        if (status.length() > 12 || !Set.of("VERIFIED", "NOT_VERIFIED", "NEEDS_REVIEW").contains(status)) throw SimulationFailure.invalid();
        String explanation = text(proposal, "explanation");
        if (explanation.isEmpty() || explanation.length() > 4000 || !validUnicode(explanation)
                || explanation.codePointCount(0, explanation.length()) > 2000) throw SimulationFailure.invalid();
        Object rawIds = proposal.get("evidenceIds");
        if (!(rawIds instanceof List<?> ids) || ids.size() > 10) throw SimulationFailure.invalid();
        var selectedIds = new java.util.ArrayList<String>(ids.size());
        for (Object value : ids) {
            if (!canonicalUuid(value) || selectedIds.contains(value)) throw SimulationFailure.invalid();
            selectedIds.add((String) value);
        }
        Map<String, Object> metadata = nestedClosed(response, "modelMetadata", Set.of("model", "promptVersion"));
        String model = text(metadata, "model");
        if (model.isEmpty() || model.length() > 320 || !validUnicode(model) || model.isBlank()
                || model.codePointCount(0, model.length()) > 160
                || !"KYC-PROMPT-1".equals(metadata.get("promptVersion"))) throw SimulationFailure.invalid();
        // Only known bounded values cross into the immutable cache; input/model text is absent.
        return object("requestId", input.get("requestId"), "workflowId", input.get("workflowId"), "generation", input.get("generation"),
                "runId", input.get("runId"), "inputSnapshotHash", input.get("inputSnapshotHash"),
                "proposal", object("status", status, "evidenceIds", selectedIds, "explanation", "SYNTHETIC_PROVIDER_RESPONSE"),
                "modelMetadata", object("model", "synthetic-provider", "promptVersion", "KYC-PROMPT-1"));
    }

    private static boolean validUnicode(String value) {
        for (int at = 0; at < value.length(); at++) {
            char unit = value.charAt(at);
            if (Character.isHighSurrogate(unit)) {
                if (++at >= value.length() || !Character.isLowSurrogate(value.charAt(at))) return false;
            } else if (Character.isLowSurrogate(unit)) return false;
        }
        return true;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> nestedClosed(Map<String, Object> value, String key, Set<String> fields) {
        if (!(value.get(key) instanceof Map<?, ?> raw) || raw.size() != fields.size() || !raw.keySet().equals(fields))
            throw SimulationFailure.invalid();
        return (Map<String, Object>) raw;
    }

    private static Map<String, Object> withoutInput(Map<String, Object> prepared) {
        Map<String, Object> receipt = new java.util.LinkedHashMap<>(prepared); receipt.remove("input");
        return CanonicalJson.immutableObject(receipt);
    }
    private static String text(Map<String, Object> value, String key) {
        if (!(value.get(key) instanceof String text)) throw SimulationFailure.invalid();
        return text;
    }
    private static boolean canonicalUuid(Object value) {
        return value instanceof String text && text.length() == 36 && text.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    }
    private static void closed(Map<String, Object> value, Set<String> fields) {
        if (value.size() != fields.size() || !value.keySet().equals(fields)) throw SimulationFailure.invalid();
    }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> nested(Map<String, Object> value, String key) {
        if (!(value.get(key) instanceof Map<?, ?> map) || map.keySet().stream().anyMatch(k -> !(k instanceof String)))
            throw SimulationFailure.invalid();
        return (Map<String, Object>) map;
    }
}
