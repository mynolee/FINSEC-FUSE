package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowResumeBoundary;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;
import static com.finsec.fuse.reimplementation.simulation.VirtualWorkflowService.*;
import static org.junit.jupiter.api.Assertions.*;

/** Authored synthetic regression source only; no provider, test or project was executed. */
final class VirtualKycJobAdapterTest {
    private static final String MODEL_MARKER = "synthetic-model-diagnostic";
    private static final String EXPLANATION_MARKER = "synthetic-explanation-diagnostic";

    private VirtualKycJobAdapter.Delivery delivery(SimulationFixture f, UUID workflow) {
        return new VirtualKycJobAdapter.Delivery(f.id(), f.id(), workflow);
    }
    private VirtualKycJobAdapter adapter(SimulationFixture f, VirtualKycJobAdapter.ProviderPort provider) {
        return new VirtualKycJobAdapter(f.store, new VirtualAgentBridge(f.workflows), provider);
    }
    private VirtualKycJobAdapter.ProviderPort provider(java.util.function.Function<Map<String, Object>, Map<String, Object>> evaluation) {
        return new VirtualKycJobAdapter.ProviderPort() {
            @Override public String mode() { return "VIRTUAL_NON_DURABLE"; }
            @Override public Map<String, Object> evaluate(VirtualKycJobAdapter.Delivery delivery, Map<String, Object> input) {
                return evaluation.apply(input);
            }
        };
    }
    private Map<String, Object> response(Map<String, Object> input) {
        return object("requestId", input.get("requestId"), "workflowId", input.get("workflowId"),
                "generation", input.get("generation"), "runId", input.get("runId"),
                "inputSnapshotHash", input.get("inputSnapshotHash"),
                "proposal", object("status", "VERIFIED", "evidenceIds", List.of(ID_FACT.toString(), FACE_FACT.toString()),
                        "explanation", EXPLANATION_MARKER),
                "modelMetadata", object("model", MODEL_MARKER, "promptVersion", "KYC-PROMPT-1"));
    }

    @Test void portMustExplicitlyIdentifySyntheticModeAndActionsMustDiffer() {
        var f = new SimulationFixture();
        assertThrows(SimulationFailure.class, () -> adapter(f, new VirtualKycJobAdapter.ProviderPort() {
            public String mode() { return "LIVE"; }
            public Map<String, Object> evaluate(VirtualKycJobAdapter.Delivery delivery, Map<String, Object> input) { return null; }
        }));
        UUID action = f.id();
        assertThrows(SimulationFailure.class, () -> new VirtualKycJobAdapter.Delivery(action, action, f.id()));
    }

    @Test void prepareDenialNeverCallsProviderAndReturnsItsBoundReceipt() {
        var f = new SimulationFixture(); UUID workflow = f.start(); f.quarantine(workflow);
        var calls = new AtomicInteger(); var delivery = delivery(f, workflow);
        var adapter = adapter(f, provider(input -> { calls.incrementAndGet(); return response(input); }));
        var receipt = adapter.run(ACTOR, delivery);
        assertEquals(0, calls.get()); assertEquals(delivery.prepareAction().toString(), receipt.get("requestId"));
        assertEquals("DENY", receipt.get("decision")); assertFalse(receipt.containsKey("input"));
        assertEquals(0, f.rows(RESULTS));
    }

    @Test void completedDeliveryReplaysStoredObservationWithoutCallingProviderTwice() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        var calls = new AtomicInteger();
        var adapter = adapter(f, provider(input -> {
            calls.incrementAndGet();
            assertThrows(UnsupportedOperationException.class, () -> input.put("customerId", "synthetic-replaced"));
            return response(input);
        }));
        var first = adapter.run(ACTOR, delivery); var second = adapter.run(ACTOR, delivery);
        assertEquals("WAIT_APPROVAL", first.get("state")); assertEquals(false, first.get("replayed"));
        assertEquals(true, second.get("replayed")); assertEquals(1, calls.get());
        assertEquals(2, f.rows(RUNS)); assertEquals(2, f.rows(RESULTS));
        assertEquals(1, f.workflows.get(ACTOR, workflow).get("kycRuns"));
    }

    @Test void responseCacheContainsOnlyFixedSyntheticMetadataAndNoInputDocuments() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        var receipt = adapter(f, provider(this::response)).run(ACTOR, delivery);
        Map<String, Object> cached = f.store.snapshot().get(VirtualKycJobAdapter.TABLE).get(delivery.prepareAction().toString());
        assertEquals("RESPONDED", cached.get("phase")); assertFalse(cached.containsKey("input"));
        assertFalse(cached.toString().contains(MODEL_MARKER)); assertFalse(cached.toString().contains(EXPLANATION_MARKER));
        assertFalse(cached.toString().contains("synthetic source 한글")); assertFalse(receipt.containsKey("input"));
        assertFalse(f.workflows.trace(ACTOR, workflow).toString().contains(MODEL_MARKER));
    }

    @Test void replayRechecksCurrentKycAuthorityBeforeAccessingCachedResponse() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        var calls = new AtomicInteger(); var adapter = adapter(f, provider(input -> { calls.incrementAndGet(); return response(input); }));
        adapter.run(ACTOR, delivery); var before = f.store.snapshot(); f.permitted.set(false);
        assertEquals(403, assertThrows(SimulationFailure.class, () -> adapter.run(ACTOR, delivery)).status());
        assertEquals(1, calls.get()); assertEquals(before, f.store.snapshot());
        f.permitted.set(true); assertEquals(true, adapter.run(ACTOR, delivery).get("replayed")); assertEquals(1, calls.get());
    }

    @Test void providerFailureIsFixedAndSamePreparedRunCanRetry() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        var calls = new AtomicInteger();
        var adapter = adapter(f, provider(input -> {
            if (calls.incrementAndGet() == 1) throw new IllegalStateException(EXPLANATION_MARKER);
            return response(input);
        }));
        var unavailable = assertThrows(SimulationFailure.class, () -> adapter.run(ACTOR, delivery));
        assertEquals(503, unavailable.status()); assertEquals("DEPENDENCY_UNAVAILABLE", unavailable.getMessage()); assertNull(unavailable.getCause());
        assertEquals(1, f.rows(RUNS)); assertEquals(0, f.rows(RESULTS));
        assertEquals("RETRYABLE", f.store.snapshot().get(VirtualKycJobAdapter.TABLE).get(delivery.prepareAction().toString()).get("phase"));
        assertTrue(f.store.snapshot().get(JOBS).values().stream().anyMatch(job -> "RUNNING".equals(job.get("state"))));
        assertEquals("WAIT_APPROVAL", adapter.run(ACTOR, delivery).get("state"));
        assertEquals(2, calls.get()); assertEquals(2, f.rows(RUNS)); assertEquals(1, f.workflows.get(ACTOR, workflow).get("kycRuns"));
    }

    @Test void terminatedProviderErrorReleasesClaimAndCachedSuccessIsNotEvaluatedAgain() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        var calls = new AtomicInteger(); var fatal = new AssertionError("synthetic evaluation terminated");
        var adapter = adapter(f, provider(input -> {
            if (calls.incrementAndGet() == 1) throw fatal;
            return response(input);
        }));
        assertSame(fatal, assertThrows(AssertionError.class, () -> adapter.run(ACTOR, delivery)));
        assertEquals("RETRYABLE", f.store.snapshot().get(VirtualKycJobAdapter.TABLE)
                .get(delivery.prepareAction().toString()).get("phase"));
        assertEquals(0, f.rows(RESULTS)); assertEquals(1, f.rows(RUNS));
        assertEquals("WAIT_APPROVAL", adapter.run(ACTOR, delivery).get("state"));
        assertEquals("RESPONDED", f.store.snapshot().get(VirtualKycJobAdapter.TABLE)
                .get(delivery.prepareAction().toString()).get("phase"));
        var completed = f.store.snapshot();
        assertEquals(true, adapter.run(ACTOR, delivery).get("replayed"));
        assertEquals(2, calls.get()); assertEquals(completed, f.store.snapshot());
        assertEquals(1, f.workflows.get(ACTOR, workflow).get("kycRuns"));
        assertEquals(0, f.rows(PAYMENTS));
    }

    @Test void malformedResponseIsNotCachedAndRetryCanUseValidResponse() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        var calls = new AtomicInteger();
        var adapter = adapter(f, provider(input -> {
            var output = new LinkedHashMap<>(response(input));
            if (calls.incrementAndGet() == 1) output.put("allowPayment", true);
            return output;
        }));
        assertEquals(400, assertThrows(SimulationFailure.class, () -> adapter.run(ACTOR, delivery)).status());
        assertEquals(0, f.rows(RESULTS));
        assertEquals("WAIT_APPROVAL", adapter.run(ACTOR, delivery).get("state"));
        assertEquals(2, calls.get()); assertEquals(2, f.rows(RESULTS));
    }

    @Test void wrongCorrelationIsRejectedBeforeResponseCacheAndMayRetry() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        var calls = new AtomicInteger();
        var adapter = adapter(f, provider(input -> {
            var output = new LinkedHashMap<>(response(input));
            if (calls.incrementAndGet() == 1) output.put("workflowId", new UUID(9, 9).toString());
            return output;
        }));
        assertEquals(400, assertThrows(SimulationFailure.class, () -> adapter.run(ACTOR, delivery)).status());
        assertEquals(0, f.rows(RESULTS));
        assertEquals("WAIT_APPROVAL", adapter.run(ACTOR, delivery).get("state")); assertEquals(2, calls.get());
    }

    @Test void preparedInputThatBecameContainedIsSkippedBeforeNewProviderCall() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        new VirtualAgentBridge(f.workflows).prepare(ACTOR, delivery.prepareAction(), workflow);
        f.quarantine(workflow);
        var calls = new AtomicInteger(); var adapter = adapter(f, provider(input -> { calls.incrementAndGet(); return response(input); }));
        var first = adapter.run(ACTOR, delivery); var second = adapter.run(ACTOR, delivery);
        assertEquals(0, calls.get()); assertEquals(delivery.observationAction().toString(), first.get("requestId"));
        assertEquals("DENY", first.get("decision")); assertEquals(List.of("LATE_RESULT_DISCARDED"), first.get("reasonCodes"));
        assertEquals(true, second.get("replayed")); assertEquals(0, f.rows(RESULTS));
    }

    @Test void previousGenerationPreparedInputCannotDispatchAgainstNewJob() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        @SuppressWarnings("unchecked") var input = (Map<String, Object>) new VirtualAgentBridge(f.workflows)
                .prepare(ACTOR, delivery.prepareAction(), workflow).get("input");
        f.workflows.observeKyc(ACTOR, f.id(), f.observation(input, List.of(ID_FACT)));
        f.workflows.resume(new WorkflowResumeBoundary.Command(ACTOR, f.id(), workflow,
                new WorkflowResumeBoundary.Request(1, "synthetic explicit recovery")));
        var calls = new AtomicInteger(); var adapter = adapter(f, provider(value -> { calls.incrementAndGet(); return response(value); }));
        var result = adapter.run(ACTOR, delivery);
        assertEquals(0, calls.get()); assertEquals("DENY", result.get("decision"));
        assertEquals(2, f.workflows.get(ACTOR, workflow).get("generation"));
        assertEquals("KYC_PENDING", f.workflows.get(ACTOR, workflow).get("state"));
    }

    @Test void faultInjectedContainmentAfterDispatchStillDiscardsLateResponse() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow); var calls = new AtomicInteger();
        var adapter = adapter(f, provider(input -> {
            calls.incrementAndGet();
            // Fault injection represents an intervening operator action, not a supported provider side effect.
            f.quarantine(workflow);
            return response(input);
        }));
        var result = adapter.run(ACTOR, delivery);
        assertEquals("DENY", result.get("decision")); assertEquals(List.of("LATE_RESULT_DISCARDED"), result.get("reasonCodes"));
        assertEquals(0, f.rows(RESULTS)); assertEquals(true, adapter.run(ACTOR, delivery).get("replayed")); assertEquals(1, calls.get());
    }

    @Test void responseRemainsCachedWhenAuthorityIsRevokedBeforeAcceptance() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow); var calls = new AtomicInteger();
        var adapter = adapter(f, provider(input -> {
            calls.incrementAndGet(); f.permitted.set(false); return response(input);
        }));
        assertEquals(403, assertThrows(SimulationFailure.class, () -> adapter.run(ACTOR, delivery)).status());
        assertEquals(0, f.rows(RESULTS));
        var cachedWithoutAuthority = f.store.snapshot();
        assertEquals("RESPONDED", cachedWithoutAuthority.get(VirtualKycJobAdapter.TABLE)
                .get(delivery.prepareAction().toString()).get("phase"));
        assertEquals(403, assertThrows(SimulationFailure.class, () -> adapter.run(ACTOR, delivery)).status());
        assertEquals(cachedWithoutAuthority, f.store.snapshot()); assertEquals(1, calls.get());
        f.permitted.set(true);
        assertEquals("WAIT_APPROVAL", adapter.run(ACTOR, delivery).get("state"));
        assertEquals(1, calls.get()); assertEquals(2, f.rows(RESULTS));
    }

    @Test void changingObservationActionForSamePrepareConflictsWithoutProviderCall() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow); var calls = new AtomicInteger();
        var adapter = adapter(f, provider(input -> { calls.incrementAndGet(); return response(input); }));
        adapter.run(ACTOR, delivery);
        var changed = new VirtualKycJobAdapter.Delivery(delivery.prepareAction(), f.id(), workflow);
        assertEquals(400, assertThrows(SimulationFailure.class, () -> adapter.run(ACTOR, changed)).status());
        assertEquals(1, calls.get()); assertEquals(2, f.rows(RESULTS));
    }

    @Test void anotherActorCannotReuseActionToReadCachedObservation() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow); var calls = new AtomicInteger();
        var adapter = adapter(f, provider(input -> { calls.incrementAndGet(); return response(input); }));
        adapter.run(ACTOR, delivery);
        assertEquals(400, assertThrows(SimulationFailure.class, () -> adapter.run(new ActorRef("synthetic-other"), delivery)).status());
        assertEquals(1, calls.get()); assertEquals(2, f.rows(RESULTS));
    }

    @Test void secondAdapterInstanceSharesResponseCacheAndNeverEvaluatesAgain() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        adapter(f, provider(this::response)).run(ACTOR, delivery);
        var calls = new AtomicInteger(); var second = adapter(f, provider(input -> { calls.incrementAndGet(); return response(input); }));
        assertEquals(true, second.run(ACTOR, delivery).get("replayed")); assertEquals(0, calls.get()); assertEquals(2, f.rows(RESULTS));
    }

    @Test void inFlightClaimDefensivelyRejectsReentrantDuplicateWithoutEvaluatingAgain() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow); var calls = new AtomicInteger();
        var reference = new AtomicReference<VirtualKycJobAdapter>();
        var adapter = adapter(f, provider(input -> {
            calls.incrementAndGet();
            assertEquals(503, assertThrows(SimulationFailure.class, () -> reference.get().run(ACTOR, delivery)).status());
            return response(input);
        }));
        reference.set(adapter);
        assertEquals("WAIT_APPROVAL", adapter.run(ACTOR, delivery).get("state")); assertEquals(1, calls.get());
    }
    @Test void unknownLargeRootIsRejectedWithoutTraversingOrCopyingIt() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        Map<String, Object> excessive = new java.util.AbstractMap<>() {
            @Override public int size() { return 8; }
            @Override public java.util.Set<Map.Entry<String, Object>> entrySet() {
                throw new AssertionError("Unknown provider tree must not be traversed");
            }
        };
        var adapter = adapter(f, provider(input -> excessive));
        assertEquals(400, assertThrows(SimulationFailure.class, () -> adapter.run(ACTOR, delivery)).status());
        assertEquals(0, f.rows(RESULTS));
    }

    @Test void unknownNestedFieldsAreRejectedWithoutTraversingTheirValues() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        var adapter = adapter(f, provider(input -> {
            Map<String, Object> nested = new java.util.AbstractMap<>() {
                @Override public int size() { return 4; }
                @Override public java.util.Set<Map.Entry<String, Object>> entrySet() {
                    throw new AssertionError("Unknown nested provider tree must not be traversed");
                }
            };
            var raw = new LinkedHashMap<>(response(input)); raw.put("proposal", nested); return raw;
        }));
        assertEquals(400, assertThrows(SimulationFailure.class, () -> adapter.run(ACTOR, delivery)).status());
        assertEquals(0, f.rows(RESULTS));
    }

    @Test void excessiveEvidenceCountIsRejectedWithoutReadingElements() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        var adapter = adapter(f, provider(input -> {
            List<Object> excessive = new java.util.AbstractList<>() {
                @Override public int size() { return Integer.MAX_VALUE; }
                @Override public Object get(int index) { throw new AssertionError("Excessive provider list must not be read"); }
            };
            var raw = new LinkedHashMap<>(response(input));
            var proposal = new LinkedHashMap<String, Object>(Map.of("status", "VERIFIED", "explanation", "synthetic"));
            proposal.put("evidenceIds", excessive); raw.put("proposal", proposal); return raw;
        }));
        assertEquals(400, assertThrows(SimulationFailure.class, () -> adapter.run(ACTOR, delivery)).status());
        assertEquals(0, f.rows(RESULTS));
    }

    @Test void publicUnicodeCodePointMaximaAreAcceptedWithoutKeepingProviderText() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        var adapter = adapter(f, provider(input -> {
            var raw = new LinkedHashMap<>(response(input));
            raw.put("modelMetadata", object("model", "🧪".repeat(160), "promptVersion", "KYC-PROMPT-1"));
            raw.put("proposal", object("status", "VERIFIED", "evidenceIds", List.of(ID_FACT.toString(), FACE_FACT.toString()),
                    "explanation", "🧪".repeat(2000)));
            return raw;
        }));
        assertEquals("WAIT_APPROVAL", adapter.run(ACTOR, delivery).get("state"));
        assertFalse(f.store.snapshot().get(VirtualKycJobAdapter.TABLE).toString().contains("🧪"));
    }

    @Test void providerModeChangeFailsWithoutEvaluationAndWithoutFallback() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        var virtual = new java.util.concurrent.atomic.AtomicBoolean(true); var calls = new AtomicInteger();
        var adapter = adapter(f, new VirtualKycJobAdapter.ProviderPort() {
            @Override public String mode() { return virtual.get() ? "VIRTUAL_NON_DURABLE" : "LIVE"; }
            @Override public Map<String, Object> evaluate(VirtualKycJobAdapter.Delivery key, Map<String, Object> input) {
                calls.incrementAndGet(); return response(input);
            }
        });
        virtual.set(false);
        assertEquals(503, assertThrows(SimulationFailure.class, () -> adapter.run(ACTOR, delivery)).status());
        assertEquals(0, calls.get()); assertEquals(0, f.rows(RESULTS));
    }

    @Test void modeChangeDuringEvaluationCannotCacheOrCompleteAndCanRetry() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        var virtual = new java.util.concurrent.atomic.AtomicBoolean(true); var calls = new AtomicInteger();
        var adapter = adapter(f, new VirtualKycJobAdapter.ProviderPort() {
            @Override public String mode() { return virtual.get() ? "VIRTUAL_NON_DURABLE" : "LIVE"; }
            @Override public Map<String, Object> evaluate(VirtualKycJobAdapter.Delivery key, Map<String, Object> input) {
                if (calls.incrementAndGet() == 1) virtual.set(false);
                return response(input);
            }
        });
        var failure = assertThrows(SimulationFailure.class, () -> adapter.run(ACTOR, delivery));
        assertEquals(503, failure.status()); assertEquals("DEPENDENCY_UNAVAILABLE", failure.getMessage());
        assertNull(failure.getCause()); assertEquals(1, calls.get()); assertEquals(0, f.rows(RESULTS));
        var saved = f.store.snapshot().get(VirtualKycJobAdapter.TABLE).get(delivery.prepareAction().toString());
        assertEquals("RETRYABLE", saved.get("phase")); assertFalse(saved.containsKey("response"));
        assertEquals("KYC_PENDING", f.workflows.get(ACTOR, workflow).get("state"));
        virtual.set(true);
        assertEquals("WAIT_APPROVAL", adapter.run(ACTOR, delivery).get("state"));
        assertEquals(2, calls.get());
    }

    @Test void postEvaluationModeFailureUsesFixedErrorAndReleasesClaim() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        var evaluated = new java.util.concurrent.atomic.AtomicBoolean(false);
        var adapter = adapter(f, new VirtualKycJobAdapter.ProviderPort() {
            @Override public String mode() {
                if (evaluated.get()) throw new IllegalStateException(EXPLANATION_MARKER);
                return "VIRTUAL_NON_DURABLE";
            }
            @Override public Map<String, Object> evaluate(VirtualKycJobAdapter.Delivery key, Map<String, Object> input) {
                evaluated.set(true); return response(input);
            }
        });
        var failure = assertThrows(SimulationFailure.class, () -> adapter.run(ACTOR, delivery));
        assertEquals(503, failure.status()); assertEquals("DEPENDENCY_UNAVAILABLE", failure.getMessage());
        assertNull(failure.getCause()); assertEquals(0, f.rows(RESULTS));
        var saved = f.store.snapshot().get(VirtualKycJobAdapter.TABLE).get(delivery.prepareAction().toString());
        assertEquals("RETRYABLE", saved.get("phase")); assertFalse(saved.containsKey("response"));
    }

    @Test void inconsistentPreparedRunHashIsSkippedWithoutProviderEvaluation() {
        var f = new SimulationFixture(); UUID workflow = f.start(); var delivery = delivery(f, workflow);
        new VirtualAgentBridge(f.workflows).prepare(ACTOR, delivery.prepareAction(), workflow);
        f.store.transaction(tx -> {
            var stored = tx.rows(RUNS).entrySet().iterator().next();
            var changed = new LinkedHashMap<>(stored.getValue()); changed.put("inputSnapshotHash", "0".repeat(64));
            tx.put(RUNS, stored.getKey(), changed); return null;
        });
        var calls = new AtomicInteger(); var adapter = adapter(f, provider(input -> { calls.incrementAndGet(); return response(input); }));
        assertEquals("DENY", adapter.run(ACTOR, delivery).get("decision")); assertEquals(0, calls.get()); assertEquals(0, f.rows(RESULTS));
    }
}
