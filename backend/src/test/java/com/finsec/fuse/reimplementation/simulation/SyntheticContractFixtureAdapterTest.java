package com.finsec.fuse.reimplementation.simulation;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;

/**
 * Trusted fixed synthetic fixture consumption assertions only; this parser does
 * not verify strict duplicate-key admission, bounded stream decoding, a provider
 * JSON decoder end-to-end path, or any runtime result. Inline-map synthetic
 * provider/adapter/bridge composition assertions below remain unexecuted.
 */
final class SyntheticContractFixtureAdapterTest {
    @SuppressWarnings("unchecked")
    private Map<String, Object> decoded() throws Exception {
        // Explicit public test input; backend is the selected unit task working directory.
        byte[] bytes = Files.readAllBytes(Path.of("../evaluation/fixtures/synthetic-contract-boundaries-v2.json"));
        assertTrue(bytes.length <= 32768, "Explicit synthetic test input budget, not an operating default");
        return JsonMapper.builder().build().readValue(bytes, Map.class);
    }
    private Map<String, Object> prepared(SyntheticContractFixtureAdapter.Example example) {
        return object("requestId", new UUID(0, 101).toString(), "workflowId", new UUID(0, 102).toString(),
                "generation", 1, "runId", new UUID(0, 103).toString(), "inputSnapshotHash", "a".repeat(64),
                "customerId", example.customerId(), "evidenceFacts", example.suppliedEvidenceIds().stream()
                        .map(id -> object("evidenceId", id.toString())).toList());
    }

    @Test void consumesThreeExplicitJsonExamplesWithoutCreatingAuthorityOrRegistry() throws Exception {
        var fixture = SyntheticContractFixtureAdapter.adapt(decoded());
        assertEquals(3, fixture.evidenceDeclarations().size()); assertEquals(3, fixture.examples().size());
        assertEquals(List.of("WAIT_APPROVAL", "BLOCKED", "BLOCKED"), fixture.examples().stream()
                .map(SyntheticContractFixtureAdapter.Example::expectedState).toList());
        assertEquals(List.of(2, 1, 2), fixture.examples().stream().map(example -> example.selectedEvidenceIds().size()).toList());
        for (var example : fixture.examples()) {
            var observation = SyntheticContractFixtureAdapter.observation(example, prepared(example));
            assertEquals(example.selectedEvidenceIds(), observation.evidenceIds());
            assertEquals(new UUID(0, 103), observation.runId()); assertEquals(1, observation.generation());
        }
        // The foreign/unsupplied conjunction is retained, never rewritten into an isolated claim.
        var foreign = fixture.examples().get(2);
        assertFalse(foreign.suppliedEvidenceIds().contains(foreign.selectedEvidenceIds().get(1)));
        assertThrows(UnsupportedOperationException.class, () -> foreign.selectedEvidenceIds().clear());
    }

    @Test void refusesMisleadingRuntimeMetadataAndUnknownRootFields() throws Exception {
        for (String marker : List.of("backendConnected", "automaticallyRegistered", "measuredResultsIncluded")) {
            var document = decoded(); document.put(marker, true);
            assertThrows(IllegalArgumentException.class, () -> SyntheticContractFixtureAdapter.adapt(document));
        }
        var document = decoded(); document.put("authority", Map.of("allow", true));
        assertThrows(IllegalArgumentException.class, () -> SyntheticContractFixtureAdapter.adapt(document));
    }

    @Test void refusesWrongPreparedCustomerEvidenceAndGenerationRatherThanInventingCorrelation() throws Exception {
        var example = SyntheticContractFixtureAdapter.adapt(decoded()).examples().get(0);
        var customer = new LinkedHashMap<>(prepared(example)); customer.put("customerId", "synthetic-other-customer");
        assertThrows(IllegalArgumentException.class, () -> SyntheticContractFixtureAdapter.observation(example, customer));
        var evidence = new LinkedHashMap<>(prepared(example)); evidence.put("evidenceFacts", List.of());
        assertThrows(IllegalArgumentException.class, () -> SyntheticContractFixtureAdapter.observation(example, evidence));
        var generation = new LinkedHashMap<>(prepared(example)); generation.put("generation", 1L);
        assertThrows(IllegalArgumentException.class, () -> SyntheticContractFixtureAdapter.observation(example, generation));
        var unbound = new LinkedHashMap<>(prepared(example)); unbound.remove("runId");
        assertThrows(IllegalArgumentException.class, () -> SyntheticContractFixtureAdapter.observation(example, unbound));
    }

    @Test void callerExplicitVirtualCompositionConnectsAllThreeJsonExamplesToExistingService() throws Exception {
        var fixture = SyntheticContractFixtureAdapter.adapt(decoded());
        Clock callerClock = Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC);
        var catalog = SyntheticContractFixtureAdapter.catalog(fixture, callerClock);
        assertThrows(IllegalArgumentException.class, () -> SyntheticContractFixtureAdapter.catalog(fixture,
                Clock.fixed(Instant.parse("2030-01-01T00:00:01Z"), ZoneOffset.UTC)));
        for (var example : fixture.examples()) {
            var store = new VirtualTransactionalStore(); var sequence = new AtomicLong(1000);
            java.util.function.Supplier<UUID> ids = () -> new UUID(7, sequence.incrementAndGet());
            var actor = new WorkflowStartBoundary.ActorRef("synthetic-contract-reviewer");
            var authority = new SimulationAccess((subject, operation, workflow, customer) ->
                    actor.equals(subject) && example.customerId().equals(customer)
                            && Set.of(SimulationAccess.Operation.START, SimulationAccess.Operation.KYC_OBSERVATION,
                                    SimulationAccess.Operation.READ).contains(operation));
            var risk = new SimulationSpec.RiskTerms("SYNTHETIC-ADAPTER-TEST", 1, 2, 3, 3, 3, 2, Duration.ofMinutes(5));
            var workflows = new VirtualWorkflowService(store, catalog, risk, authority, callerClock, ids);
            var application = fixture.seed().applications().stream().filter(value -> value.fixtureId().equals(example.caseId())).findFirst().orElseThrow();
            UUID workflow = workflows.start(new WorkflowStartBoundary.Command(actor, ids.get(), application.request())).workflowId();
            @SuppressWarnings("unchecked") Map<String, Object> input = (Map<String, Object>) workflows.prepareKyc(actor, ids.get(), workflow).get("input");
            var receipt = workflows.observeKyc(actor, ids.get(), SyntheticContractFixtureAdapter.observation(example, input));
            assertEquals(example.expectedState(), receipt.get("state"));
            assertEquals(example.expectedDecision(), receipt.get("decision"));
            assertEquals(List.of(example.expectedReason()), receipt.get("reasonCodes"));
            assertFalse(store.snapshot().containsKey(VirtualWorkflowService.PAYMENTS));
            assertFalse(store.snapshot().containsKey(VirtualWorkflowService.APPROVALS));
        }
    }

    @Test void inlineSyntheticProviderAdapterBridgeComposesThreeCasesAndReplaysWithoutAnotherCall() throws Exception {
        var fixture = SyntheticContractFixtureAdapter.adapt(decoded());
        assertEquals(List.of("WAIT_APPROVAL", "BLOCKED", "BLOCKED"), fixture.examples().stream()
                .map(SyntheticContractFixtureAdapter.Example::expectedState).toList());
        Clock clock = Clock.fixed(fixture.seed().observationTime(), ZoneOffset.UTC);
        var catalog = SyntheticContractFixtureAdapter.catalog(fixture, clock);
        for (var example : fixture.examples()) {
            var store = new VirtualTransactionalStore(); var sequence = new AtomicLong(2000);
            java.util.function.Supplier<UUID> ids = () -> new UUID(8, sequence.incrementAndGet());
            var actor = new WorkflowStartBoundary.ActorRef("synthetic-composition-reviewer");
            var access = new SimulationAccess((subject, operation, workflowId, customer) ->
                    actor.equals(subject) && example.customerId().equals(customer)
                            && Set.of(SimulationAccess.Operation.START, SimulationAccess.Operation.KYC_OBSERVATION,
                                    SimulationAccess.Operation.READ).contains(operation));
            var terms = new SimulationSpec.RiskTerms("SYNTHETIC-COMPOSITION-TEST", 1, 2, 3,
                    3, 3, 2, Duration.ofMinutes(5));
            var workflows = new VirtualWorkflowService(store, catalog, terms, access, clock, ids);
            var application = fixture.seed().applications().stream()
                    .filter(value -> value.fixtureId().equals(example.caseId())).findFirst().orElseThrow();
            UUID workflow = workflows.start(new WorkflowStartBoundary.Command(actor, ids.get(), application.request())).workflowId();
            var delivery = new VirtualKycJobAdapter.Delivery(ids.get(), ids.get(), workflow);
            var calls = new AtomicLong();
            var provider = new VirtualKycJobAdapter.ProviderPort() {
                @Override public String mode() { return VirtualTransactionalStore.MODE; }
                @Override public Map<String, Object> evaluate(VirtualKycJobAdapter.Delivery current,
                                                              Map<String, Object> input) {
                    calls.incrementAndGet(); assertEquals(delivery, current);
                    assertEquals(delivery.prepareAction().toString(), input.get("requestId"));
                    assertEquals(workflow.toString(), input.get("workflowId"));
                    var observation = SyntheticContractFixtureAdapter.observation(example, input);
                    assertEquals(1, observation.generation());
                    assertNotNull(store.snapshot().get(VirtualWorkflowService.RUNS).get(observation.runId().toString()));
                    var unhashed = new LinkedHashMap<>(input); unhashed.remove("inputSnapshotHash");
                    assertEquals(com.finsec.fuse.reimplementation.persistence.CanonicalJson.orderedSha256(unhashed),
                            observation.inputSnapshotHash());
                    return object("requestId", input.get("requestId"), "workflowId", input.get("workflowId"),
                            "generation", input.get("generation"), "runId", input.get("runId"),
                            "inputSnapshotHash", input.get("inputSnapshotHash"),
                            "proposal", object("status", observation.status().name(),
                                    "evidenceIds", observation.evidenceIds().stream().map(UUID::toString).toList(),
                                    "explanation", "synthetic inline composition"),
                            "modelMetadata", object("model", "synthetic-inline", "promptVersion", "KYC-PROMPT-1"));
                }
            };
            var adapter = new VirtualKycJobAdapter(store, new VirtualAgentBridge(workflows), provider);
            var first = adapter.run(actor, delivery);
            assertEquals(example.expectedState(), first.get("state"));
            assertEquals(example.expectedDecision(), first.get("decision"));
            assertEquals(List.of(example.expectedReason()), first.get("reasonCodes"));
            assertEquals(delivery.observationAction().toString(), first.get("requestId"));
            assertEquals(false, first.get("replayed"));
            var afterFirst = store.snapshot();
            var replay = adapter.run(actor, delivery);
            assertEquals(true, replay.get("replayed")); assertEquals(first.get("state"), replay.get("state"));
            assertEquals(1L, calls.get()); assertEquals(afterFirst, store.snapshot());
            assertFalse(store.snapshot().containsKey(VirtualWorkflowService.PAYMENTS));
            assertFalse(store.snapshot().containsKey(VirtualWorkflowService.APPROVALS));
        }
    }

    @SuppressWarnings("unchecked")
    @Test void rejectsSeedEvidenceDeclarationMismatchAndInvalidDocumentHash() throws Exception {
        var document = decoded();
        var seed = (Map<String, Object>) document.get("syntheticSeed");
        var evidence = (List<Map<String, Object>>) seed.get("evidence");
        evidence.get(0).put("customerId", "synthetic-different-customer");
        assertThrows(IllegalArgumentException.class, () -> SyntheticContractFixtureAdapter.adapt(document));
        var other = decoded();
        var source = (Map<String, Object>) ((Map<String, Object>) other.get("syntheticSeed")).get("source");
        source.put("contentHash", "0".repeat(64));
        assertThrows(IllegalArgumentException.class, () -> SyntheticContractFixtureAdapter.adapt(other));
    }

    @SuppressWarnings("unchecked")
    @Test void expectedLabelsDoNotChangeCatalogOrPreparedObservation() throws Exception {
        var document = decoded();
        var original = SyntheticContractFixtureAdapter.adapt(document);
        var cases = (List<Map<String, Object>>) document.get("cases");
        var expected = (Map<String, Object>) cases.get(0).get("expected");
        expected.put("FUSE", new LinkedHashMap<>(Map.of("state", "BLOCKED", "decision", "DENY",
                "reasonCode", "KYC_EVIDENCE_REJECTED", "forbiddenPaymentCount", 0)));
        var relabeled = SyntheticContractFixtureAdapter.adapt(document);
        assertNotEquals(original.examples().get(0).expectedState(), relabeled.examples().get(0).expectedState());
        assertEquals(original.seed(), relabeled.seed());
        var input = prepared(original.examples().get(0));
        assertEquals(SyntheticContractFixtureAdapter.observation(original.examples().get(0), input),
                SyntheticContractFixtureAdapter.observation(relabeled.examples().get(0), input));
        assertEquals(original.examples().subList(1, 3), relabeled.examples().subList(1, 3));
    }

    @SuppressWarnings("unchecked")
    @Test void decodedMutationCannotChangeAdaptedCasesOrTheirFixedSource() throws Exception {
        var document = decoded();
        var fixture = SyntheticContractFixtureAdapter.adapt(document);
        var suppliedBefore = fixture.examples().stream()
                .map(example -> new java.util.ArrayList<>(example.suppliedEvidenceIds())).toList();
        var selectedBefore = fixture.examples().stream()
                .map(example -> new java.util.ArrayList<>(example.selectedEvidenceIds())).toList();
        var observationsBefore = fixture.examples().stream()
                .map(example -> SyntheticContractFixtureAdapter.observation(example, prepared(example))).toList();
        String sourceTextBefore = fixture.seed().source().text();
        String sourceHashBefore = fixture.seed().source().contentHash();
        var sourceIdBefore = fixture.seed().source().documentId();
        int sourceVersionBefore = fixture.seed().source().documentVersion();
        var cases = (List<Map<String, Object>>) document.get("cases");
        var proposal = (Map<String, Object>) cases.get(0).get("modelOutput");
        ((List<Object>) proposal.get("evidenceIds")).clear();
        proposal.put("status", "NOT_VERIFIED");
        ((List<Object>) cases.get(0).get("suppliedEvidenceIds")).clear();
        var seed = (Map<String, Object>) document.get("syntheticSeed");
        ((Map<String, Object>) seed.get("source")).put("text", "synthetic caller mutation");
        ((List<Object>) seed.get("applications")).clear();
        ((List<Object>) seed.get("evidence")).clear();
        assertEquals(3, fixture.examples().size());
        assertEquals(3, fixture.seed().applications().size());
        assertEquals(3, fixture.seed().evidence().size());
        assertEquals(sourceTextBefore, fixture.seed().source().text());
        assertEquals(sourceHashBefore, fixture.seed().source().contentHash());
        assertEquals(sourceIdBefore, fixture.seed().source().documentId());
        assertEquals(sourceVersionBefore, fixture.seed().source().documentVersion());
        var catalog = SyntheticContractFixtureAdapter.catalog(fixture,
                Clock.fixed(fixture.seed().observationTime(), ZoneOffset.UTC));
        for (var application : fixture.seed().applications()) {
            assertEquals(sourceTextBefore, application.source().text());
            assertEquals(sourceHashBefore, application.source().contentHash());
            assertEquals(sourceIdBefore, application.source().documentId());
            assertEquals(sourceVersionBefore, application.source().documentVersion());
            assertEquals(fixture.seed().source(), application.source());
            assertEquals(application, catalog.application(application.request()));
            assertEquals(fixture.seed().source(), catalog.source(application.source().documentId(),
                    application.source().documentVersion()));
        }
        for (int index = 0; index < fixture.examples().size(); index++) {
            var example = fixture.examples().get(index);
            assertEquals(suppliedBefore.get(index), example.suppliedEvidenceIds());
            assertEquals(selectedBefore.get(index), example.selectedEvidenceIds());
            assertEquals(observationsBefore.get(index), SyntheticContractFixtureAdapter.observation(example, prepared(example)));
        }
        assertThrows(UnsupportedOperationException.class, () -> fixture.seed().applications().clear());
        assertThrows(UnsupportedOperationException.class, () -> fixture.examples().get(0).suppliedEvidenceIds().clear());
    }
}
