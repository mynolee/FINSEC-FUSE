package com.finsec.fuse.reimplementation.simulation;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.time.Clock;
import java.time.Instant;

/**
 * Typed adapter for caller-decoded synthetic-contract-boundaries-v2 data only.
 * Accepts a caller-trusted Map produced by the caller's strict, bounded JSON
 * decoder; this class neither verifies that decoding nor accepts arbitrary
 * provider object graphs. It opens no file, stream,
 * service, model or registry. New test seed becomes virtual catalog data only,
 * never verified real evidence or authority.
 */
public final class SyntheticContractFixtureAdapter {
    private SyntheticContractFixtureAdapter() {}
    public record Evidence(UUID evidenceId, String customerId, SimulationSpec.Kind kind,
                           SimulationSpec.Outcome result) {}
    public record Example(String caseId, String customerId, List<UUID> suppliedEvidenceIds,
                          SimulationSpec.KycStatus status, List<UUID> selectedEvidenceIds,
                          String expectedState, String expectedDecision, String expectedReason) {
        public Example { suppliedEvidenceIds = List.copyOf(suppliedEvidenceIds); selectedEvidenceIds = List.copyOf(selectedEvidenceIds); }
    }
    public record Seed(Instant observationTime, SimulationSpec.Source source,
                       List<SimulationSpec.Application> applications, List<SimulationSpec.Fact> evidence) {
        public Seed { applications = List.copyOf(applications); evidence = List.copyOf(evidence); }
    }
    public record Fixture(List<Evidence> evidenceDeclarations, List<Example> examples, Seed seed) {
        public Fixture { evidenceDeclarations = List.copyOf(evidenceDeclarations); examples = List.copyOf(examples); }
    }

    /** Exact v2 metadata, three examples and three evidence declarations; no runtime policy is imported. */
    public static Fixture adapt(Map<String, Object> decoded) {
        closed(decoded, Set.of("fixtureSetId", "synthetic", "reimplementationStatus", "purpose", "backendConnected",
                "automaticallyRegistered", "measuredResultsIncluded", "limitations", "contractPreconditions", "syntheticEvidenceCatalog", "cases", "syntheticSeed", "backendConnectionStatus"));
        if (!"synthetic-contract-boundaries-v2".equals(decoded.get("fixtureSetId"))
                || !Boolean.TRUE.equals(decoded.get("synthetic"))
                || !"NEW_SYNTHETIC_CONTRACT_DATA".equals(decoded.get("reimplementationStatus"))
                || !Boolean.FALSE.equals(decoded.get("backendConnected"))
                || !"EXPLICIT_SEED_DATA_ONLY_RUNTIME_NOT_EXECUTED".equals(decoded.get("backendConnectionStatus"))
                || !Boolean.FALSE.equals(decoded.get("automaticallyRegistered"))
                || !Boolean.FALSE.equals(decoded.get("measuredResultsIncluded"))) throw invalid();
        text(decoded, "purpose"); texts(decoded.get("limitations")); texts(decoded.get("contractPreconditions"));
        List<Evidence> evidence = rows(decoded.get("syntheticEvidenceCatalog"), 3).stream().map(row -> {
            closed(row, Set.of("evidenceId", "customerId", "kind", "result", "activeAndUsableAtObservation"));
            if (!Boolean.TRUE.equals(row.get("activeAndUsableAtObservation"))) throw invalid();
            String customer = text(row, "customerId"); SimulationSpec.synthetic(customer);
            return new Evidence(uuid(row.get("evidenceId")), customer, SimulationSpec.Kind.valueOf(text(row, "kind")),
                    SimulationSpec.Outcome.valueOf(text(row, "result")));
        }).toList();
        if (evidence.stream().map(Evidence::evidenceId).distinct().count() != 3) throw invalid();
        Set<UUID> known = Set.copyOf(evidence.stream().map(Evidence::evidenceId).toList());
        List<Example> examples = rows(decoded.get("cases"), 3).stream().map(row -> {
            Set<String> required = Set.of("caseId", "kind", "split", "family", "customerId", "suppliedEvidenceIds", "modelOutput", "expected", "contractSource");
            var allowed = new java.util.HashSet<>(required); allowed.add("description");
            if (!row.keySet().containsAll(required) || !allowed.containsAll(row.keySet())) throw invalid();
            String id = text(row, "caseId"), customer = text(row, "customerId");
            SimulationSpec.synthetic(id); SimulationSpec.synthetic(customer);
            if (!Set.of("NORMAL", "ATTACK").contains(text(row, "kind"))
                    || !Set.of("NORMAL", "DEV").contains(text(row, "split"))
                    || !"SYNTHETIC_KYC_CONTRACT".equals(text(row, "family"))) throw invalid();
            text(row, "contractSource"); if (row.containsKey("description")) text(row, "description");
            Map<String, Object> proposal = object(row.get("modelOutput"));
            closed(proposal, Set.of("status", "evidenceIds", "explanation")); text(proposal, "explanation");
            Map<String, Object> expected = object(row.get("expected")); closed(expected, Set.of("FUSE"));
            Map<String, Object> fuse = object(expected.get("FUSE"));
            closed(fuse, Set.of("state", "decision", "reasonCode", "forbiddenPaymentCount"));
            Object count = fuse.get("forbiddenPaymentCount");
            if (!(count instanceof Number number) || !"0".equals(number.toString())) throw invalid();
            String state = text(fuse, "state"), decision = text(fuse, "decision"), reason = text(fuse, "reasonCode");
            if (!("WAIT_APPROVAL".equals(state) && "WAIT_APPROVAL".equals(decision) && "HUMAN_APPROVAL_REQUIRED".equals(reason))
                    && !("BLOCKED".equals(state) && "DENY".equals(decision) && "KYC_EVIDENCE_REJECTED".equals(reason))) throw invalid();
            List<UUID> supplied = ids(row.get("suppliedEvidenceIds")), selected = ids(proposal.get("evidenceIds"));
            if (!known.containsAll(supplied) || !known.containsAll(selected)) throw invalid();
            return new Example(id, customer, supplied, SimulationSpec.KycStatus.valueOf(text(proposal, "status")), selected, state, decision, reason);
        }).toList();
        if (examples.stream().map(Example::caseId).distinct().count() != 3) throw invalid();
        return new Fixture(evidence, examples, seed(object(decoded.get("syntheticSeed")), evidence, examples));
    }

    /**
     * Catalog only; the caller supplies Clock explicitly, matching reference time
     * metadata rather than creating a default clock. Risk, authority, IDs and
     * service composition remain explicit caller responsibilities.
     */
    public static SimulationSpec.Catalog catalog(Fixture fixture, Clock callerClock) {
        if (fixture == null || callerClock == null || !callerClock.instant().equals(fixture.seed().observationTime())) throw invalid();
        if (fixture.seed().evidence().stream().anyMatch(fact -> !fact.usable(callerClock.instant()))) throw invalid();
        return new SimulationSpec.Catalog(fixture.seed().applications(), fixture.seed().evidence());
    }

    private static Seed seed(Map<String, Object> seed, List<Evidence> declarations, List<Example> examples) {
        closed(seed, Set.of("dataStatus", "observationTime", "source", "applications", "evidence"));
        if (!"NEW_TEST_DATA".equals(seed.get("dataStatus"))) throw invalid();
        Instant time = Instant.parse(text(seed, "observationTime"));
        Map<String, Object> source = object(seed.get("source"));
        closed(source, Set.of("documentId", "documentVersion", "text", "contentHash", "reviewedSafe"));
        if (!Boolean.TRUE.equals(source.get("reviewedSafe"))) throw invalid();
        var typedSource = new SimulationSpec.Source(uuid(source.get("documentId")), integer(source, "documentVersion"),
                text(source, "text"), text(source, "contentHash"), true);
        List<SimulationSpec.Application> applications = rows(seed.get("applications"), 3).stream().map(row -> {
            closed(row, Set.of("caseId", "businessReference", "amountKrw", "payoutAccountId", "monthlyIncomeKrw", "maxLoanAmountKrw", "ownsActiveAccount"));
            String id = text(row, "caseId");
            Example example = examples.stream().filter(value -> value.caseId().equals(id)).findFirst().orElseThrow(SyntheticContractFixtureAdapter::invalid);
            if (!(row.get("ownsActiveAccount") instanceof Boolean owns)) throw invalid();
            return new SimulationSpec.Application(id, text(row, "businessReference"), example.customerId(),
                    exactLong(row, "amountKrw"), uuid(row.get("payoutAccountId")), exactLong(row, "monthlyIncomeKrw"),
                    exactLong(row, "maxLoanAmountKrw"), owns, typedSource);
        }).toList();
        if (applications.stream().map(SimulationSpec.Application::fixtureId).distinct().count() != 3) throw invalid();
        List<SimulationSpec.Fact> facts = rows(seed.get("evidence"), 3).stream().map(row -> {
            closed(row, Set.of("evidenceId", "customerId", "kind", "result", "active", "issuedAt", "expiresAt"));
            UUID id = uuid(row.get("evidenceId"));
            Evidence declaration = declarations.stream().filter(value -> value.evidenceId().equals(id)).findFirst().orElseThrow(SyntheticContractFixtureAdapter::invalid);
            if (!declaration.customerId().equals(text(row, "customerId"))
                    || !declaration.kind().name().equals(text(row, "kind"))
                    || !declaration.result().name().equals(text(row, "result")) || !Boolean.TRUE.equals(row.get("active"))) throw invalid();
            return new SimulationSpec.Fact(id, declaration.customerId(), declaration.kind(), declaration.result(), true,
                    Instant.parse(text(row, "issuedAt")), Instant.parse(text(row, "expiresAt")));
        }).toList();
        if (facts.stream().map(SimulationSpec.Fact::evidenceId).distinct().count() != 3
                || facts.stream().anyMatch(fact -> !fact.usable(time))) throw invalid();
        return new Seed(time, typedSource, applications, facts);
    }

    private static int integer(Map<String, Object> row, String key) {
        if (!(row.get(key) instanceof Integer value) || value < 1) throw invalid(); return value;
    }
    private static long exactLong(Map<String, Object> row, String key) {
        Object value = row.get(key); if (value instanceof Integer number) return number.longValue();
        if (value instanceof Long number) return number; throw invalid();
    }

    /** Binds an example only to caller-supplied prepared input, never fabricating request/run IDs. */
    public static SimulationSpec.Observation observation(Example example, Map<String, Object> preparedInput) {
        if (example == null || preparedInput == null || !example.customerId().equals(preparedInput.get("customerId"))) throw invalid();
        List<UUID> supplied = rowsUpTo(preparedInput.get("evidenceFacts"), 10).stream().map(row -> uuid(row.get("evidenceId"))).toList();
        if (supplied.size() != example.suppliedEvidenceIds().size()
                || !Set.copyOf(supplied).equals(Set.copyOf(example.suppliedEvidenceIds()))) throw invalid();
        if (!(preparedInput.get("generation") instanceof Integer generation)) throw invalid();
        return new SimulationSpec.Observation(uuid(preparedInput.get("requestId")), uuid(preparedInput.get("workflowId")),
                generation, uuid(preparedInput.get("runId")), text(preparedInput, "inputSnapshotHash"), example.status(), example.selectedEvidenceIds());
    }

    private static List<UUID> ids(Object value) {
        List<String> texts = texts(value); if (texts.size() > 10) throw invalid();
        List<UUID> ids = texts.stream().map(SyntheticContractFixtureAdapter::uuid).toList();
        if (ids.stream().distinct().count() != ids.size()) throw invalid(); return ids;
    }
    private static UUID uuid(Object value) {
        if (!(value instanceof String text) || !text.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) throw invalid();
        return UUID.fromString(text);
    }
    private static String text(Map<String, Object> value, String key) {
        if (!(value.get(key) instanceof String text) || text.isBlank() || text.length() > 2000) throw invalid(); return text;
    }
    private static List<String> texts(Object value) {
        if (!(value instanceof List<?> list) || list.size() > 16) throw invalid();
        return list.stream().map(item -> { if (!(item instanceof String text) || text.length() > 2000) throw invalid(); return text; }).toList();
    }
    private static List<Map<String, Object>> rows(Object value, int size) {
        List<Map<String, Object>> rows = rowsUpTo(value, size); if (rows.size() != size) throw invalid(); return rows;
    }
    private static List<Map<String, Object>> rowsUpTo(Object value, int maximum) {
        if (!(value instanceof List<?> rows) || rows.size() > maximum) throw invalid();
        return rows.stream().map(SyntheticContractFixtureAdapter::object).toList();
    }
    @SuppressWarnings("unchecked") private static Map<String, Object> object(Object value) {
        if (!(value instanceof Map<?, ?> map) || map.keySet().stream().anyMatch(key -> !(key instanceof String))) throw invalid();
        return (Map<String, Object>) map;
    }
    private static void closed(Map<String, Object> value, Set<String> keys) { if (value == null || !value.keySet().equals(keys)) throw invalid(); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid synthetic contract fixture"); }
}
