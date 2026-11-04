package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import java.lang.reflect.RecordComponent;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantV2Codec.*;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.*;
import static org.junit.jupiter.api.Assertions.*;

/** Consistency of supplied synthetic snapshots does not establish their truth. */
final class SyntheticGrantStageBindingTest {
    private static UUID id(long n) { return new UUID(8, n); }
    private static Profile codecProfile() { return new Profile(16384, 8192, 8, 64, 1000, 300); }
    private static final String HASH = "a".repeat(64), INPUT = "b".repeat(64), EVIDENCE = "c".repeat(64);
    private static final byte[] BODY = "{}".getBytes(StandardCharsets.US_ASCII);
    private static String actionPayload(Action a) {
        var m = new LinkedHashMap<String, Object>();
        m.put("actionId", a.actionId().toString()); m.put("workflowId", a.workflowId().toString());
        m.put("generation", a.generation()); m.put("allowedAction", a.allowedAction().name());
        m.put("customerId", a.customerId()); m.put("amountKrw", a.amountKrw());
        m.put("payoutAccountId", a.payoutAccountId().toString()); m.put("targetRunId", a.targetRunId().toString());
        m.put("sourceResultId", a.sourceResultId() == null ? null : a.sourceResultId().toString());
        m.put("evidenceBundleHash", a.evidenceBundleHash());
        m.put("approvalId", a.approvalId() == null ? null : a.approvalId().toString());
        m.put("policyVersion", a.policyVersion());
        // Only the existing codec's action fingerprint; never a stage body hash proof.
        return CanonicalJson.sha256(m);
    }
    private static List<SyntheticGrantChainStructure.Node> chain(int depth) {
        var rows = new ArrayList<SyntheticGrantChainStructure.Node>();
        for (int d = 1; d <= depth; d++) {
            var action = switch (d) {
                case 1 -> GrantStorageShape.AllowedAction.EVALUATE_KYC;
                case 2 -> GrantStorageShape.AllowedAction.CREATE_LOAN_RECOMMENDATION;
                default -> GrantStorageShape.AllowedAction.EXECUTE_MOCK_PAYMENT;
            };
            var a = new Action(id(100 + d), id(1), 1, action, "synthetic-customer", 1000L,
                    id(2), id(200 + d), d == 1 ? null : id(300 + d), EVIDENCE,
                    d == 3 ? id(3) : null, "synthetic-policy");
            var c = new Claims("FUSE-GRANT-v2", "HMAC-SHA256", "synthetic-key", id(400 + d),
                    a.workflowId(), 1, id(4), "synthetic-principal", "synthetic-intent", "synthetic-issuer",
                    "synthetic-source", "synthetic-target", d == 1 ? null : id(200 + d - 1),
                    a.targetRunId(), a.allowedAction(), a.customerId(), a.amountKrw(), a.payoutAccountId(),
                    a.sourceResultId(), EVIDENCE, d == 1 ? null : id(400 + d - 1), d, a.actionId(),
                    actionPayload(a), a.policyVersion(), id(5), a.approvalId(), 100, 400);
            rows.add(new SyntheticGrantChainStructure.Node(c, a));
        }
        return rows;
    }
    private static final class Fixture {
        final List<SyntheticGrantChainStructure.Node> nodes;
        final BindingProfile profile = new BindingProfile(2);
        StageCommand command;
        RunSnapshot run;
        ResultSnapshot result;
        WorkflowSnapshot workflow;
        ExpectedResultBinding expected;
        Fixture(int depth) {
            nodes = chain(depth); var leaf = nodes.get(depth - 1).claims();
            var scope = new Scope(leaf.workflowId(), leaf.generation(), leaf.customerId());
            command = new StageCommand("synthetic-actor", id(500), "synthetic-stage", "command-version-1",
                    HASH, leaf.grantId(), leaf.actionId(), leaf.targetRunId(), scope);
            run = new RunSnapshot(leaf.targetRunId(), leaf.actionId(), scope,
                    depth == 1 ? AgentRole.KYC : depth == 2 ? AgentRole.LOAN : AgentRole.PAYMENT, RunStatus.VALIDATED);
            var binding = new BodyBinding("synthetic-body-version", BODY, HASH, INPUT, EVIDENCE,
                    leaf.sourceRunId(), leaf.sourceResultId(), "synthetic-validation-ref");
            result = new ResultSnapshot(id(600), leaf.targetRunId(), leaf.workflowId(), leaf.generation(),
                    ResultStatus.VALIDATED, BusinessConclusion.POSITIVE, binding);
            expected = new ExpectedResultBinding(result.resultId(), binding);
            workflow = new WorkflowSnapshot(scope);
        }
        PreparedStage prepare() {
            return prepareAgentResultStage(codecProfile(), nodes, profile, command, run, result, workflow, expected);
        }
    }
    /** Only public immutable record components and their public constructor are accessed. */
    @SuppressWarnings("unchecked")
    private static <T extends Record> T changed(T original, String field, Object replacement) throws Exception {
        RecordComponent[] components = original.getClass().getRecordComponents();
        var types = new Class<?>[components.length]; var values = new Object[components.length]; boolean found = false;
        for (int i = 0; i < components.length; i++) {
            types[i] = components[i].getType(); values[i] = components[i].getAccessor().invoke(original);
            if (components[i].getName().equals(field)) { values[i] = replacement; found = true; }
        }
        assertTrue(found); return (T) original.getClass().getConstructor(types).newInstance(values);
    }
    private static void rejected(Executable operation) {
        var failure = assertThrows(IllegalArgumentException.class, operation);
        assertEquals("INVALID_SYNTHETIC_GRANT_STAGE", failure.getMessage()); assertNull(failure.getCause());
    }
    private static void consistentOnly(PreparedStage prepared, int depth) {
        assertTrue(prepared.suppliedBindingConsistent()); assertEquals(depth, prepared.chain().depth());
        assertFalse(prepared.authorizationEstablished()); assertFalse(prepared.authoritativeFinalityEstablished());
        assertFalse(prepared.bodyHashVerified()); assertFalse(prepared.chain().authorizationEstablished());
    }

    @Test void coherentKycAndLoanAreUnsignedConsistencyOnlyNotHashOrFinalityProof() {
        for (int depth : List.of(1, 2)) {
            var f = new Fixture(depth); var prepared = f.prepare();
            consistentOnly(prepared, depth); assertEquals(BusinessConclusion.POSITIVE, prepared.businessConclusion());
            assertEquals(HASH, f.result.binding().digest());
            assertFalse(prepared.toString().contains("synthetic-validation-ref"));
        }
    }

    @Test void everyNonValidatedRunAndResultStatusIncludingSucceededIsRefused() throws Exception {
        for (var status : RunStatus.values()) if (status != RunStatus.VALIDATED) {
            var f = new Fixture(1); f.run = changed(f.run, "status", status); rejected(f::prepare);
        }
        for (var status : ResultStatus.values()) if (status != ResultStatus.VALIDATED) {
            var f = new Fixture(2); f.result = changed(f.result, "status", status); rejected(f::prepare);
        }
    }

    @Test void roleAndPaymentStageCannotAliasKycOrLoanFinality() throws Exception {
        for (int depth : List.of(1, 2)) for (var role : AgentRole.values()) {
            var f = new Fixture(depth);
            if (role == f.run.role()) continue;
            f.run = changed(f.run, "role", role); rejected(f::prepare);
        }
        var payment = new Fixture(3);
        assertNotNull(prepareChain(codecProfile(), payment.nodes));
        rejected(payment::prepare);
    }

    @Test void eachCommandGrantActionTargetAndScopeBindingMustMatch() throws Exception {
        for (String field : List.of("grantId", "actionId", "targetRunId")) {
            var f = new Fixture(1); f.command = changed(f.command, field, id(999)); rejected(f::prepare);
        }
        for (Scope scope : List.of(new Scope(id(999), 1, "synthetic-customer"),
                new Scope(id(1), 2, "synthetic-customer"), new Scope(id(1), 1, "synthetic-other"))) {
            var f = new Fixture(2); f.command = changed(f.command, "scope", scope); rejected(f::prepare);
        }
    }

    @Test void runResultAndWorkflowRelationsAreIndependentRequiredBindings() throws Exception {
        for (String field : List.of("runId", "actionId")) {
            var f = new Fixture(1); f.run = changed(f.run, field, id(999)); rejected(f::prepare);
        }
        var wrongScope = new Scope(id(1), 1, "synthetic-other");
        var runScope = new Fixture(1); runScope.run = changed(runScope.run, "scope", wrongScope); rejected(runScope::prepare);
        for (String field : List.of("runId", "workflowId", "resultId")) {
            var f = new Fixture(2); f.result = changed(f.result, field, id(999)); rejected(f::prepare);
        }
        var generation = new Fixture(2); generation.result = changed(generation.result, "generation", 2); rejected(generation::prepare);
        var workflow = new Fixture(1); workflow.workflow = new WorkflowSnapshot(wrongScope); rejected(workflow::prepare);
    }

    @Test void expectedResultAndEveryBodyReferenceAreComparedWithoutTruthInference() throws Exception {
        String[] fields = {"canonicalizationVersion", "canonicalBody", "digest", "inputSnapshotHash",
                "evidenceBundleHash", "sourceRunId", "sourceResultId", "validationReference"};
        Object[] values = {"other-version", "[]".getBytes(StandardCharsets.US_ASCII), "d".repeat(64),
                "d".repeat(64), "d".repeat(64), id(999), id(999), "other-validation"};
        for (int i = 0; i < fields.length; i++) {
            var f = new Fixture(2);
            f.expected = new ExpectedResultBinding(f.result.resultId(), changed(f.expected.binding(), fields[i], values[i]));
            rejected(f::prepare);
        }
        var resultId = new Fixture(1); resultId.expected = changed(resultId.expected, "resultId", id(999)); rejected(resultId::prepare);
    }

    @Test void matchingObservedAndExpectedCannotOverrideLeafSourceOrEvidence() throws Exception {
        for (String field : List.of("sourceRunId", "sourceResultId", "evidenceBundleHash")) {
            var f = new Fixture(2);
            Object replacement = field.equals("evidenceBundleHash") ? "d".repeat(64) : id(999);
            var binding = changed(f.result.binding(), field, replacement);
            f.result = changed(f.result, "binding", binding); f.expected = new ExpectedResultBinding(f.result.resultId(), binding);
            rejected(f::prepare);
        }
        var root = new Fixture(1);
        var binding = changed(root.result.binding(), "sourceResultId", id(999));
        root.result = changed(root.result, "binding", binding); root.expected = new ExpectedResultBinding(root.result.resultId(), binding);
        rejected(root::prepare);
    }

    @Test void bodySnapshotClonesAtConstructionAndAccessWithExactExplicitByteCap() {
        byte[] input = BODY.clone();
        var binding = new BodyBinding("synthetic-body-version", input, HASH, INPUT, EVIDENCE, null, null, "synthetic-ref");
        input[0] = '['; assertArrayEquals(BODY, binding.canonicalBody());
        byte[] exposed = binding.canonicalBody(); exposed[0] = '['; assertArrayEquals(BODY, binding.canonicalBody());
        var f = new Fixture(1); f.result = new ResultSnapshot(f.result.resultId(), f.result.runId(), f.result.workflowId(), 1,
                ResultStatus.VALIDATED, BusinessConclusion.POSITIVE, binding);
        f.expected = new ExpectedResultBinding(f.result.resultId(), binding);
        consistentOnly(f.prepare(), 1);
        rejected(() -> prepareAgentResultStage(codecProfile(), f.nodes, new BindingProfile(1), f.command,
                f.run, f.result, f.workflow, f.expected));
        rejected(() -> new BindingProfile(0));
    }

    @Test void emptyOrUnknownBodyVersionDigestInputEvidenceAndValidationCannotPass() throws Exception {
        String[] fields = {"canonicalizationVersion", "canonicalBody", "digest", "inputSnapshotHash",
                "evidenceBundleHash", "validationReference"};
        Object[] values = {" ", new byte[0], "A".repeat(64), "unknown", "unknown", " "};
        for (int i = 0; i < fields.length; i++) {
            var f = new Fixture(1); var invalid = changed(f.result.binding(), fields[i], values[i]);
            f.result = changed(f.result, "binding", invalid); f.expected = new ExpectedResultBinding(f.result.resultId(), invalid);
            rejected(f::prepare);
        }
    }

    @Test void negativeBusinessConclusionIsRetainedWithoutConsumptionOrChildCreation() throws Exception {
        for (int depth : List.of(1, 2)) {
            var f = new Fixture(depth); f.result = changed(f.result, "businessConclusion", BusinessConclusion.NEGATIVE);
            var prepared = f.prepare(); consistentOnly(prepared, depth);
            assertEquals(BusinessConclusion.NEGATIVE, prepared.businessConclusion());
            assertEquals(depth, f.nodes.size()); assertEquals(depth, prepared.chain().frames().size());
        }
        var unknown = new Fixture(1); unknown.result = changed(unknown.result, "businessConclusion", BusinessConclusion.UNCONFIRMED);
        rejected(unknown::prepare);
    }

    @Test void requestAndActionUuidMayEqualOrDifferButMissingIdentityIsNotDefaulted() throws Exception {
        var different = new Fixture(1); assertNotEquals(different.command.globalRequestId(), different.command.actionId());
        consistentOnly(different.prepare(), 1);
        var equal = new Fixture(1); equal.command = changed(equal.command, "globalRequestId", equal.command.actionId());
        consistentOnly(equal.prepare(), 1);
        for (String field : List.of("actorId", "globalRequestId", "operation", "canonicalizationVersion", "canonicalBodyDigest")) {
            var f = new Fixture(1); f.command = changed(f.command, field, null); rejected(f::prepare);
        }
    }

    @Test void missingSnapshotsHaveOneFixedFailureAndDoNotCreateFinalityFacts() {
        var f = new Fixture(1);
        rejected(() -> prepareAgentResultStage(codecProfile(), f.nodes, null, f.command, f.run, f.result, f.workflow, f.expected));
        rejected(() -> prepareAgentResultStage(codecProfile(), f.nodes, f.profile, null, f.run, f.result, f.workflow, f.expected));
        rejected(() -> prepareAgentResultStage(codecProfile(), f.nodes, f.profile, f.command, null, f.result, f.workflow, f.expected));
        rejected(() -> prepareAgentResultStage(codecProfile(), f.nodes, f.profile, f.command, f.run, null, f.workflow, f.expected));
        rejected(() -> prepareAgentResultStage(codecProfile(), f.nodes, f.profile, f.command, f.run, f.result, null, f.expected));
        rejected(() -> prepareAgentResultStage(codecProfile(), f.nodes, f.profile, f.command, f.run, f.result, f.workflow, null));
    }
}
