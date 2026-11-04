package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import static com.finsec.fuse.reimplementation.auth.SyntheticGrantV2Codec.*;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic structural chains; matching rows do not establish grant authority. */
final class SyntheticGrantChainStructureTest {
    private static UUID id(long n) { return new UUID(7, n); }
    private static Profile profile() { return new Profile(16384, 8192, 8, 64, 1000, 300); }
    private static GrantStorageShape.AllowedAction actionAt(int depth) {
        return switch (depth) {
            case 1 -> GrantStorageShape.AllowedAction.EVALUATE_KYC;
            case 2 -> GrantStorageShape.AllowedAction.CREATE_LOAN_RECOMMENDATION;
            case 3 -> GrantStorageShape.AllowedAction.EXECUTE_MOCK_PAYMENT;
            default -> throw new AssertionError("synthetic depth");
        };
    }
    private static String payload(Action a) {
        var m = new LinkedHashMap<String, Object>();
        m.put("actionId", a.actionId().toString()); m.put("workflowId", a.workflowId().toString());
        m.put("generation", a.generation()); m.put("allowedAction", a.allowedAction().name());
        m.put("customerId", a.customerId()); m.put("amountKrw", a.amountKrw());
        m.put("payoutAccountId", a.payoutAccountId().toString()); m.put("targetRunId", a.targetRunId().toString());
        m.put("sourceResultId", a.sourceResultId() == null ? null : a.sourceResultId().toString());
        m.put("evidenceBundleHash", a.evidenceBundleHash());
        m.put("approvalId", a.approvalId() == null ? null : a.approvalId().toString());
        m.put("policyVersion", a.policyVersion());
        return CanonicalJson.sha256(m);
    }
    private static SyntheticGrantChainStructure.Node node(int depth) {
        var a = new Action(id(100 + depth), id(1), 1, actionAt(depth), "synthetic-customer",
                1000L, id(2), id(200 + depth), depth == 1 ? null : id(300 + depth),
                null, depth == 3 ? id(3) : null, "synthetic-policy");
        var c = new Claims("FUSE-GRANT-v2", "HMAC-SHA256", "synthetic-key", id(400 + depth),
                a.workflowId(), a.generation(), id(4), "synthetic-principal", "synthetic-intent",
                "synthetic-issuer", "synthetic-source", "synthetic-target",
                depth == 1 ? null : id(200 + depth - 1), a.targetRunId(), a.allowedAction(),
                a.customerId(), a.amountKrw(), a.payoutAccountId(), a.sourceResultId(), a.evidenceBundleHash(),
                depth == 1 ? null : id(400 + depth - 1), depth, a.actionId(), payload(a),
                a.policyVersion(), id(5), a.approvalId(), 100, 400);
        return new SyntheticGrantChainStructure.Node(c, a);
    }
    private static List<SyntheticGrantChainStructure.Node> chain(int depth) {
        var rows = new ArrayList<SyntheticGrantChainStructure.Node>();
        for (int i = 1; i <= depth; i++) rows.add(node(i));
        return rows;
    }
    /** Copies only public record components through their public constructor. */
    @SuppressWarnings("unchecked")
    private static <T extends Record> T changed(T original, String field, Object replacement) throws Exception {
        RecordComponent[] components = original.getClass().getRecordComponents();
        var types = new Class<?>[components.length]; var values = new Object[components.length];
        boolean found = false;
        for (int i = 0; i < components.length; i++) {
            types[i] = components[i].getType(); values[i] = components[i].getAccessor().invoke(original);
            if (components[i].getName().equals(field)) { values[i] = replacement; found = true; }
        }
        assertTrue(found, "public record field must exist");
        return (T) original.getClass().getConstructor(types).newInstance(values);
    }
    private static SyntheticGrantChainStructure.Node claimChanged(SyntheticGrantChainStructure.Node n,
            String field, Object replacement) throws Exception {
        return new SyntheticGrantChainStructure.Node(changed(n.claims(), field, replacement), n.action());
    }
    private static SyntheticGrantChainStructure.Node bothChanged(SyntheticGrantChainStructure.Node n,
            String field, Object replacement) throws Exception {
        var a = changed(n.action(), field, replacement);
        var c = changed(n.claims(), field, replacement);
        c = changed(c, "payloadHash", payload(a));
        return new SyntheticGrantChainStructure.Node(c, a);
    }
    private static void rejected(Executable operation) {
        var failure = assertThrows(IllegalArgumentException.class, operation);
        assertEquals("INVALID_SYNTHETIC_GRANT_CHAIN", failure.getMessage());
        assertNull(failure.getCause());
    }

    @Test void completeRootFirstChainsPreserveEveryIndependentRowPreparation() {
        for (int depth = 1; depth <= 3; depth++) {
            var rows = chain(depth); var prepared = prepareChain(profile(), rows);
            assertEquals(depth, prepared.depth()); assertEquals(depth, prepared.frames().size());
            assertTrue(prepared.structuralSatisfied()); assertFalse(prepared.authorizationEstablished());
            for (int i = 0; i < depth; i++) {
                var row = rows.get(i); var expected = prepare(profile(), row.claims(), row.action());
                assertArrayEquals(expected.claimsBytes(), prepared.frames().get(i).claimsBytes());
                assertArrayEquals(expected.actionBytes(), prepared.frames().get(i).actionBytes());
                assertArrayEquals(expected.unsignedFrame(), prepared.frames().get(i).unsignedFrame());
                assertEquals(expected.payloadSha256(), prepared.frames().get(i).payloadSha256());
            }
        }
    }

    @Test void missingExtraAndOutOfOrderAncestorsDoNotBecomeCompleteChains() {
        rejected(() -> prepareChain(profile(), List.of()));
        rejected(() -> prepareChain(profile(), List.of(node(2))));
        rejected(() -> prepareChain(profile(), List.of(node(1), node(3))));
        rejected(() -> prepareChain(profile(), List.of(node(2), node(1))));
        rejected(() -> prepareChain(profile(), List.of(node(1), node(2), node(3), node(1))));
    }

    @Test void repeatedGrantActionAndTargetIdsAreRefusedWithOtherwiseValidRows() throws Exception {
        for (String field : List.of("grantId", "actionId", "targetRunId")) {
            var root = node(1); var child = node(2);
            child = field.equals("grantId") ? claimChanged(child, field, root.claims().grantId())
                    : bothChanged(child, field, field.equals("actionId") ? root.action().actionId() : root.action().targetRunId());
            assertNotNull(prepare(profile(), child.claims(), child.action()));
            var invalid = List.of(root, child);
            rejected(() -> prepareChain(profile(), invalid));
        }
    }

    @Test void cyclicOrSkippedParentAndWrongSourceRunCannotPassAdjacency() throws Exception {
        var root = node(1); var child = node(2); var leaf = node(3);
        for (UUID parent : List.of(child.claims().grantId(), leaf.claims().grantId(), id(999))) {
            var invalid = List.of(root, claimChanged(child, "parentGrantId", parent));
            rejected(() -> prepareChain(profile(), invalid));
        }
        var skipped = List.of(root, child, claimChanged(leaf, "parentGrantId", root.claims().grantId()));
        rejected(() -> prepareChain(profile(), skipped));
        var wrongRun = List.of(root, claimChanged(child, "sourceRunId", id(999)));
        rejected(() -> prepareChain(profile(), wrongRun));
    }

    @Test void eachDepthRequiresItsActionEvenThoughExistingRowApiDoesNotInferStages() throws Exception {
        for (int depth = 1; depth <= 3; depth++) {
            var rows = chain(depth);
            var wrong = bothChanged(rows.get(depth - 1), "allowedAction", actionAt(depth == 3 ? 1 : depth + 1));
            assertNotNull(prepare(profile(), wrong.claims(), wrong.action()));
            rows.set(depth - 1, wrong);
            rejected(() -> prepareChain(profile(), rows));
        }
    }

    @Test void workflowGenerationAndCustomerMustMatchAcrossIndividuallyValidRows() throws Exception {
        var child = node(2);
        String[] fields = {"workflowId", "generation", "customerId"};
        Object[] replacements = {id(999), 2, "synthetic-other"};
        for (int i = 0; i < fields.length; i++) {
            var wrong = bothChanged(child, fields[i], replacements[i]);
            assertNotNull(prepare(profile(), wrong.claims(), wrong.action()));
            var rows = List.of(node(1), wrong);
            rejected(() -> prepareChain(profile(), rows));
        }
    }

    @Test void rowNullShapeAndActionPayloadMismatchAreNotHiddenByChainChecks() throws Exception {
        var rootWithParent = claimChanged(node(1), "parentGrantId", id(999));
        rejected(() -> prepareChain(profile(), List.of(rootWithParent)));
        var missingSourceRun = List.of(node(1), claimChanged(node(2), "sourceRunId", null));
        rejected(() -> prepareChain(profile(), missingSourceRun));
        var missingResult = List.of(node(1), bothChanged(node(2), "sourceResultId", null));
        rejected(() -> prepareChain(profile(), missingResult));
        var missingApproval = List.of(node(1), node(2), bothChanged(node(3), "approvalId", null));
        rejected(() -> prepareChain(profile(), missingApproval));
        var changedAction = changed(node(1).action(), "customerId", "synthetic-other");
        var mismatched = new SyntheticGrantChainStructure.Node(node(1).claims(), changedAction);
        rejected(() -> prepareChain(profile(), List.of(mismatched)));
        var badHash = claimChanged(node(1), "payloadHash", "0".repeat(64));
        rejected(() -> prepareChain(profile(), List.of(badHash)));
    }

    @Test void nullProfileRowsNodesAndComponentsHaveOneFixedFailure() {
        rejected(() -> prepareChain(null, chain(1)));
        rejected(() -> prepareChain(profile(), null));
        rejected(() -> prepareChain(profile(), Arrays.asList((SyntheticGrantChainStructure.Node) null)));
        rejected(() -> prepareChain(profile(), List.of(new SyntheticGrantChainStructure.Node(null, node(1).action()))));
        rejected(() -> prepareChain(profile(), List.of(new SyntheticGrantChainStructure.Node(node(1).claims(), null))));
    }

    @Test void preparedFramesAreDetachedImmutableAndNeverEstablishAuthority() {
        var rows = chain(3); var prepared = prepareChain(profile(), rows);
        var before = prepared.frames().get(0).unsignedFrame(); rows.clear();
        assertEquals(3, prepared.depth()); assertEquals(3, prepared.frames().size());
        assertThrows(UnsupportedOperationException.class, () -> prepared.frames().clear());
        var exposed = prepared.frames().get(0).unsignedFrame(); exposed[0] ^= 1;
        assertArrayEquals(before, prepared.frames().get(0).unsignedFrame());
        assertFalse(prepared.authorizationEstablished());
        assertFalse(prepared.toString().contains("synthetic-customer"));
        assertFalse(prepared.toString().contains("synthetic-issuer"));
    }

    @Test void concreteIdentityStringsAndSourceResultAreNotInventedAuthorityEqualities() throws Exception {
        var rows = chain(2);
        var child = claimChanged(rows.get(1), "issuer", "synthetic-independent-issuer");
        child = claimChanged(child, "sourceAgent", "synthetic-not-parent-target");
        child = claimChanged(child, "principalId", "synthetic-independent-principal");
        child = bothChanged(child, "sourceResultId", id(888));
        rows.set(1, child);
        var prepared = prepareChain(profile(), rows);
        assertTrue(prepared.structuralSatisfied()); assertFalse(prepared.authorizationEstablished());
    }
}
