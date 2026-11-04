package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.*;
import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.Fact;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.RecordComponent;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.*;
import static com.finsec.fuse.reimplementation.grant.VirtualGrantFactResolverTest.*;
import static org.junit.jupiter.api.Assertions.*;

/** Supplied root consistency only; no signer, current registry or store authority. */
final class SyntheticRootProvisionBindingTest {
    static final class RootFixture {
        final SyntheticGrantChainStructure.Node node = chain(1).get(0);
        final RootInputs inputs = new RootInputs(profile(), node.claims(), node.action(),
                SyntheticGrantV2Codec.prepare(profile(), node.claims(), node.action()));
        final Map<AllowedAction, AgentReference> suppliedAgents = new LinkedHashMap<>(Map.of(
                AllowedAction.EVALUATE_KYC, new AgentReference(node.claims().targetAgent(), 1)));
        final SimulationSpec.Source source = new SimulationSpec.Source(id(700), 1, "synthetic document body",
                SimulationSpec.rawHash("synthetic document body"), true);
        final SimulationSpec.Application application = new SimulationSpec.Application("synthetic-fixture", "synthetic-business",
                node.claims().customerId(), node.claims().amountKrw(), node.claims().payoutAccountId(), 2000, 3000, true, source);
        final SimulationSpec.RiskTerms terms = new SimulationSpec.RiskTerms(node.claims().policyVersion(), 1, 1, 1, 10, 5, 1, Duration.ofSeconds(60));
        final TypedWorkflowPlan plan = new TypedWorkflowPlan(node.claims().workflowId(), 1, application, terms,
                "synthetic-lane-reference", node.claims().targetRunId(), suppliedAgents);
        final CommandIdentity identity = new CommandIdentity("synthetic-actor-alias", id(800), "synthetic-root-provision",
                "synthetic-command-version", HASH, node.claims().grantId(), node.claims().actionId(), node.claims().targetRunId(),
                node.claims().workflowId(), 1, node.claims().customerId());
        final RootCommand command = new RootCommand(identity, inputs, plan);
        final SyntheticGrantIssuerBindings.Prepared registry = SyntheticGrantIssuerBindings.prepare("synthetic-registry",
                List.of(binding(1)), new SyntheticGrantIssuerBindings.Limits(4, 128));
        final IssuerFacts issuer = new IssuerFacts(registry, new VirtualGrantFactResolver.Descriptor(identity.actorId(), binding(1),
                "synthetic-owner-reference", "synthetic-key-version"));
        final VirtualGrantFactResolver.KeyFacts baseKey = key(SyntheticGrantKeyLifecycleAssessment.Lifecycle.ACTIVE,
                SyntheticGrantKeyLifecycleAssessment.Ordering.BEFORE_RETIREMENT, SyntheticGrantKeyLifecycleAssessment.MaterialFact.AVAILABLE);
        final KeyFacts keyFacts = new KeyFacts(baseKey.expected(), baseKey.snapshot(), Fact.CLEAR, baseKey.material(),
                new SyntheticGrantTemporalAssessment.TemporalFacts(150, 100, 400,
                        SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null), revocations(), baseKey.currentUse());
        ResolvedRootProvision resolved(CurrentBindings current) { return new ResolvedRootProvision(command, current, issuer, keyFacts); }
    }
    static CurrentBindings absent() { return new CurrentBindings(true,true,true,true,true,true); }
    @SuppressWarnings("unchecked")
    static <T extends Record> T changed(T value, String field, Object replacement) throws Exception {
        RecordComponent[] components = value.getClass().getRecordComponents();
        Class<?>[] types = new Class<?>[components.length]; Object[] values = new Object[components.length]; boolean found = false;
        for (int i = 0; i < components.length; i++) {
            types[i] = components[i].getType(); values[i] = components[i].getAccessor().invoke(value);
            if (components[i].getName().equals(field)) { values[i] = replacement; found = true; }
        }
        assertTrue(found);
        try { return (T) value.getClass().getConstructor(types).newInstance(values); }
        catch (InvocationTargetException failure) {
            if (failure.getCause() instanceof RuntimeException runtime) throw runtime;
            throw failure;
        }
    }
    static void invalidInput(org.junit.jupiter.api.function.Executable action) {
        var failure = assertThrows(IllegalArgumentException.class, action);
        assertEquals("INVALID_GRANT_COMMAND", failure.getMessage()); assertNull(failure.getCause());
    }

    @Test void exactAliasUuidDescriptorRootAndKeyFactsAreConsistentWithoutAuthority() {
        var f = new RootFixture(); assertDoesNotThrow(() -> checkResolved(f.command, f.resolved(absent())));
        assertNotEquals(f.identity.actorId(), f.issuer.binding().actorId().toString());
        var receipt = new RootReceipt(1, f.command); assertTrue(receipt.matches(f.command));
        assertFalse(receipt.actualAuthority()); assertFalse(receipt.durable());
    }

    @Test void actorAliasOwnerVersionAndSubjectRegistryMustMatchExplicitDescriptor() throws Exception {
        var f = new RootFixture(); var d = f.issuer.descriptor();
        for (var field : List.of("actorAlias", "keyOwnerReference", "keyVersion")) {
            var altered = new IssuerFacts(f.registry, changed(d, field, "synthetic-wrong"));
            invalidInput(() -> checkResolved(f.command, new ResolvedRootProvision(f.command, absent(), altered, f.keyFacts)));
        }
        var other = changed(f.issuer.binding(), "subjectId", "synthetic-unregistered");
        var altered = new IssuerFacts(f.registry, changed(d, "issuerBinding", other));
        invalidInput(() -> checkResolved(f.command, new ResolvedRootProvision(f.command, absent(), altered, f.keyFacts)));
    }

    @Test void eachCurrentCollisionFlagRefusesEvenWhenAllOtherSuppliedFactsMatch() {
        var f = new RootFixture();
        for (int i = 0; i < 6; i++) {
            var flags = new CurrentBindings(i!=0,i!=1,i!=2,i!=3,i!=4,i!=5);
            invalidInput(() -> checkResolved(f.command, f.resolved(flags)));
        }
    }

    @Test void rootTimeWindowExpiryAndParentCapCannotBorrowHistoricalReadException() throws Exception {
        var f = new RootFixture();
        for (var time : List.of(new SyntheticGrantTemporalAssessment.TemporalFacts(400,100,400,
                SyntheticGrantTemporalAssessment.ChainPosition.ROOT,null),
                new SyntheticGrantTemporalAssessment.TemporalFacts(150,100,400,
                SyntheticGrantTemporalAssessment.ChainPosition.CHILD,400L))) {
            var key = changed(f.keyFacts, "time", time);
            invalidInput(() -> checkResolved(f.command, new ResolvedRootProvision(f.command, absent(), f.issuer, key)));
        }
    }

    @Test void revokedUnknownMissingMaterialAndChangedKeyNeverAdmitNewIssuance() throws Exception {
        var f = new RootFixture();
        for (var lifecycle : List.of(SyntheticGrantKeyLifecycleAssessment.Lifecycle.REVOKED,
                SyntheticGrantKeyLifecycleAssessment.Lifecycle.UNKNOWN)) {
            var key = changed(f.keyFacts, "snapshot", new SyntheticGrantKeyLifecycleAssessment.KeySnapshot(f.baseKey.expected(), lifecycle));
            invalidInput(() -> checkResolved(f.command, new ResolvedRootProvision(f.command, absent(), f.issuer, key)));
        }
        var unknownMaterial = changed(f.keyFacts, "material", SyntheticGrantKeyLifecycleAssessment.MaterialFact.UNKNOWN);
        invalidInput(() -> checkResolved(f.command, new ResolvedRootProvision(f.command, absent(), f.issuer, unknownMaterial)));
        var changedBinding = changed(f.keyFacts, "bindingChanged", Fact.ACTIVE);
        invalidInput(() -> checkResolved(f.command, new ResolvedRootProvision(f.command, absent(), f.issuer, changedBinding)));
    }

    @Test void commandScopeGenerationAndApplicationJoinsCannotBeSubstituted() throws Exception {
        var f = new RootFixture();
        for (String field : List.of("grantId", "actionId", "targetRunId", "workflowId", "generation", "customerId")) {
            Object replacement = field.equals("generation") ? 2 : field.equals("customerId") ? "synthetic-other" : id(999);
            var identity = changed(f.identity, field, replacement);
            invalidInput(() -> new RootCommand(identity, f.inputs, f.plan));
        }
        var app = changed(f.application, "amountKrw", 2000L);
        var plan = changed(f.plan, "application", app);
        invalidInput(() -> new RootCommand(f.identity, f.inputs, plan));
    }

    @Test void planMapIsDetachedAndOnlyKycReferenceIsRequiredWithoutAutodispatch() {
        var f = new RootFixture(); f.suppliedAgents.clear();
        assertEquals(1, f.plan.stageAgents().size());
        assertThrows(UnsupportedOperationException.class, () -> f.plan.stageAgents().clear());
        assertEquals("KYC_PENDING", f.plan.initialState()); assertEquals(0, f.plan.usedRisk());
        assertEquals(0, f.plan.reservedRisk()); assertEquals(0, f.plan.kycRuns());
        invalidInput(() -> new TypedWorkflowPlan(f.plan.workflowId(),1,f.application,f.terms,"synthetic-lane",f.plan.targetRunId(),Map.of()));
    }

    @Test void rootReceiptFullIdentityBindingAndSafeProjectionDoNotExposeSourceText() throws Exception {
        var f = new RootFixture(); var receipt = new RootReceipt(1, f.command);
        String[] fields = {"actorId","globalRequestId","operation","canonicalizationVersion","canonicalBodyDigest",
                "grantId","actionId","targetRunId","workflowId","generation","customerId"};
        for (String field : fields) {
            Object replacement = field.equals("generation") ? 2 : field.equals("customerId") ? "synthetic-other" :
                    field.endsWith("Id") && !field.equals("actorId") ? id(999) : "synthetic-other";
            var other = changed(f.identity, field, replacement);
            if (List.of("grantId","actionId","targetRunId","workflowId","generation","customerId").contains(field)) {
                invalidInput(() -> new RootCommand(other,f.inputs,f.plan));
            } else assertFalse(receipt.matches(new RootCommand(other,f.inputs,f.plan)));
        }
        assertEquals(f.source.contentHash(), receipt.planBinding().contentHash());
        for (var component : RootPlanBinding.class.getRecordComponents()) assertNotEquals("text", component.getName());
        assertFalse(receipt.toString().contains(f.source.text())); assertFalse(f.command.toString().contains(f.source.text()));
        byte[] frame = f.inputs.prepared().unsignedFrame(); byte old = frame[0]; frame[0] ^= 1;
        assertEquals(old, f.inputs.prepared().unsignedFrame()[0]);
    }

    @Test void malformedRootInputsAndOutcomeShapeHaveFixedCausefreeErrors() {
        var f = new RootFixture(); invalidInput(() -> new RootInputs(null,f.node.claims(),f.node.action(),f.inputs.prepared()));
        invalidInput(() -> new RootReceipt(2,f.command));
        invalidInput(() -> new RootOutcome(OwnedGrantTransactionPort.Status.VIRTUAL_COMMITTED_IN_PROCESS,null,RootEffect.COMMITTED_IN_PROCESS));
    }
}
