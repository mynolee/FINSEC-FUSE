package com.finsec.fuse.reimplementation.http;

import com.finsec.fuse.reimplementation.auth.*;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.*;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.*;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.http.PreparedTypedActionCatalog.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.*;

/** Real synthetic registry, context, catalog and APP bridge, never a servlet container or real issuer. */
class TypedWorkflowMutationControllerTest {
    enum Route { ROOT, RECONCILE, CONTINUATION }
    private static UUID id(long n) { return new UUID(95, n); }
    private static final class Fixture {
        final PreparedTypedActionCatalogTest.NativeFixture nativeInput = new PreparedTypedActionCatalogTest.NativeFixture();
        final UUID reference = id(1);
        RootCommand command = nativeInput.root;
        final VirtualTransactionalStore store = new VirtualTransactionalStore();
        final AtomicInteger tokens = new AtomicInteger(1000), coordinateReads = new AtomicInteger();
        int rootChecks, rootResolves;
        Gate nativeGate = Gate.CLEAR;
        OwnedRootProvisionPort.OwnedRootTx seenTx;
        SimulationSpec.Catalog currentCatalog = new SimulationSpec.Catalog(List.of(nativeInput.application), List.of());
        final LocalVirtualTokenRegistry tokenRegistry = new LocalVirtualTokenRegistry(1);
        final LocalVirtualPrincipalRegistry principals = new LocalVirtualPrincipalRegistry(1, 1);
        final TokenMaterialCodec.Material tokenMaterial = TokenMaterialCodec.encode(new byte[32]);
        final LocalVirtualAdmissionContext context;
        final LocalVirtualAuthenticationFilter filter;
        final VirtualGrantWorkflowBridge bridge;
        TypedWorkflowMutationController controller;
        HttpServletRequest lastBound;
        Fixture() { this(0); }
        Fixture(int identityDifference) {
            var binding = nativeInput.binding;
            UUID principal = identityDifference == 1 ? id(90) : binding.localPrincipalId();
            long revision = identityDifference == 2 ? binding.bindingRevision() + 1 : binding.bindingRevision();
            String alias = identityDifference == 3 ? "synthetic-other-local-alias" : binding.actorAlias();
            principals.registerPrepared(new LocalVirtualPrincipal(principal, alias, revision, LocalVirtualPrincipal.Status.ACTIVE,
                Set.of(TokenRegistryInput.Role.CUSTOMER), Set.of(command.identity().customerId()),
                Map.of(command.identity().workflowId(), command.identity().customerId()), 2));
            tokenRegistry.registerPrepared(new LocalVirtualTokenRegistry.Credential(id(91), principal,
                LocalVirtualTokenRegistry.Status.ACTIVE, 0, Instant.ofEpochSecond(149), Instant.ofEpochSecond(210),
                revision, tokenMaterial.fingerprint()));
            context = new LocalVirtualAdmissionContext(new LocalVirtualCurrentVerifier(tokenRegistry, principals), tokenRegistry);
            filter = new LocalVirtualAuthenticationFilter(tokenRegistry, context, Clock.fixed(Instant.ofEpochSecond(150), ZoneOffset.UTC), new PublicHttpErrors());
            var claims = command.inputs().claims();
            var issuerBinding = new SyntheticGrantIssuerBindings.Binding(binding.issuerSubjectId(), id(92), claims.principalId(),
                claims.issuer(), SyntheticGrantIssuerBindings.Stage.KYC_EVALUATOR, claims.allowedAction(), claims.customerId(),
                claims.rootAuthorizationId(), claims.workflowId(), claims.originIntent(),
                new SyntheticGrantIssuerBindings.KeyReference(claims.kid(), claims.algorithm(), "synthetic-key-owner-reference"));
            var registry = SyntheticGrantIssuerBindings.prepare("synthetic-controller-registry", List.of(issuerBinding), new SyntheticGrantIssuerBindings.Limits(1, 256));
            var descriptor = new VirtualGrantFactResolver.Descriptor(binding.actorAlias(), issuerBinding,
                "synthetic-key-owner-reference", "synthetic-key-version");
            var expectedKey = new SyntheticGrantKeyLifecycleAssessment.KeyBinding(claims.kid(), claims.issuer(), claims.algorithm(), descriptor.keyVersion());
            VirtualGrantWorkflowBridge.Facts facts = new VirtualGrantWorkflowBridge.Facts() {
                public Gate current(SyntheticRootProvisionService.RootServerContext caller, RootCommand selected, OwnedRootProvisionPort.OwnedRootTx tx) {
                    rootChecks++; if (seenTx == null) seenTx = tx; else assertSame(seenTx, tx);
                    if (!selected.equals(command) || !caller.actorId().equals(binding.actorAlias())
                            || !caller.subjectId().equals(binding.issuerSubjectId()) || context.current() == null) return Gate.REFUSED;
                    var decision = context.authorizeSameActor(context.current().actor(), SimulationAccess.Operation.START,
                        selected.identity().workflowId(), selected.identity().customerId());
                    if (decision != LocalVirtualAccessPolicy.Decision.ALLOW) return Gate.REFUSED;
                    if (currentCatalog == null || !currentCatalog.application(selected.workflowPlan().application().request())
                            .equals(selected.workflowPlan().application())) return Gate.UNKNOWN;
                    return nativeGate;
                }
                public ResolvedRootProvision resolve(SyntheticRootProvisionService.RootServerContext caller, RootCommand selected,
                        CurrentBindings bindings, OwnedRootProvisionPort.OwnedRootTx tx) {
                    assertSame(seenTx, tx); assertEquals(command, selected); rootResolves++;
                    var clear = SyntheticGrantTemporalAssessment.Fact.CLEAR;
                    var time = new SyntheticGrantTemporalAssessment.TemporalFacts(150, claims.issuedAt(), claims.expiresAt(),
                        SyntheticGrantTemporalAssessment.ChainPosition.ROOT, null);
                    var revocation = new SyntheticGrantTemporalAssessment.RevocationFacts(clear, clear, clear, clear, clear, clear, clear, clear, clear);
                    var current = new SyntheticGrantKeyLifecycleAssessment.CurrentUseFacts(clear, clear, clear, clear, clear, clear);
                    var key = new SyntheticRootProvisionBinding.KeyFacts(expectedKey,
                        new SyntheticGrantKeyLifecycleAssessment.KeySnapshot(expectedKey, SyntheticGrantKeyLifecycleAssessment.Lifecycle.ACTIVE),
                        clear, SyntheticGrantKeyLifecycleAssessment.MaterialFact.AVAILABLE, time, revocation, current);
                    return new ResolvedRootProvision(selected, bindings, new IssuerFacts(registry, descriptor), key);
                }
                public VirtualGrantFactResolver.Snapshot load(ServerContext caller, StageCommand selected, OwnedTx tx) { throw new AssertionError("No agent stage"); }
                public SyntheticGrantTemporalAssessment.Fact versionChanged(ServerContext caller, StageCommand selected, OwnedTx tx, String version) { throw new AssertionError("No stage version"); }
                public VirtualMockPaymentFactResolver.PaymentSnapshot loadPayment(ServerContext caller, SyntheticMockPaymentTransactionBinding.PaymentCommand selected, OwnedTx tx, VirtualGrantFactResolver.Snapshot base) { throw new AssertionError("No payment"); }
                public Gate current(ServerContext caller, SyntheticKycPreparationBinding.PreparationCommand selected, OwnedKycPreparationPort.OwnedPreparationTx tx) { throw new AssertionError("No preparation"); }
                public Gate current(SyntheticMockPaymentPlanService.PlanServerContext caller, CommandIdentity selected, SyntheticMockPaymentPlanBinding.PlanOperation operation, OwnedMockPaymentPlanPort.OwnedPlanTx tx) { throw new AssertionError("No plan"); }
                public SyntheticMockPaymentPlanBinding.ResolvedEvidence resolveEvidence(SyntheticMockPaymentPlanService.PlanServerContext caller, CommandIdentity selected, SyntheticMockPaymentPlanBinding.ReviewBindings bindings, OwnedMockPaymentPlanPort.OwnedPlanTx tx) { throw new AssertionError("No plan evidence"); }
            };
            var journal = new VirtualGrantTransactionJournal(store, () -> id(tokens.incrementAndGet()), 65536);
            bridge = new VirtualGrantWorkflowBridge(journal, registry, facts); rebuildController();
        }
        void rebuildController() {
            var action = new PreparedAction(reference, new Root(command), nativeInput.binding, nativeInput.coordinates(1));
            var catalog = new PreparedTypedActionCatalog(List.of(action), 1);
            controller = new TypedWorkflowMutationController(bridge, catalog, context,
                new TypedWorkflowRequestDecoder(new HttpLimits(4096, 1024, 4)), (ref, purpose, request, admission, reconciliation) -> {
                    coordinateReads.incrementAndGet(); assertSame(context.current(), admission);
                    if (!reference.equals(ref) || currentCatalog == null) return null;
                    // Read independent current server catalog and actual store coordinates, never catalog.metadata().
                    var app = currentCatalog.application(nativeInput.application.request());
                    var row = store.snapshot().getOrDefault("virtual_workflows", Map.of()).get(command.identity().workflowId().toString());
                    int generation = row == null ? command.identity().generation() : ((Number) row.get("generation")).intValue();
                    String customer = row == null ? app.customerId() : (String) row.get("customerId");
                    var source = app.source();
                    return new Coordinates(command.identity().workflowId(), generation, customer, source.documentId(), source.documentVersion(),
                        source.contentHash(), nativeInput.terms.policyVersion());
                }, new PublicHttpErrors());
        }
        byte[] body(UUID ref) { return ("{\"commandRef\":\"" + ref + "\"}").getBytes(StandardCharsets.UTF_8); }
        MockHttpServletRequest request(String requestId) {
            var request = new MockHttpServletRequest(); request.setDispatcherType(DispatcherType.REQUEST);
            request.addHeader("Authorization", "Bearer " + tokenMaterial.bearer()); request.addHeader("Idempotency-Key", requestId); return request;
        }
        ResponseEntity<Map<String,Object>> call(Route route) throws Exception { return call(route, reference, command.identity().globalRequestId().toString(), false, false, null); }
        ResponseEntity<Map<String,Object>> call(Route route, UUID ref, String requestId, boolean loseWrapper, boolean bindRead, byte[] wireBody) throws Exception {
            seenTx = null; var response = new AtomicReference<ResponseEntity<Map<String,Object>>>();
            var wire = new MockHttpServletResponse();
            filter.doFilter(request(requestId), wire, (input, output) -> {
                lastBound = (HttpServletRequest) input;
                if (bindRead) assertEquals(LocalVirtualAccessPolicy.Decision.ALLOW,
                    context.current().authorize(SimulationAccess.Operation.READ, command.identity().workflowId(), command.identity().customerId()));
                var bound = loseWrapper ? new HttpServletRequestWrapper(lastBound) : lastBound;
                byte[] bytes = wireBody == null ? body(ref) : wireBody;
                response.set(switch (route) {
                    case ROOT -> controller.rootProvisions(bound, bytes);
                    case RECONCILE -> controller.rootProvisionsReconcile(bound, bytes);
                    case CONTINUATION -> controller.continuations(bound, bytes);
                });
            });
            assertEquals(200, wire.getStatus()); assertNotNull(response.get()); assertNull(context.current()); return response.get();
        }
        void changeWorkflow(String field, Object value) {
            store.transaction(tx -> {
                var old = tx.get("virtual_workflows", command.identity().workflowId().toString());
                var changed = new LinkedHashMap<String,Object>(old); changed.put(field, value);
                tx.put("virtual_workflows", command.identity().workflowId().toString(), changed); return null;
            });
        }
    }
    private static void status(ResponseEntity<Map<String,Object>> response, int code) {
        assertEquals(code, response.getStatusCode().value());
        assertFalse(response.getBody().toString().contains(PreparedTypedActionCatalogTest.CANARY));
    }
    @Test void actualAllowedRootCommitsAndExactReplayAndReconcileRemainClosedVirtualMetadata() throws Exception {
        var f = new Fixture(); var first = f.call(Route.ROOT); status(first, 200);
        assertEquals("VIRTUAL_COMMITTED_IN_PROCESS", first.getBody().get("status")); assertTrue(first.getBody().containsKey("receipt"));
        assertEquals(false, first.getBody().get("actualAuthority")); assertEquals(false, first.getBody().get("durable"));
        assertEquals(false, first.getBody().get("executionAuthorityGranted")); assertEquals(1, f.rootResolves);
        assertEquals(1, f.store.snapshot().get("virtual_workflows").size());
        assertTrue(f.store.snapshot().getOrDefault("virtual_jobs", Map.of()).isEmpty());
        var before = f.store.snapshot();
        var replay = f.call(Route.ROOT); status(replay, 200); assertEquals("VIRTUAL_REPLAYED_IN_PROCESS", replay.getBody().get("status"));
        var reconciled = f.call(Route.RECONCILE); status(reconciled, 200); assertEquals("VIRTUAL_REPLAYED_IN_PROCESS", reconciled.getBody().get("status"));
        assertEquals(before, f.store.snapshot()); assertEquals(1, f.rootResolves); assertTrue(f.coordinateReads.get() >= 3);
        assertThrows(UnsupportedOperationException.class, () -> first.getBody().put("raw", "not-allowed"));
    }
    @Test void bareLostOrExpiredPrivateCarrierNeverReachesCurrentCoordinatesOrNativeRoot() throws Exception {
        var f = new Fixture();
        status(f.controller.rootProvisions(f.request(f.command.identity().globalRequestId().toString()), f.body(f.reference)), 401);
        status(f.call(Route.ROOT, f.reference, f.command.identity().globalRequestId().toString(), true, false, null), 401);
        assertEquals(0, f.coordinateReads.get()); assertEquals(0, f.rootChecks); assertTrue(f.store.snapshot().isEmpty());
        assertEquals("VIRTUAL_COMMITTED_IN_PROCESS", f.call(Route.ROOT).getBody().get("status"));
        int reads = f.coordinateReads.get(); var before = f.store.snapshot();
        status(f.controller.rootProvisions(f.lastBound, f.body(f.reference)), 401);
        assertEquals(reads, f.coordinateReads.get()); assertEquals(before, f.store.snapshot());
    }
    @Test void missingCurrentMetadataChangedSourceOrActualGenerationStopsBeforeNativeService() throws Exception {
        for (int mode = 0; mode < 3; mode++) {
            var f = new Fixture();
            if (mode == 0) f.currentCatalog = null;
            if (mode == 1) {
                var a = f.nativeInput.application; var source = a.source(); String text = "synthetic remediated server source";
                var changedSource = new SimulationSpec.Source(source.documentId(), 2, text, SimulationSpec.rawHash(text), true);
                f.currentCatalog = new SimulationSpec.Catalog(List.of(new SimulationSpec.Application(a.fixtureId(), a.businessReference(), a.customerId(),
                    a.amountKrw(), a.payoutAccountId(), a.monthlyIncomeKrw(), a.maxLoanAmountKrw(), a.ownsActiveAccount(), changedSource)), List.of());
            }
            if (mode == 2) { assertEquals("VIRTUAL_COMMITTED_IN_PROCESS", f.call(Route.ROOT).getBody().get("status")); f.changeWorkflow("generation", 2); }
            int nativeChecks = f.rootChecks, resolves = f.rootResolves; var before = f.store.snapshot();
            status(f.call(Route.ROOT), 503); assertEquals(nativeChecks, f.rootChecks); assertEquals(resolves, f.rootResolves); assertEquals(before, f.store.snapshot());
        }
    }
    @Test void wrongReferenceRequestPurposeOrMalformedHeaderNeverExecutesThePreparedRoot() throws Exception {
        for (int mode = 0; mode < 4; mode++) {
            var f = new Fixture(); UUID ref = mode == 0 ? id(999) : f.reference;
            String requestId = mode == 1 ? id(998).toString() : mode == 3 ? " invalid-uuid " : f.command.identity().globalRequestId().toString();
            status(f.call(mode == 2 ? Route.CONTINUATION : Route.ROOT, ref, requestId, false, false, null), mode == 0 ? 503 : 400);
            assertEquals(0, f.rootChecks); assertEquals(0, f.rootResolves); assertTrue(f.store.snapshot().isEmpty());
        }
    }
    @Test void genuineButDifferentPrincipalRevisionOrAliasDoesNotResolveCatalogMaterial() throws Exception {
        for (int mode = 1; mode <= 3; mode++) {
            var f = new Fixture(mode); status(f.call(Route.ROOT), 403);
            assertEquals(1, f.coordinateReads.get()); assertEquals(0, f.rootChecks); assertTrue(f.store.snapshot().isEmpty());
        }
    }
    @Test void operationLatchAndActualTargetCustomerMismatchAreForbiddenBeforeNativeWork() throws Exception {
        var f = new Fixture();
        status(f.call(Route.ROOT, f.reference, f.command.identity().globalRequestId().toString(), false, true, null), 403);
        assertEquals(0, f.rootChecks); assertTrue(f.store.snapshot().isEmpty());
        var changed = new Fixture(); assertEquals("VIRTUAL_COMMITTED_IN_PROCESS", changed.call(Route.ROOT).getBody().get("status"));
        changed.changeWorkflow("customerId", "synthetic-other-customer"); var before = changed.store.snapshot(); int checks = changed.rootChecks;
        status(changed.call(Route.ROOT), 403); assertEquals(checks, changed.rootChecks); assertEquals(before, changed.store.snapshot());
    }
    @Test void nativeFiniteRefusalIsNotDomainAllowAndUnknownIsNotSuccessfulNoop() throws Exception {
        for (Gate gate : List.of(Gate.REFUSED, Gate.UNKNOWN)) {
            var f = new Fixture(); f.nativeGate = gate; var response = f.call(Route.ROOT);
            status(response, gate == Gate.REFUSED ? 200 : 503);
            assertEquals(gate == Gate.REFUSED ? "REFUSED_BEFORE_ADMISSION" : "UNCONFIRMED_BEFORE_ADMISSION", response.getBody().get("status"));
            assertFalse(response.getBody().containsKey("receipt")); assertEquals(false, response.getBody().get("actualAuthority"));
            assertTrue(f.rootChecks > 0); assertEquals(0, f.rootResolves); assertTrue(f.store.snapshot().isEmpty());
        }
    }
    @Test void changedNativeIdentityOnConsumedGlobalRequestProducesFinite409WithoutAnotherRoot() throws Exception {
        var f = new Fixture(); assertEquals("VIRTUAL_COMMITTED_IN_PROCESS", f.call(Route.ROOT).getBody().get("status"));
        var old = f.command; var i = old.identity();
        var changed = new CommandIdentity(i.actorId(), i.globalRequestId(), i.operation(), i.canonicalizationVersion(), "b".repeat(64),
            i.grantId(), i.actionId(), i.targetRunId(), i.workflowId(), i.generation(), i.customerId());
        f.command = new RootCommand(changed, old.inputs(), old.workflowPlan()); f.rebuildController(); var before = f.store.snapshot();
        var conflict = f.call(Route.ROOT); status(conflict, 409); assertTrue(conflict.getBody().toString().contains("IDENTITY_CONFLICT"));
        assertEquals(before, f.store.snapshot()); assertEquals(1, f.rootResolves);
    }
    @Test void reconcileWithoutAnyCommitRemainsUnknownAndDoesNotProvisionANewRoot() throws Exception {
        var f = new Fixture(); var response = f.call(Route.RECONCILE); status(response, 503);
        assertEquals("NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH", response.getBody().get("status"));
        assertFalse(response.getBody().containsKey("receipt")); assertEquals(1, f.rootChecks); assertEquals(0, f.rootResolves);
        assertTrue(f.store.snapshot().isEmpty());
    }
}
