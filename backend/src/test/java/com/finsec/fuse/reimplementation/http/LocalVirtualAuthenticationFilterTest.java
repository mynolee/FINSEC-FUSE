package com.finsec.fuse.reimplementation.http;

import com.finsec.fuse.reimplementation.auth.*;
import com.finsec.fuse.reimplementation.simulation.SimulationFailure;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import static org.junit.jupiter.api.Assertions.*;

/** Actual filter/registry/context protocol on synthetic mock requests, never container registration. */
class LocalVirtualAuthenticationFilterTest {
    static final String CUSTOMER = "synthetic-auth-customer";
    static final String OTHER = "synthetic-other-customer";
    static final String CANARY = "synthetic-private-header-or-exception-canary";
    static final UUID WORKFLOW = new UUID(0, 710), SECOND = new UUID(0, 711);
    static final Instant NOW = Instant.parse("2030-01-01T00:00:00Z");
    static final class Fixture {
        final LocalVirtualTokenRegistry registry = new LocalVirtualTokenRegistry(2);
        final TokenMaterialCodec.Material material = TokenMaterialCodec.encode(new byte[32]);
        final UUID token = new UUID(0, 712), principalId = new UUID(0, 713);
        final AtomicInteger verifications = new AtomicInteger();
        LocalVirtualPrincipal principal = new LocalVirtualPrincipal(principalId, "synthetic-http-actor", 1,
            LocalVirtualPrincipal.Status.ACTIVE, Set.of(TokenRegistryInput.Role.CUSTOMER),
            Set.of(CUSTOMER, OTHER), Map.of(WORKFLOW, CUSTOMER, SECOND, OTHER), 4);
        boolean verifierUnknown;
        final LocalVirtualAdmissionContext context;
        final LocalVirtualAuthenticationFilter filter;
        final LocalVirtualHttpActors actors;
        Fixture() {
            registry.registerPrepared(new LocalVirtualTokenRegistry.Credential(token, principalId,
                LocalVirtualTokenRegistry.Status.ACTIVE, 0, NOW.minusSeconds(1), NOW.plusSeconds(60), 1, material.fingerprint()));
            context = new LocalVirtualAdmissionContext((requested, now) -> {
                verifications.incrementAndGet();
                var actual = registry.revalidateReference(requested.tokenId(), requested.principalId(), requested.tokenRevision(),
                    requested.bindingRevision(), requested.issuedAt(), requested.expiresAt(), now);
                var state = verifierUnknown ? LocalVirtualAdmissionContext.CredentialState.UNCONFIRMED
                    : actual.status() == LocalVirtualTokenRegistry.LookupStatus.FOUND
                        ? LocalVirtualAdmissionContext.CredentialState.ACTIVE : LocalVirtualAdmissionContext.CredentialState.ABSENT;
                return new LocalVirtualAdmissionContext.VerifiedSnapshot(requested, state, principal);
            }, registry);
            actors = new LocalVirtualHttpActors(context);
            filter = new LocalVirtualAuthenticationFilter(registry, context, Clock.fixed(NOW, ZoneOffset.UTC), new PublicHttpErrors());
        }
        MockHttpServletRequest request() {
            var request = new MockHttpServletRequest(); request.setDispatcherType(DispatcherType.REQUEST);
            request.addHeader("Authorization", "Bearer " + material.bearer()); return request;
        }
        MockHttpServletResponse invoke(MockHttpServletRequest request, FilterChain chain) throws Exception {
            var response = new MockHttpServletResponse(); filter.doFilter(request, response, chain); return response;
        }
    }
    static void fixed(MockHttpServletResponse response, int status, String code) throws Exception {
        assertEquals(status, response.getStatus()); assertTrue(response.getContentType().startsWith("application/json"));
        assertTrue(response.getContentAsString().contains(code)); assertFalse(response.getContentAsString().contains(CANARY));
        assertFalse(response.getContentAsString().contains("A".repeat(43)));
    }
    @Test void genuineCanonicalRegistryEvidenceMakesOnlySynchronousPrivateCarrierLiveUntilFinally() throws Exception {
        var f = new Fixture(); var original = f.request(); var calls = new AtomicInteger();
        LocalVirtualAdmissionContext.Admission[] escaped = new LocalVirtualAdmissionContext.Admission[1];
        var response = f.invoke(original, (request, out) -> {
            calls.incrementAndGet(); assertNotSame(original, request);
            escaped[0] = f.context.current(); assertNotNull(escaped[0]);
            assertEquals(f.principalId, escaped[0].principal().principalId());
            assertFalse(request.isAsyncSupported());
            assertThrows(IllegalStateException.class, request::startAsync);
        });
        assertEquals(200, response.getStatus()); assertEquals(1, calls.get()); assertEquals(1, f.verifications.get());
        assertNull(f.context.current());
        assertEquals(LocalVirtualAdmissionContext.Code.UNAVAILABLE,
            assertThrows(LocalVirtualAdmissionContext.Failure.class, escaped[0]::actor).code());
        assertFalse(Collections.list(original.getAttributeNames()).contains("localVirtualAdmission"));
    }
    @Test void missingNoncanonicalMultipleAndUnknownCanonicalCredentialsNeverEnterTheChain() throws Exception {
        for (int mode = 0; mode < 4; mode++) {
            var f = new Fixture(); var request = f.request();
            if (mode == 0) request.removeHeader("Authorization");
            if (mode == 1) { request.removeHeader("Authorization"); request.addHeader("Authorization", "Bearer " + "A".repeat(42) + "B"); }
            if (mode == 2) request.addHeader("Authorization", "Bearer " + f.material.bearer());
            if (mode == 3) { request.removeHeader("Authorization"); request.addHeader("Authorization", "Bearer " + "_".repeat(42) + "8"); }
            fixed(f.invoke(request, (r, out) -> fail("No authenticated chain")), 401, "UNAUTHENTICATED");
            assertEquals(0, f.verifications.get()); assertNull(f.context.current());
        }
    }
    @Test void revokedRegistryAndDisabledCurrentPrincipalRefuseBeforeAnyController() throws Exception {
        var revoked = new Fixture(); revoked.registry.revoke(revoked.token, 0);
        fixed(revoked.invoke(revoked.request(), (r, out) -> fail("No revoked chain")), 401, "UNAUTHENTICATED");
        assertEquals(0, revoked.verifications.get());
        var disabled = new Fixture(); var p = disabled.principal;
        disabled.principal = new LocalVirtualPrincipal(p.principalId(), p.actorAlias(), p.bindingRevision(),
            LocalVirtualPrincipal.Status.DISABLED, p.roles(), p.customerAssignments(), p.workflowAssignments(), p.maximumAssignments());
        fixed(disabled.invoke(disabled.request(), (r, out) -> fail("No disabled chain")), 401, "UNAUTHENTICATED");
        assertEquals(1, disabled.verifications.get()); assertNull(disabled.context.current());
    }
    @Test void unconfirmedCurrentVerifierIsDependencyUnavailableNotAnAuthenticatedDefault() throws Exception {
        var f = new Fixture(); f.verifierUnknown = true;
        fixed(f.invoke(f.request(), (r, out) -> fail("No unknown chain")), 503, "DEPENDENCY_UNAVAILABLE");
        assertEquals(1, f.verifications.get()); assertNull(f.context.current());
    }
    @Test void ordinaryChainFailuresAlwaysRetireAdmissionAndRedactPublicErrors() throws Exception {
        for (int mode = 0; mode < 3; mode++) {
            var f = new Fixture(); final int fault = mode;
            fixed(f.invoke(f.request(), (r, out) -> {
                assertNotNull(f.context.current());
                if (fault == 0) throw new IOException(CANARY);
                if (fault == 1) throw new ServletException(CANARY);
                throw new IllegalStateException(CANARY);
            }), 503, "DEPENDENCY_UNAVAILABLE");
            assertNull(f.context.current());
        }
    }
    @Test void fixedDomainAndHttpRejectionsPreserveTheirPublicStatusAfterClose() throws Exception {
        var domain = new Fixture();
        fixed(domain.invoke(domain.request(), (r, out) -> { throw SimulationFailure.forbidden(); }), 403, "FORBIDDEN");
        assertNull(domain.context.current());
        var bounded = new Fixture();
        fixed(bounded.invoke(bounded.request(), (r, out) -> { throw new PublicHttpErrors.Rejected(PublicHttpErrors.Error.REQUEST_TOO_LARGE); }), 413, "REQUEST_TOO_LARGE");
        assertNull(bounded.context.current());
    }
    @Test void asyncOrRedispatchedRequestIsInvalidBeforeBearerVerification() throws Exception {
        for (DispatcherType type : List.of(DispatcherType.ASYNC, DispatcherType.ERROR, DispatcherType.FORWARD)) {
            var f = new Fixture(); var request = f.request(); request.setDispatcherType(type);
            fixed(f.invoke(request, (r, out) -> fail("No redispatch")), 400, "INVALID_REQUEST");
            assertEquals(0, f.verifications.get());
        }
        var f = new Fixture(); var request = f.request(); request.setAsyncStarted(true);
        fixed(f.invoke(request, (r, out) -> fail("No active async")), 400, "INVALID_REQUEST");
        assertEquals(0, f.verifications.get());
    }
    @Test void nestedSameThreadAdmissionRefusesWithoutClosingTheOuterFrameEarly() throws Exception {
        var f = new Fixture();
        f.invoke(f.request(), (r, out) -> {
            var outer = f.context.current(); var innerResponse = new MockHttpServletResponse();
            f.filter.doFilter(f.request(), innerResponse, (inner, ignored) -> fail("No nested frame"));
            assertEquals(503, innerResponse.getStatus()); assertSame(outer, f.context.current());
            assertEquals(f.principalId, outer.principal().principalId());
        });
        assertEquals(1, f.verifications.get()); assertNull(f.context.current());
    }
    @Test void canonicalEvidenceIsAvailableOnlyOnSameLivePrivateCarrierWithoutReadingHeaderAgain() throws Exception {
        var f=new Fixture();var foreign=new Fixture();
        class NoReparseRequest extends MockHttpServletRequest {
            boolean admitted;
            @Override public Enumeration<String> getHeaders(String name) {
                if(admitted)throw new AssertionError("No header reparsing after canonical admission");
                return super.getHeaders(name);
            }
        }
        var original=new NoReparseRequest();original.setDispatcherType(DispatcherType.REQUEST);
        original.addHeader("Authorization","Bearer "+f.material.bearer());
        HttpServletRequest[] escaped=new HttpServletRequest[1];
        var response=f.invoke(original,(request,out)->{
            original.admitted=true;var bound=(HttpServletRequest)request;escaped[0]=bound;
            var proof=LocalVirtualAuthenticationFilter.canonicalCredential(bound,f.context);
            assertTrue(proof.issuedBy(f.registry));assertFalse(proof.issuedBy(foreign.registry));
            assertEquals(f.context.current().credential(),proof.reference());
            assertSame(proof,LocalVirtualAuthenticationFilter.canonicalCredential(bound,f.context));
            assertEquals(401,assertThrows(SimulationFailure.class,
                ()->LocalVirtualAuthenticationFilter.canonicalCredential(bound,foreign.context)).status());
            assertEquals(401,assertThrows(SimulationFailure.class,
                ()->LocalVirtualAuthenticationFilter.canonicalCredential(new jakarta.servlet.http.HttpServletRequestWrapper(bound),f.context)).status());
            original.setAttribute("credentialEvidence",proof);
            assertEquals(401,assertThrows(SimulationFailure.class,
                ()->LocalVirtualAuthenticationFilter.canonicalCredential(original,f.context)).status());
        });
        assertEquals(200,response.getStatus());assertEquals(1,f.verifications.get());assertNull(f.context.current());
        assertEquals(401,assertThrows(SimulationFailure.class,
            ()->LocalVirtualAuthenticationFilter.canonicalCredential(escaped[0],f.context)).status());
        var next=f.invoke(f.request(),(request,out)->{
            assertEquals(401,assertThrows(SimulationFailure.class,
                ()->LocalVirtualAuthenticationFilter.canonicalCredential(escaped[0],f.context)).status());
            assertNotNull(LocalVirtualAuthenticationFilter.canonicalCredential((HttpServletRequest)request,f.context));
        });
        assertEquals(200,next.getStatus());assertNull(f.context.current());
    }

    @Test void framingUsesOnlyLivePrivateFrameAndDirectInspectedUpstream() throws Exception {
        for (boolean chunked : new boolean[] {false, true}) {
            var f = new Fixture(); var raw = f.request(); raw.setMethod("GET");
            if (chunked) raw.addHeader("Transfer-Encoding", "chunked");
            var response = new MockHttpServletResponse(); var calls = new AtomicInteger();
            HttpServletRequest[] escaped = new HttpServletRequest[1];
            var bounded = new BoundedRequestFilter(new RequestGuard(new HttpLimits(4096, 1024, 8)), new PublicHttpErrors());
            bounded.doFilter(raw, response, (cached, out) -> f.filter.doFilter(cached, out, (bound, output) -> {
                calls.incrementAndGet(); escaped[0] = (HttpServletRequest) bound;
                assertNull(escaped[0].getHeader("Transfer-Encoding"));
                assertEquals(chunked ? BoundedRequestFilter.Framing.PRESENT : BoundedRequestFilter.Framing.ABSENT,
                    LocalVirtualAuthenticationFilter.originalTransferEncoding(escaped[0], f.context));
                assertThrows(SimulationFailure.class, () -> LocalVirtualAuthenticationFilter.originalTransferEncoding(
                    new jakarta.servlet.http.HttpServletRequestWrapper(escaped[0]), f.context));
                assertThrows(SimulationFailure.class, () -> LocalVirtualAuthenticationFilter.originalTransferEncoding(
                    escaped[0], new Fixture().context));
            }));
            assertEquals(200, response.getStatus()); assertEquals(1, calls.get()); assertNull(f.context.current());
            assertThrows(SimulationFailure.class, () -> LocalVirtualAuthenticationFilter.originalTransferEncoding(escaped[0], f.context));
        }
        var direct = new Fixture(); var calls = new AtomicInteger();
        assertEquals(200, direct.invoke(direct.request(), (request, out) -> {
            calls.incrementAndGet();
            assertEquals(BoundedRequestFilter.Framing.UNCONFIRMED,
                LocalVirtualAuthenticationFilter.originalTransferEncoding((HttpServletRequest) request, direct.context));
        }).getStatus());
        assertEquals(1, calls.get());
    }

}
