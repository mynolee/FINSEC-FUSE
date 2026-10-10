package com.finsec.fuse.auth;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.config.SecurityPolicy;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.*;
import static org.junit.jupiter.api.Assertions.*;

/** Pure synthetic policy checks. These are not PostgreSQL or process-survival evidence. */
class DemoTokenLifecycleTest {
    private static final String TOKEN="a".repeat(64),OTHER="b".repeat(64);
    private static final Instant ISSUED=Instant.parse("2026-10-09T00:00:00Z");
    private static final Actor ACTOR=new Actor("customer-101","CUSTOMER",Set.of("customer-101"));
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private SecurityPolicy policy()throws Exception{return new JsonConfiguration().securityPolicy(json.mapper());}
    private static MockEnvironment environment() {
        var env=new MockEnvironment().withProperty("FUSE_DEV_CUSTOMER_101_TOKEN",TOKEN);env.setActiveProfiles("test");return env;
    }
    private static final class Authority implements DemoTokenStore {
        Instant now=ISSUED;boolean available=true;int reads;
        final Map<String,Credential> rows=new HashMap<>();
        void issue(String token,Actor actor) {String fingerprint=DevActorRegistry.fingerprint(token);rows.put(fingerprint,new Credential(fingerprint,actor,actor.customerIds(),ISSUED,ISSUED.plusSeconds(7200),Status.ACTIVE,null,0));}
        void scope(String token,Set<String> scope) {String key=DevActorRegistry.fingerprint(token);var old=rows.get(key);rows.put(key,new Credential(key,old.initialActor(),scope,old.issuedAt(),old.expiresAt(),old.status(),old.revokedAt(),old.revision()+1));}
        void revoke(String token) {String key=DevActorRegistry.fingerprint(token);var old=rows.get(key);rows.put(key,new Credential(key,old.initialActor(),old.currentScope(),old.issuedAt(),old.expiresAt(),Status.REVOKED,now,old.revision()+1));}
        @Override public Snapshot lookup(String fingerprint,List<Binding> configured) {
            reads++;if(!available)throw new Unavailable();
            for(var binding:configured){var row=rows.get(binding.fingerprint());if(row==null||!row.initialActor().equals(binding.actor()))throw new Unavailable();}
            return new Snapshot(now,fingerprint==null?null:rows.get(fingerprint));
        }
    }
    @Test void issuanceAndExpiryHaveExactBoundariesAndReadsArePure()throws Exception {
        var authority=new Authority();authority.issue(TOKEN,ACTOR);var initial=Map.copyOf(authority.rows);
        var registry=new DevActorRegistry(environment(),policy(),authority);
        assertEquals(0,authority.reads,"Construction must not consult or mutate authority");
        for(long delta:new long[]{-1,0,7199,7200,7201}) {
            authority.now=ISSUED.plusSeconds(delta);assertEquals(delta>=0&&delta<7200,registry.resolve(TOKEN)!=null);
            assertEquals(initial,authority.rows);
        }
        assertNull(registry.resolve(OTHER));assertEquals(initial,authority.rows);
    }
    @Test void reconstructionDoesNotIssueRefreshWidenOrUndoRevocation()throws Exception {
        var authority=new Authority();authority.issue(TOKEN,ACTOR);authority.scope(TOKEN,Set.of());
        var narrowed=authority.rows.get(DevActorRegistry.fingerprint(TOKEN));
        var first=new DevActorRegistry(environment(),policy(),authority);var second=new DevActorRegistry(environment(),policy(),authority);
        assertEquals(Set.of(),first.resolve(TOKEN).customerIds());assertEquals(first.resolve(TOKEN),second.resolve(TOKEN));
        assertEquals(narrowed,authority.rows.get(narrowed.fingerprint()));
        authority.revoke(TOKEN);authority.scope(TOKEN,Set.of("customer-101"));
        assertNull(first.resolve(TOKEN));assertNull(second.resolve(TOKEN));
        var revoked=authority.rows.get(narrowed.fingerprint());assertEquals(ISSUED,revoked.issuedAt());assertEquals(ISSUED.plusSeconds(7200),revoked.expiresAt());
        assertEquals(DemoTokenStore.Status.REVOKED,revoked.status());
    }
    @Test void missingAuthorityRecoversOnlyFromRestoredOriginalRecord()throws Exception {
        var authority=new Authority();var registry=new DevActorRegistry(environment(),policy(),authority);
        assertThrows(DemoTokenStore.Unavailable.class,registry::requireReady);assertTrue(authority.rows.isEmpty());
        authority.issue(TOKEN,ACTOR);var original=authority.rows.get(DevActorRegistry.fingerprint(TOKEN));
        assertNotNull(registry.resolve(TOKEN));authority.available=false;
        assertThrows(DemoTokenStore.Unavailable.class,()->registry.resolve(TOKEN));authority.available=true;
        assertEquals(original,authority.rows.get(original.fingerprint()));assertNotNull(registry.resolve(TOKEN));
    }
    @Test void expiredConfiguredBindingDoesNotHideSeparatelyIssuedCredential()throws Exception {
        var authority=new Authority();authority.issue(TOKEN,ACTOR);authority.now=ISSUED.plusSeconds(7200);
        String key=DevActorRegistry.fingerprint(OTHER);authority.rows.put(key,new DemoTokenStore.Credential(key,ACTOR,ACTOR.customerIds(),authority.now,authority.now.plusSeconds(7200),DemoTokenStore.Status.ACTIVE,null,0));
        var registry=new DevActorRegistry(environment(),policy(),authority);assertDoesNotThrow(registry::requireReady);
        assertNull(registry.resolve(TOKEN));assertNotNull(registry.resolve(OTHER));
    }
    @Test void configurationMismatchDoesNotOverwriteHistoricalBinding()throws Exception {
        var authority=new Authority();authority.issue(TOKEN,new Actor("other","CUSTOMER",Set.of("customer-101")));var before=Map.copyOf(authority.rows);
        var registry=new DevActorRegistry(environment(),policy(),authority);assertThrows(DemoTokenStore.Unavailable.class,()->registry.resolve(TOKEN));assertEquals(before,authority.rows);
    }
    @Test void inactiveOrMixedProfilesNeverResolveExtraPersistedCredentials()throws Exception {
        var authority=new Authority();authority.issue(OTHER,ACTOR);
        for(String[] profiles:List.of(new String[]{"prod"},new String[]{"demo","prod"})) {
            var env=new MockEnvironment().withProperty("FUSE_SERVICE_TOKEN",OTHER);env.setActiveProfiles(profiles);
            var registry=new DevActorRegistry(env,policy(),authority);assertNull(registry.resolve(OTHER));assertDoesNotThrow(registry::requireReady);
            env.setProperty("FUSE_DEV_CUSTOMER_101_TOKEN",TOKEN);assertThrows(IllegalStateException.class,()->new DevActorRegistry(env,policy(),authority));
        }
        assertEquals(0,authority.reads);
    }
    @Test void malformedTokensAreRejectedWithoutAuthorityReadsAndDuplicatesFailConstruction()throws Exception {
        var authority=new Authority();authority.issue(TOKEN,ACTOR);var registry=new DevActorRegistry(environment(),policy(),authority);
        for(String invalid:List.of("short","x".repeat(257),"=".repeat(64),"CHANGE_ME"))assertNull(registry.resolve(invalid));
        assertNull(registry.resolve(null));assertEquals(0,authority.reads);
        var env=environment().withProperty("FUSE_DEV_REVIEWER_TOKEN",TOKEN);assertThrows(IllegalStateException.class,()->new DevActorRegistry(env,policy(),authority));
        assertThrows(IllegalStateException.class,()->new DevActorRegistry(environment().withProperty("FUSE_DEV_CUSTOMER_101_TOKEN","short"),policy(),authority));
    }
    @Test void fingerprintIsStableExactUtf8AndNoRawBearerAppearsInAuthority() {
        assertEquals("ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",DevActorRegistry.fingerprint(TOKEN));
        assertNotEquals(DevActorRegistry.fingerprint(TOKEN),DevActorRegistry.fingerprint(TOKEN.toUpperCase(Locale.ROOT)));
        var authority=new Authority();authority.issue(TOKEN,ACTOR);assertFalse(authority.rows.toString().contains(TOKEN));
        assertFalse(new DemoTokenStore.Unavailable().toString().contains(TOKEN));
    }
    @Test void lookupFailureReturnsSanitized503OutsideMvcAndNeverCallsDownstream()throws Exception {
        DemoTokenStore missing=(fingerprint,bindings)->{throw new DemoTokenStore.Unavailable();};
        var filter=new DemoAuthFilter(new DevActorRegistry(environment(),policy(),missing),new AdmissionLimiter(policy()),json);
        String action="00000000-0000-4000-8000-000000000001";
        var request=new MockHttpServletRequest("POST","/api/v1/workflows");request.addHeader("Authorization","Bearer "+TOKEN);request.addHeader("Idempotency-Key",action);
        var response=new MockHttpServletResponse();var chain=new MockFilterChain();filter.doFilter(request,response,chain);
        assertEquals(503,response.getStatus());assertNull(chain.getRequest());assertEquals("no-store",response.getHeader("Cache-Control"));assertEquals("nosniff",response.getHeader("X-Content-Type-Options"));
        var body=json.map(response.getContentAsString());assertEquals(action,body.get("requestId"));assertEquals("ERROR",body.get("decision"));assertEquals(List.of("DEPENDENCY_UNAVAILABLE"),body.get("reasonCodes"));
        for(String field:List.of("workflowId","generation","state"))assertNull(body.get(field));assertEquals(false,body.get("replayed"));
        for(String secret:List.of(TOKEN,DevActorRegistry.fingerprint(TOKEN),"demo_token","SQLException"))assertFalse(response.getContentAsString().contains(secret));
    }
}
