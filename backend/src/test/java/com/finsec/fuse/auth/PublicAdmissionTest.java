package com.finsec.fuse.auth;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.testing.DemoTokenTestFixture;
import com.finsec.fuse.config.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.*;
import static org.junit.jupiter.api.Assertions.*;

class PublicAdmissionTest {
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private final SecurityPolicy policy=policy();
    private SecurityPolicy policy(){try{return new JsonConfiguration().securityPolicy(json.mapper());}catch(Exception e){throw new AssertionError(e);}}
    private static final class TestClock extends Clock {
        Instant now=Instant.parse("2026-10-09T00:00:00Z");
        public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId zone){return this;}public Instant instant(){return now;}
        void advance(long seconds){now=now.plusSeconds(seconds);}
    }
    private MockEnvironment env(String token){var env=new MockEnvironment().withProperty("FUSE_DEV_CUSTOMER_101_TOKEN",token);env.setActiveProfiles("test");return env;}
    @Test void tokensAreRandomBoundedExpireExactlyAndCannotBeReactivatedByScopeUpdates(){
        String token=DevActorRegistry.generateToken();assertEquals(32,Base64.getUrlDecoder().decode(token).length);assertNotEquals(token,DevActorRegistry.generateToken());
        var clock=new TestClock();var fixture=new DemoTokenTestFixture(env(token),policy,clock);var registry=fixture.registry();
        assertTrue(registry.resolve(token).canAccess("customer-101"));fixture.updateScope("customer-101",Set.of());assertFalse(registry.resolve(token).canAccess("customer-101"));
        clock.advance(7199);assertNotNull(registry.resolve(token));clock.advance(1);assertNull(registry.resolve(token));
        String other=DevActorRegistry.generateToken();fixture.issue(other,new Actor("other","CUSTOMER",Set.of("customer-102")));
        fixture.revoke("other");fixture.updateScope("other",Set.of("customer-102"));assertNull(registry.resolve(other));
    }
    @Test void weakTokensAndMixedProductionProfilesFailClosed(){
        assertThrows(IllegalStateException.class,()->new DemoTokenTestFixture(env("test-only-short"),policy,new TestClock()));
        var env=env(DevActorRegistry.generateToken());env.setActiveProfiles("prod","demo");assertThrows(IllegalStateException.class,()->new DemoTokenTestFixture(env,policy,new TestClock()));
    }
    @Test void actorReadWriteAndAnonymousWindowsHaveExactBoundariesAndIndependentActors(){
        var clock=new TestClock();var limiter=new AdmissionLimiter(policy,clock);var actor=new Actor("a","CUSTOMER",Set.of());
        for(int i=0;i<120;i++)assertTrue(limiter.actor(actor,true));assertFalse(limiter.actor(actor,true));
        for(int i=0;i<20;i++)assertTrue(limiter.actor(actor,false));assertFalse(limiter.actor(actor,false));
        assertTrue(limiter.actor(new Actor("b","CUSTOMER",Set.of()),true));
        for(int i=0;i<30;i++)assertTrue(limiter.anonymous("127.0.0.1"));assertFalse(limiter.anonymous("127.0.0.1"));
        clock.advance(59);assertFalse(limiter.actor(actor,true));clock.advance(1);assertTrue(limiter.actor(actor,true));assertTrue(limiter.anonymous("127.0.0.1"));
    }
    @Test void concurrentRequestsCannotOvershootWriteLimit()throws Exception{
        var limiter=new AdmissionLimiter(policy,new TestClock());var actor=new Actor("a","CUSTOMER",Set.of());var allowed=new AtomicInteger();
        try(var executor=Executors.newFixedThreadPool(8)){List<Future<?>> futures=new ArrayList<>();for(int i=0;i<100;i++)futures.add(executor.submit(()->{if(limiter.actor(actor,false))allowed.incrementAndGet();}));for(var future:futures)future.get();}
        assertEquals(20,allowed.get());
    }
    @Test void cookiesDoNotAuthenticateAndSpoofedForwardingCannotResetAnonymousRate()throws Exception{
        var token=DevActorRegistry.generateToken();var filter=DemoTokenTestFixture.filter(env(token),json);
        for(int i=0;i<31;i++){var req=new MockHttpServletRequest("GET","/api/v1/workflows");req.setRemoteAddr("127.0.0.1");req.addHeader("X-Forwarded-For","192.0.2."+i);req.addHeader("Cookie","Authorization=Bearer "+token);var res=new MockHttpServletResponse();var chain=new MockFilterChain();filter.doFilter(req,res,chain);assertEquals(i<30?401:429,res.getStatus());assertNull(chain.getRequest());if(i==30)assertEquals("60",res.getHeader("Retry-After"));}
    }
    @Test void duplicateAndCombinedAuthorityHeadersAreRejectedBeforeWork()throws Exception{
        for(String name:List.of("Authorization","Idempotency-Key"))for(boolean combined:List.of(false,true)){
            var token=DevActorRegistry.generateToken();var filter=DemoTokenTestFixture.filter(env(token),json);var req=new MockHttpServletRequest("POST","/api/v1/workflows");
            if(!name.equals("Authorization"))req.addHeader("Authorization","Bearer "+token);
            req.addHeader(name,combined?"one,two":"one");if(!combined)req.addHeader(name,"two");var res=new MockHttpServletResponse();var chain=new MockFilterChain();filter.doFilter(req,res,chain);assertEquals(400,res.getStatus());assertNull(chain.getRequest());
        }
    }
    @Test void authenticatedRateRejectsBeforeWorkAcrossRemoteAddresses()throws Exception{
        String token=DevActorRegistry.generateToken();var filter=DemoTokenTestFixture.filter(env(token),json);
        for(int i=0;i<21;i++){
            var request=new MockHttpServletRequest("POST","/api/v1/workflows");request.setRemoteAddr("192.0.2."+i);request.addHeader("Authorization","Bearer "+token);
            var response=new MockHttpServletResponse();var chain=new MockFilterChain();filter.doFilter(request,response,chain);
            assertEquals(i<20?200:429,response.getStatus());if(i<20)assertNotNull(chain.getRequest());else assertNull(chain.getRequest());
        }
    }
    @Test void everyRequestResolvesCurrentScopeExpiryAndRevocation()throws Exception{
        String token=DevActorRegistry.generateToken();var clock=new TestClock();var fixture=new DemoTokenTestFixture(env(token),policy,clock);var registry=fixture.registry();var filter=new DemoAuthFilter(registry,new AdmissionLimiter(policy,clock),json);
        for(int step=0;step<3;step++){
            if(step==1)fixture.updateScope("customer-101",Set.of());if(step==2)fixture.revoke("customer-101");
            var request=new MockHttpServletRequest("GET","/api/v1/workflows");request.addHeader("Authorization","Bearer "+token);var response=new MockHttpServletResponse();var chain=new MockFilterChain();filter.doFilter(request,response,chain);
            if(step<2){assertEquals(200,response.getStatus());assertEquals(step==0,ActorResolver.current(request).canAccess("customer-101"));}else{assertEquals(401,response.getStatus());assertNull(chain.getRequest());}
        }
    }
    @Test void actualCorsRequestsStillRequireBearerAndNeverGrantSuffixOrigins()throws Exception{
        var headers=new PublicHeaderFilter(json,policy,new MockEnvironment().withProperty("FUSE_CORS_ALLOWED_ORIGINS","http://localhost:5173"));
        var auth=DemoTokenTestFixture.filter(env(DevActorRegistry.generateToken()),json);
        for(String origin:List.of("http://localhost:5173","http://localhost:5173.evil.test")){
            var request=new MockHttpServletRequest("GET","/api/v1/workflows");request.addHeader("Origin",origin);var response=new MockHttpServletResponse();
            headers.doFilter(request,response,(req,res)->auth.doFilter(req,res,new MockFilterChain()));assertEquals(401,response.getStatus());assertEquals("no-store",response.getHeader("Cache-Control"));
            assertEquals(origin.equals("http://localhost:5173")?origin:null,response.getHeader("Access-Control-Allow-Origin"));assertNull(response.getHeader("Access-Control-Allow-Credentials"));
        }
    }
    @Test void rawJsonRejectsDepthDuplicatesMultipleValuesInvalidUtf8AndScalarRoots()throws Exception{
        for(byte[] body:List.of("{\"x\":1,\"x\":2}".getBytes(),"{} {}".getBytes(),"[]".getBytes(),"null".getBytes(),("{\"x\":".repeat(17)+"0"+"}".repeat(17)).getBytes(),new byte[]{'{','"','x','"',':','"',(byte)0xc3,'"','}'}))assertGuard(body,"application/json",null,400);
    }
    @Test void streamingBodyLimitWorksWithoutContentLengthAndBoundariesAreAccepted()throws Exception{
        for(int length:List.of(65535,65536,65537)){
            byte[] body=("{\"x\":\""+"a".repeat(length-8)+"\"}").getBytes(StandardCharsets.UTF_8);assertEquals(length,body.length);
            assertGuard(body,"application/json",null,length>65536?413:200);
        }
    }
    @Test void compressedAndUnsupportedMediaNeverReachController()throws Exception{
        assertGuard("{}".getBytes(),"text/plain",null,415);assertGuard("{}".getBytes(),"application/json","gzip",415);assertGuard("{}".getBytes(),"application/json; charset=ISO-8859-1",null,415);
    }
    private void assertGuard(byte[] body,String media,String encoding,int expected)throws Exception{
        var request=new MockHttpServletRequest("POST","/api/v1/workflows"){@Override public long getContentLengthLong(){return -1;}@Override public int getContentLength(){return -1;}};
        request.setContent(body);request.setContentType(media);if(encoding!=null)request.addHeader("Content-Encoding",encoding);
        var response=new MockHttpServletResponse();var chain=new MockFilterChain();new JsonRequestGuard(json,policy).doFilter(request,response,chain);assertEquals(expected,response.getStatus());
        if(expected==200){assertNotNull(chain.getRequest());assertArrayEquals(body,chain.getRequest().getInputStream().readAllBytes());}else{assertNull(chain.getRequest());assertNull(json.map(response.getContentAsString()).get("state"));}
    }
    @Test void exactCorsPreflightAndHeaderBudgetAreEnforced()throws Exception{
        var env=new MockEnvironment().withProperty("FUSE_CORS_ALLOWED_ORIGINS","http://localhost:5173");var filter=new PublicHeaderFilter(json,policy,env);
        for(String origin:List.of("http://localhost:5173","http://localhost:5173.evil.test","null","https://localhost:5173")){
            var request=new MockHttpServletRequest("OPTIONS","/api/v1/workflows");request.addHeader("Origin",origin);request.addHeader("Access-Control-Request-Method","POST");request.addHeader("Access-Control-Request-Headers","Authorization, Idempotency-Key, Content-Type");var response=new MockHttpServletResponse();var chain=new MockFilterChain();filter.doFilter(request,response,chain);
            assertEquals(origin.equals("http://localhost:5173")?204:403,response.getStatus());assertNull(response.getHeader("Access-Control-Allow-Credentials"));assertNull(chain.getRequest());
        }
        var request=new MockHttpServletRequest("GET","/api/v1/workflows");request.addHeader("X-Large","a".repeat(16384));var response=new MockHttpServletResponse();var chain=new MockFilterChain();filter.doFilter(request,response,chain);assertEquals(431,response.getStatus());assertNull(chain.getRequest());
    }
}
