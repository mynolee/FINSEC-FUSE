package com.finsec.fuse.foundation;

import com.finsec.fuse.auth.ActorResolver;
import com.finsec.fuse.auth.DemoAuthFilter;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.testing.DemoTokenTestFixture;
import com.finsec.fuse.config.JsonConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import static org.junit.jupiter.api.Assertions.*;

class DemoAuthFilterTest {
    private static final String CUSTOMER=DevActorRegistry.generateToken(), REVIEWER=DevActorRegistry.generateToken(), SERVICE=DevActorRegistry.generateToken();
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private MockEnvironment environment() {
        var env=new MockEnvironment().withProperty("FUSE_DEV_CUSTOMER_101_TOKEN",CUSTOMER)
            .withProperty("FUSE_DEV_REVIEWER_TOKEN",REVIEWER).withProperty("FUSE_SERVICE_TOKEN",SERVICE);
        env.setActiveProfiles("test");return env;
    }
    @Test void missingOrPlaceholderTokensNeverAuthenticate() throws Exception {
        var env=environment().withProperty("FUSE_DEV_SECURITY_TOKEN","CHANGE_ME");
        var filter=DemoTokenTestFixture.filter(env,json);
        var request=new MockHttpServletRequest("GET","/api/v1/workflows");
        request.addHeader("Authorization","Bearer CHANGE_ME");
        var response=new MockHttpServletResponse();var chain=new MockFilterChain();
        filter.doFilter(request,response,chain);
        assertEquals(401,response.getStatus());assertNull(chain.getRequest());
    }
    @Test void pythonServiceIdentityCannotCallPublicApprovalApi() throws Exception {
        var filter=DemoTokenTestFixture.filter(environment(),json);
        var request=new MockHttpServletRequest("POST","/api/v1/workflows/00000000-0000-4000-8000-000000000102/approvals");
        request.addHeader("Authorization","Bearer "+SERVICE);
        var response=new MockHttpServletResponse();var chain=new MockFilterChain();
        filter.doFilter(request,response,chain);
        assertEquals(403,response.getStatus());assertNull(chain.getRequest());
        assertEquals(java.util.List.of("FORBIDDEN"),json.map(response.getContentAsString()).get("reasonCodes"));
    }
    @Test void principalAndScopeComeOnlyFromServerTokenMapping() throws Exception {
        var filter=DemoTokenTestFixture.filter(environment(),json);
        var request=new MockHttpServletRequest("POST","/api/v1/workflows");
        request.addHeader("Authorization","Bearer "+CUSTOMER);
        request.setContent("{\"principalId\":\"staff-01\",\"role\":\"LOAN_REVIEWER\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        var response=new MockHttpServletResponse();var chain=new MockFilterChain();
        filter.doFilter(request,response,chain);
        assertNotNull(chain.getRequest());
        var actor=ActorResolver.current(request);assertEquals("customer-101",actor.actorId());
        assertEquals("CUSTOMER",actor.role());assertFalse(actor.canAccess("customer-102"));
    }
    @Test void duplicateRoleTokensFailConfigurationInsteadOfAmbiguouslyResolving() {
        var env=environment().withProperty("FUSE_DEV_REVIEWER_TOKEN",CUSTOMER);
        assertThrows(IllegalStateException.class,()->DemoTokenTestFixture.filter(env,json));
    }
}
