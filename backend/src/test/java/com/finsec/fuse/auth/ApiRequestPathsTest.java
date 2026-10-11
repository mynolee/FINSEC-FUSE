package com.finsec.fuse.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic path representations; these tests do not establish real-container routing. */
class ApiRequestPathsTest {
    @Test void protectsExactApiAndCanonicalDescendants() {
        for(String path:new String[]{"/api","/api/","/api/v1/experiments"}) {
            assertTrue(protectedPath(path,path,null));
            assertTrue(protectedPath(path,"/unrelated",null));
            assertTrue(protectedPath("/unrelated",path,null));
        }
    }

    @Test void containerPathsProtectEncodedAndMatrixAliasesWithoutAuthorizingThem() {
        for(String raw:new String[]{"/%61pi/v1/experiments","/api;v=1/v1/experiments"}) {
            assertTrue(protectedPath(raw,"/api/v1/experiments",null));
            assertFalse(DemoAuthFilter.allowed("POST",raw));
        }
        assertTrue(DemoAuthFilter.allowed("POST","/api/v1/experiments"));
    }

    @Test void doesNotDecodeOrStripMatrixParametersItself() {
        for(String path:new String[]{"/%61pi/v1/x","/api;v=1/v1/x","/api%3Bv=1/v1/x",
                "/api%2Fv1/x","/%2561pi/v1/x"}) {
            assertFalse(protectedPath(path,path,null));
        }
        assertFalse(protectedPath("/%2561pi/v1/x","/%61pi/v1/x",null));
    }

    @Test void contextPathExpandsGuardCoverageButDoesNotExpandRawAllowlist() {
        var request=request("/ctx/api/v1/experiments","/api/v1/experiments",null);
        assertTrue(ApiRequestPaths.protectedApi(request));
        assertFalse(DemoAuthFilter.allowed("POST",request.getRequestURI()));
        assertTrue(protectedPath("/ctx/%61pi/v1/experiments","/api/v1/experiments",null));
        assertTrue(protectedPath("/ctx/api;v=1/v1/experiments","/api/v1/experiments",null));
    }

    @Test void combinesServletPathAndPathInfoIncludingEmptyServletPath() {
        assertTrue(protectedPath("/ctx/api/v1/x","","/api/v1/x"));
        assertTrue(protectedPath("/ctx/api","","/api"));
        assertTrue(protectedPath("/ctx/api/v1/x","/api","/v1/x"));
        assertFalse(protectedPath("/ctx/apix","/api","x"));
        assertFalse(protectedPath("/ctx/assets/api/x","/assets","/api/x"));
    }

    @Test void prefixServletMappingsRemainExplicitlyUnsupported() {
        assertFalse(protectedPath("/mvc/api/v1/x","/mvc","/api/v1/x"));
    }

    @Test void unrelatedPathsDoNotMatchSubstringsOrNearPrefixes() {
        for(String path:new String[]{"/apix","/api-v1","/API/v1/x","/assets/api/x",
                "/actuator/health","/internal/kyc","/",""}) {
            assertFalse(protectedPath(path,path,null));
        }
    }

    @Test void missingPathRepresentationsAreNullSafeAndRetainEitherCoverage() {
        assertFalse(protectedPath(null,null,null));
        assertFalse(protectedPath("",null,""));
        assertTrue(protectedPath("/api/v1/x",null,null));
        assertTrue(protectedPath(null,"/api",null));
        assertTrue(protectedPath(null,null,"/api/v1/x"));
    }

    @Test void forwardedHeadersCannotSupplyAnApiPath() {
        var original=new MockHttpServletRequest("GET","/assets/x");
        original.setServletPath("/assets/x");
        original.addHeader("X-Forwarded-Prefix","/api");
        original.addHeader("X-Original-URL","/api/v1/workflows");
        original.addHeader("X-Rewrite-URL","/api/v1/workflows");
        assertFalse(ApiRequestPaths.protectedApi(original));
    }

    private static boolean protectedPath(String raw,String servletPath,String pathInfo) {
        return ApiRequestPaths.protectedApi(request(raw,servletPath,pathInfo));
    }

    private static HttpServletRequest request(String raw,String servletPath,String pathInfo) {
        return new HttpServletRequestWrapper(new MockHttpServletRequest()) {
            @Override public String getRequestURI(){return raw;}
            @Override public String getServletPath(){return servletPath;}
            @Override public String getPathInfo(){return pathInfo;}
        };
    }
}
