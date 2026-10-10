package com.finsec.fuse.auth;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.SecurityPolicy;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Exact optional cross-origin allowlist. Same-origin needs no CORS permission. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public final class PublicHeaderFilter extends OncePerRequestFilter {
    private final Json json;private final SecurityPolicy policy;private final Set<String> origins;
    private static final Set<String> HEADERS=Set.of("authorization","content-type","idempotency-key");
    public PublicHeaderFilter(Json json,SecurityPolicy policy,Environment environment) {
        this.json=json;this.policy=policy;
        origins=Arrays.stream(environment.getProperty("FUSE_CORS_ALLOWED_ORIGINS","").split(",")).map(String::trim).filter(s->!s.isEmpty()).collect(Collectors.toUnmodifiableSet());
        for(String origin:origins){URI uri=URI.create(origin);if(!Set.of("http","https").contains(uri.getScheme())||uri.getHost()==null||uri.getRawUserInfo()!=null||uri.getRawQuery()!=null||uri.getRawFragment()!=null||uri.getRawPath()!=null&&!uri.getRawPath().isEmpty())throw new IllegalStateException("CORS origins must be exact scheme/host/port origins");}
    }
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain)throws IOException,ServletException {
        response.setHeader("X-Content-Type-Options","nosniff");response.setHeader("Referrer-Policy","no-referrer");response.setHeader("X-Frame-Options","DENY");
        response.setHeader("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
        if(!request.getRequestURI().startsWith("/api/")){chain.doFilter(request,response);return;}
        response.setHeader("Cache-Control","no-store");
        long bytes=2;
        for(String name:Collections.list(request.getHeaderNames()))for(String value:Collections.list(request.getHeaders(name))){bytes+=name.getBytes(StandardCharsets.UTF_8).length+value.getBytes(StandardCharsets.UTF_8).length+4;if(bytes>policy.httpHeaderMaxBytes()){PublicErrors.deny(json,response,431,"INVALID_REQUEST","Request headers exceed the allowed size");return;}}
        var supplied=Collections.list(request.getHeaders("Origin"));String origin=request.getHeader("Origin");
        boolean allowed=supplied.size()==1 && origins.contains(origin);
        if(allowed){response.setHeader("Access-Control-Allow-Origin",origin);response.addHeader("Vary","Origin");}
        if("OPTIONS".equals(request.getMethod())&&origin!=null){
            String method=request.getHeader("Access-Control-Request-Method");
            String requested=request.getHeader("Access-Control-Request-Headers");
            boolean headers=requested==null||Arrays.stream(requested.split(",")).map(String::trim).map(s->s.toLowerCase(Locale.ROOT)).allMatch(HEADERS::contains);
            if(!allowed||!DemoAuthFilter.allowed(method,request.getRequestURI())||!headers||Collections.list(request.getHeaders("Access-Control-Request-Method")).size()!=1){PublicErrors.deny(json,response,403,"FORBIDDEN","Cross-origin request is not allowed");return;}
            response.setHeader("Access-Control-Allow-Methods",method);response.setHeader("Access-Control-Allow-Headers","Authorization, Content-Type, Idempotency-Key");response.setStatus(204);return;
        }
        chain.doFilter(request,response);
    }
}
