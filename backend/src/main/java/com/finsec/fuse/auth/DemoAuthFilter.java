package com.finsec.fuse.auth;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Set;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Stateless Bearer-only API authentication; no cookie/session or Basic authentication. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE+10)
public final class DemoAuthFilter extends OncePerRequestFilter {
    private final DevActorRegistry registry;private final AdmissionLimiter limiter;private final Json json;
    @Autowired public DemoAuthFilter(DevActorRegistry registry,AdmissionLimiter limiter,Json json){this.registry=registry;this.limiter=limiter;this.json=json;}
    public DemoAuthFilter(Environment env,Json json) {
        this.json=json;
        try {var policy=new JsonConfiguration().securityPolicy(json.mapper());this.registry=new DevActorRegistry(env,policy);this.limiter=new AdmissionLimiter(policy);}
        catch(IOException failure){throw new IllegalStateException("Security policy unavailable",failure);}
    }
    @Override protected boolean shouldNotFilter(HttpServletRequest request){return !request.getRequestURI().startsWith("/api/");}
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain) throws IOException,ServletException {
        if(ambiguous(request,"Authorization")||ambiguous(request,"Idempotency-Key")) {
            if(!limiter.anonymous(request.getRemoteAddr())){rate(response);return;}
            PublicErrors.deny(json,response,400,"INVALID_REQUEST","Ambiguous authentication or action header");return;
        }
        String header=request.getHeader("Authorization");
        Actor actor=header!=null && header.matches("Bearer [A-Za-z0-9_-]+")?registry.resolve(header.substring(7)):null;
        if(actor==null){
            if(!limiter.anonymous(request.getRemoteAddr())){rate(response);return;}
            PublicErrors.deny(json,response,401,"UNAUTHENTICATED","A valid bearer token is required");return;
        }
        if(!limiter.actor(actor,"GET".equals(request.getMethod())||"HEAD".equals(request.getMethod()))){rate(response);return;}
        if(actor.is("KYC_SERVICE")||actor.is("FUSE_WORKER")){PublicErrors.deny(json,response,403,"FORBIDDEN","Service identities cannot access the public API");return;}
        if(!allowed(request.getMethod(),request.getRequestURI())){PublicErrors.deny(json,response,404,"NOT_FOUND","API route not found");return;}
        if(!allowedQueryNames(request)) {PublicErrors.deny(json,response,400,"INVALID_REQUEST","Unsupported query parameter");return;}
        request.setAttribute(ActorResolver.ATTRIBUTE,actor);
        response.setHeader("Cache-Control","no-store");response.setHeader("X-Content-Type-Options","nosniff");
        chain.doFilter(request,response);
    }
    private static boolean allowedQueryNames(HttpServletRequest request) {
        String query=request.getQueryString();
        if(query==null||query.isEmpty())return true;
        Set<String> allowed="GET".equals(request.getMethod()) && "/api/v1/workflows".equals(request.getRequestURI())
            ?Set.of("state","page","size"):Set.of();
        // Inspect only the URL. getParameterMap() may parse a form body before its size/media guard.
        var seen=new java.util.HashSet<String>();
        int start=0;
        while(start<=query.length()) {
            int end=query.indexOf('&',start);if(end<0)end=query.length();
            int equals=query.indexOf('=',start);
            int nameEnd=equals>=start && equals<end?equals:end;
            // Accepted ASCII names are at most five bytes, or fifteen percent-encoded characters.
            // Scan values without splitting/copying them, and bound allocation before decoding names.
            if(nameEnd-start>15)return false;
            try {
                String name=URLDecoder.decode(query.substring(start,nameEnd),StandardCharsets.UTF_8);
                if(!allowed.contains(name)||!seen.add(name))return false;
            } catch(IllegalArgumentException malformedEncoding) {return false;}
            if(end==query.length())break;
            start=end+1;
        }
        return true;
    }
    static boolean ambiguous(HttpServletRequest request,String name) {
        var values=Collections.list(request.getHeaders(name));
        return values.size()>1 || values.stream().anyMatch(v->v.indexOf(',')>=0||v.indexOf('\r')>=0||v.indexOf('\n')>=0);
    }
    private void rate(HttpServletResponse response)throws IOException{response.setHeader("Retry-After","60");PublicErrors.deny(json,response,429,"RATE_LIMITED","Request rate exceeded; retry after 60 seconds");}
    public static boolean allowed(String method,String path) {
        // UUID validation is performed by the DTO/controller. Keep malformed path IDs on that boundary.
        String segment="[^/;]+";
        if("GET".equals(method))return path.equals("/api/v1/workflows")||path.matches("/api/v1/workflows/"+segment+"(?:/trace|/approval-preview)?")||path.matches("/api/v1/incidents/"+segment+"/impact")||path.matches("/api/v1/experiments/"+segment);
        if("POST".equals(method))return path.equals("/api/v1/workflows")||path.equals("/api/v1/quarantines")||path.equals("/api/v1/experiments")||path.matches("/api/v1/workflows/"+segment+"/(approvals|resume)")||path.matches("/api/v1/quarantines/"+segment+"/release");
        return false;
    }
}
