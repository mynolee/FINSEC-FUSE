package com.finsec.fuse.auth;

import com.finsec.fuse.common.Json;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;

final class PublicErrors {
    private PublicErrors() {}
    static void deny(Json json,HttpServletResponse response,int status,String reason,String message) throws IOException {
        envelope(json,response,status,"DENY",reason,message,null);
    }
    static void unavailable(Json json,HttpServletResponse response,HttpServletRequest request)throws IOException {
        java.util.UUID action=null;
        try {if(request.getHeader("Idempotency-Key")!=null)action=com.finsec.fuse.config.PublicUuidConfiguration.parseCanonical(request.getHeader("Idempotency-Key"));}
        catch(IllegalArgumentException ignored) { /* Echo only a validated action identifier. */ }
        envelope(json,response,503,"ERROR","DEPENDENCY_UNAVAILABLE","Authentication dependencies are unavailable. Retry after recovery.",action);
    }
    private static void envelope(Json json,HttpServletResponse response,int status,String decision,String reason,String message,Object action)throws IOException {
        response.setStatus(status);response.setContentType("application/json");response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control","no-store");response.setHeader("X-Content-Type-Options","nosniff");
        response.getOutputStream().write(json.bytes(Json.ordered("requestId",action,"workflowId",null,"generation",null,"state",null,"decision",decision,"reasonCodes",List.of(reason),"message",message,"replayed",false)));
    }
}
