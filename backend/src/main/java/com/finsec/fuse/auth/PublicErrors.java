package com.finsec.fuse.auth;

import com.finsec.fuse.common.Json;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

final class PublicErrors {
    private PublicErrors() {}
    static void deny(Json json,HttpServletResponse response,int status,String reason,String message) throws IOException {
        response.setStatus(status);response.setContentType("application/json");response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control","no-store");response.setHeader("X-Content-Type-Options","nosniff");
        response.getOutputStream().write(json.bytes(Json.ordered("requestId",null,"workflowId",null,"generation",null,"state",null,"decision","DENY","reasonCodes",List.of(reason),"message",message,"replayed",false)));
    }
}
