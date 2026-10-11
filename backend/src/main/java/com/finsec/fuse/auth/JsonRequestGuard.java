package com.finsec.fuse.auth;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.SecurityPolicy;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CodingErrorAction;
import java.util.Collections;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Bounded streaming read before binding/fingerprinting or any business work. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE+20)
public final class JsonRequestGuard extends OncePerRequestFilter {
    private final Json json;private final SecurityPolicy policy;
    public JsonRequestGuard(Json json,SecurityPolicy policy){this.json=json;this.policy=policy;}
    @Override protected boolean shouldNotFilter(HttpServletRequest request){return !request.getRequestURI().startsWith("/api/");}
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain)throws IOException,ServletException {
        if(request.getHeader("Content-Encoding")!=null){reject(response,415,"UNSUPPORTED_MEDIA_TYPE","Compressed request bodies are unsupported");return;}
        if(request.getContentLengthLong()>policy.publicRequestMaxBytes()){reject(response,413,"REQUEST_TOO_LARGE","Request body exceeds the allowed size");return;}
        byte[] body=request.getInputStream().readNBytes(policy.publicRequestMaxBytes()+1);
        if(body.length>policy.publicRequestMaxBytes()){reject(response,413,"REQUEST_TOO_LARGE","Request body exceeds the allowed size");return;}
        if(body.length>0 || "POST".equals(request.getMethod())) {
            if(!jsonMedia(request)){reject(response,415,"UNSUPPORTED_MEDIA_TYPE","Only application/json with UTF-8 is supported");return;}
            if(!"POST".equals(request.getMethod())){reject(response,400,"INVALID_REQUEST","This method does not accept a request body");return;}
            try {
                String text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(body)).toString();
                var tree=json.mapper().readTree(text);
                if(tree==null||!tree.isObject())throw new IllegalArgumentException();
            }catch(RuntimeException|java.nio.charset.CharacterCodingException invalid){reject(response,400,"INVALID_REQUEST","Invalid JSON request");return;}
        }
        chain.doFilter(new BufferedRequest(request,body),response);
    }
    private static boolean jsonMedia(HttpServletRequest request) {
        if(Collections.list(request.getHeaders("Content-Type")).size()!=1)return false;
        try {var type=MediaType.parseMediaType(request.getContentType());return type.getType().equalsIgnoreCase("application")&&type.getSubtype().equalsIgnoreCase("json")&&(type.getCharset()==null||type.getCharset().equals(StandardCharsets.UTF_8))&&type.getParameters().keySet().stream().allMatch("charset"::equalsIgnoreCase);}
        catch(IllegalArgumentException invalid){return false;}
    }
    private void reject(HttpServletResponse response,int status,String reason,String message)throws IOException{PublicErrors.deny(json,response,status,reason,message);}
    private static final class BufferedRequest extends HttpServletRequestWrapper {
        private final byte[] body;
        BufferedRequest(HttpServletRequest original,byte[] body){super(original);this.body=body;}
        @Override public int getContentLength(){return body.length;}
        @Override public long getContentLengthLong(){return body.length;}
        @Override public ServletInputStream getInputStream(){
            var input=new ByteArrayInputStream(body);
            return new ServletInputStream(){
                public int read(){return input.read();}
                public int read(byte[] bytes,int off,int len){return input.read(bytes,off,len);}
                public boolean isFinished(){return input.available()==0;}
                public boolean isReady(){return true;}
                public void setReadListener(ReadListener listener){throw new UnsupportedOperationException("Async request reads are unsupported");}
            };
        }
        @Override public BufferedReader getReader(){return new BufferedReader(new InputStreamReader(getInputStream(),StandardCharsets.UTF_8));}
    }
}
