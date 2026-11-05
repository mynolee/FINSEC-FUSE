package com.finsec.fuse.reimplementation.http;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import tools.jackson.databind.json.JsonMapper;

/** Exact reference-only wire admission; no business command, role, frame or digest is decoded. */
public final class TypedWorkflowRequestDecoder {
    public record Selection(UUID commandRef,UUID requestId) {
        public Selection {Objects.requireNonNull(commandRef);Objects.requireNonNull(requestId);}
    }
    private final HttpLimits limits;
    private final JsonMapper mapper=JsonMapper.builder().build();
    public TypedWorkflowRequestDecoder(HttpLimits limits){this.limits=Objects.requireNonNull(limits);}
    public Selection decode(HttpServletRequest request,byte[] body){
        Objects.requireNonNull(request);
        if(body==null||body.length==0)throw invalid();
        if(body.length>limits.maxBodyBytes())throw new PublicHttpErrors.Rejected(PublicHttpErrors.Error.REQUEST_TOO_LARGE);
        StrictJsonInspector.verify(body,limits.maxJsonDepth());
        var values=request.getHeaders("Idempotency-Key");
        if(values==null||!values.hasMoreElements())throw invalid();
        String key=values.nextElement();if(values.hasMoreElements())throw invalid();
        UUID requestId=canonical(key);
        final Object value;
        try{value=mapper.readValue(body,Object.class);}
        catch(RuntimeException malformed){throw invalid();}
        if(!(value instanceof Map<?,?> map)||map.size()!=1||!map.containsKey("commandRef"))throw invalid();
        Object ref=map.get("commandRef");if(!(ref instanceof String text))throw invalid();
        return new Selection(canonical(text),requestId);
    }
    private static UUID canonical(String value){
        if(value==null||!value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))throw invalid();
        try{return UUID.fromString(value);}catch(IllegalArgumentException malformed){throw invalid();}
    }
    private static PublicHttpErrors.Rejected invalid(){return new PublicHttpErrors.Rejected(PublicHttpErrors.Error.INVALID_REQUEST);}
}
