package com.finsec.fuse.auth;

import com.finsec.fuse.common.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Component
public final class ActorResolver {
    public static final String ATTRIBUTE=ActorResolver.class.getName()+".actor";
    public static Actor current() {
        if(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)
            return current(attributes.getRequest());
        throw new ApiException(401,"UNAUTHENTICATED","Authentication is required");
    }
    public static Actor current(HttpServletRequest request) {
        if(request.getAttribute(ATTRIBUTE) instanceof Actor actor)return actor;
        throw new ApiException(401,"UNAUTHENTICATED","Authentication is required");
    }
}
