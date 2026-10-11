package com.finsec.fuse.auth;

import com.finsec.fuse.common.ApiException;
import java.util.Arrays;
import org.springframework.stereotype.Component;

@Component
public final class RoleGuard {
    public static void require(Actor actor,String... roles) {
        if(actor==null)throw new ApiException(401,"UNAUTHENTICATED","Authentication is required");
        if(Arrays.stream(roles).noneMatch(actor::is))throw new ApiException(403,"FORBIDDEN","This role cannot perform the requested action");
    }
    public static void requireCustomer(Actor actor,String customerId) {
        if(actor==null || !actor.canAccess(customerId))throw new ApiException(403,"FORBIDDEN","Customer is outside the authenticated actor's access scope");
    }
}
