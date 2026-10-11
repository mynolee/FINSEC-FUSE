package com.finsec.fuse.config;

import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Construction fails before scheduling if development authority leaks into a normal runtime. */
@Component
public final class RuntimeSafety {
    public RuntimeSafety(Environment env) {
        Set<String> profiles=new HashSet<>(Arrays.asList(env.getActiveProfiles()));
        boolean development=profiles.contains("demo") || profiles.contains("test");
        if(development && profiles.stream().anyMatch(p->!Set.of("demo","test").contains(p)))
            throw new IllegalStateException("Development profiles cannot be combined with normal runtime profiles");
        String service=env.getProperty("FUSE_SERVICE_TOKEN",env.getProperty("fuse.service-token",""));
        if(service.getBytes(StandardCharsets.UTF_8).length<32 || service.contains("CHANGE_ME"))
            throw new IllegalStateException("A separate strong internal service token is required");
        String timeouts="SET lock_timeout = '2s'; SET statement_timeout = '5s'";
        if(!profiles.contains("test") && !timeouts.equals(env.getProperty("spring.datasource.hikari.connection-init-sql",timeouts)))
            throw new IllegalStateException("Normal database timeouts must match the security policy");
        if(!development) {
            for(String flag:List.of("fuse.demo-seed","fuse.experiments.enabled","fuse.test-hooks.enabled","fuse.auto-approve"))
                if(env.getProperty(flag,Boolean.class,false))throw new IllegalStateException("Development features are forbidden in normal runtime");
            if(!"live".equals(env.getProperty("fuse.kyc-mode","live")))
                throw new IllegalStateException("Replay is development-only");
            for(String suffix:List.of("CUSTOMER_101","CUSTOMER_102","REVIEWER","SECURITY","DEVELOPER"))
                for(String prefix:List.of("FUSE_DEV_","FUSE_"))
                    if(!env.getProperty(prefix+suffix+"_TOKEN", "").isBlank())
                        throw new IllegalStateException("Development token registry is forbidden in normal runtime");
            for(String name:List.of("customer-101","customer-102","reviewer","security","developer"))
                if(!env.getProperty("fuse.auth."+name+"-token", "").isBlank())
                    throw new IllegalStateException("Development token registry is forbidden in normal runtime");
        }
    }
}
