package com.finsec.fuse.config;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import static org.junit.jupiter.api.Assertions.*;
class RuntimeSafetyTest {
    private MockEnvironment environment(String profile) {
        var env=new MockEnvironment().withProperty("fuse.service-token","synthetic-service-token-32-bytes-minimum");env.setActiveProfiles(profile);return env;
    }
    @Test void normalStartupRejectsDevelopmentCapabilities() {
        for(String flag:java.util.List.of("fuse.demo-seed","fuse.experiments.enabled","fuse.test-hooks.enabled","fuse.auto-approve"))
            assertThrows(IllegalStateException.class,()->new RuntimeSafety(environment("prod").withProperty(flag,"true")));
        assertThrows(IllegalStateException.class,()->new RuntimeSafety(environment("prod").withProperty("fuse.kyc-mode","replay")));
        assertThrows(IllegalStateException.class,()->new RuntimeSafety(environment("prod").withProperty("FUSE_DEV_REVIEWER_TOKEN","synthetic-token")));
    }
    @Test void applicationContextCannotRefreshWithProductionDemoSeed() {
        try(var context=new org.springframework.context.annotation.AnnotationConfigApplicationContext()) {
            context.setEnvironment(environment("prod").withProperty("fuse.demo-seed","true"));
            context.register(RuntimeSafety.class);
            assertThrows(org.springframework.beans.BeansException.class,context::refresh);
            assertFalse(context.isActive());
        }
    }
    @Test void mixedProfilesAndWeakServicesFailClosed() {
        var mixed=environment("prod");mixed.setActiveProfiles("prod","test");
        assertThrows(IllegalStateException.class,()->new RuntimeSafety(mixed));
        for(String token:java.util.List.of("","short","CHANGE_ME".repeat(8)))
            assertThrows(IllegalStateException.class,()->new RuntimeSafety(environment("test").withProperty("fuse.service-token",token)));
        assertDoesNotThrow(()->new RuntimeSafety(environment("prod")));
    }
}
