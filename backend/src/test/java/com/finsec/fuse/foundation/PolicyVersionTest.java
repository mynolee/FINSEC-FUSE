package com.finsec.fuse.foundation;

import com.finsec.fuse.config.JsonConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import static org.junit.jupiter.api.Assertions.*;

class PolicyVersionTest {
    @Test void policyFileRemainsTheSingleSourceOfNumericLimits() throws Exception {
        var config=new JsonConfiguration();
        var policy=config.fusePolicy(config.jsonMapper(),new MockEnvironment());
        assertEquals("FUSE-MVP-2",policy.policyVersion());
        assertEquals(40,policy.automaticRiskLimit());
        assertEquals(85,policy.approvedRiskLimit());
    }
    @Test void matchingRequestedVersionIsAccepted() throws Exception {
        var config=new JsonConfiguration();
        assertNotNull(config.fusePolicy(config.jsonMapper(),new MockEnvironment().withProperty("FUSE_POLICY_VERSION","FUSE-MVP-2")));
    }
    @Test void mismatchedRequestedVersionFailsStartup() {
        var config=new JsonConfiguration();
        assertThrows(IllegalStateException.class,()->config.fusePolicy(config.jsonMapper(),new MockEnvironment().withProperty("FUSE_POLICY_VERSION","UNKNOWN")));
    }
}
