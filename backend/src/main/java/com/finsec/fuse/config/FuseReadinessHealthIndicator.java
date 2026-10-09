package com.finsec.fuse.config;

import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.policy.SigningKeyProvider;
import java.util.List;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

/** Readiness is conditional on trusted policy, key material and all four required registry entries. */
@Component("fuseSecurity")
public final class FuseReadinessHealthIndicator implements HealthIndicator {
    private final Db db; private final FusePolicy policy; private final SigningKeyProvider keys;
    public FuseReadinessHealthIndicator(Db db,FusePolicy policy,SigningKeyProvider keys) {this.db=db;this.policy=policy;this.keys=keys;}
    @Override public Health health() {
        try {
            for(String agent:List.of("FUSE","KYC","LOAN","PAYMENT")) {
                boolean found=db.query("SELECT agent_id,version FROM agent_registry WHERE agent_id=? AND status='ACTIVE'",agent).stream()
                    .anyMatch(row->policy.safeAgentVersions().contains(row.get("agent_id")+":"+row.get("version")));
                if(!found)return Health.down().withDetail("reason","AGENT_REGISTRY_NOT_READY").build();
            }
            if(keys.activeKid().isBlank() || policy.policyVersion().isBlank())return Health.down().build();
            return Health.up().build();
        } catch(RuntimeException unavailable) {
            return Health.down().withDetail("reason","DEPENDENCY_UNAVAILABLE").build();
        }
    }
}
