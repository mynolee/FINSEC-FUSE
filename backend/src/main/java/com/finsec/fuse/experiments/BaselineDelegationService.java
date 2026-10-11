package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.policy.*;
import java.time.Instant;
import java.util.UUID;

/** Isolated ablation removes delegation policy bindings; common MAC/body integrity, public RBAC and exact approval remain. */
final class BaselineDelegationService extends DelegationService {
    BaselineDelegationService(Db db,Json json,FusePolicy policy,GrantCodec codec,EnvelopeValidator validator,
                              EvidenceValidator evidence,QuarantineMatcher quarantine) {
        super(db,json,policy,codec,validator,evidence,quarantine);
    }
    @Override public GrantClaims validate(GrantTransport transport,String source,UUID workflow,UUID target,String action,Instant now) {
        return verifyBasicTransport(transport).claims();
    }
}
