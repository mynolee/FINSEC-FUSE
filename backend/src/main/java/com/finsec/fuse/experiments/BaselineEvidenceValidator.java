package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.policy.*;
import java.time.Instant;
import java.util.*;

/** Not a component: installed only by the isolated non-web experiment sandbox. */
final class BaselineEvidenceValidator extends EvidenceValidator {
    private final Db db;private final Json json;
    BaselineEvidenceValidator(Db db,FusePolicy policy,Json json){super(db,policy,json);this.db=db;this.json=json;}
    @Override public EvidenceDecision validate(String status,Collection<UUID> ids,UUID run,String customer,Instant now) {
        if(!"VERIFIED".equals(status))return super.validate(status,ids,run,customer,now);
        var claimed=ids==null?List.<UUID>of():ids.stream().distinct().sorted().toList();
        return new EvidenceDecision("ALLOW","KYC_VALIDATED",null,json.hash(claimed),claimed,false);
    }
    @Override public EvidenceDecision validateStored(UUID resultId,Instant now) {
        var row=db.required("SELECT r.*,a.customer_id FROM agent_result r JOIN workflow w ON w.id=r.workflow_id JOIN loan_application a ON a.id=w.application_id WHERE r.id=?",resultId);
        var body=json.map(Db.string(row,"body_json"));
        @SuppressWarnings("unchecked") var values=(List<String>)body.get("evidenceIds");
        return validate(body.get("status").toString(),values.stream().map(UUID::fromString).toList(),Db.uuid(row,"run_id"),Db.string(row,"customer_id"),now);
    }
    @Override public EvidenceDecision revalidate(UUID run,String customer,String expected,Instant now) {
        return validateStored(Db.uuid(db.required("SELECT id FROM agent_result WHERE run_id=?",run),"id"),now);
    }
}
