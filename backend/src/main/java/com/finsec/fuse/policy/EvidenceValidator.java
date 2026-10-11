package com.finsec.fuse.policy;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.observation.SecurityCheckObservation;
import com.finsec.fuse.persistence.Db;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Component;
import static com.finsec.fuse.policy.PolicyRows.*;

/** Read-only adapter; callers commit candidate results and any denial/quarantine in their own transaction. */
@Component
public class EvidenceValidator {
    private final Db db;
    private final Json json;
    private final EvidenceChecks checks;
    public EvidenceValidator(Db db,FusePolicy policy,Json json) {
        this.db=db;this.json=json;this.checks=new EvidenceChecks(policy.trustedIssuers(),json);
    }
    public EvidenceDecision validate(String proposalStatus,Collection<UUID> proposedIds,UUID runId,String customerId,Instant dbNow) {
        // Non-VERIFIED handling is retained by the baseline and is not additional FUSE time.
        try (var ignored=SecurityCheckObservation.enter(SecurityCheckObservation.Check.VERIFIED_EVIDENCE,"VERIFIED".equals(proposalStatus))) {
            return validateProposal(proposalStatus,proposedIds,runId,customerId,dbNow);
        }
    }
    private EvidenceDecision validateProposal(String proposalStatus,Collection<UUID> proposedIds,UUID runId,String customerId,Instant dbNow) {
        Set<UUID> provided = new HashSet<>();
        for (var row: db.query("SELECT evidence_id FROM run_evidence_use WHERE run_id=?",runId)) provided.add(uuid(row,"evidence_id"));
        Set<UUID> all = new HashSet<>(provided);
        if(proposedIds!=null) proposedIds.stream().filter(Objects::nonNull).forEach(all::add);
        return checks.evaluate(proposalStatus,proposedIds,provided,load(all),customerId,dbNow);
    }
    public EvidenceDecision validateForCustomer(String customerId,List<UUID> evidenceIds,Instant dbNow) {
        if(evidenceIds==null) return EvidenceDecision.blocked("EVIDENCE_MISSING");
        Set<UUID> ids=new HashSet<>(evidenceIds); ids.remove(null);
        return checks.evaluate("VERIFIED",evidenceIds,ids,load(ids),customerId,dbNow);
    }
    public EvidenceDecision revalidate(UUID kycRunId,String customerId,String expectedBundleHash,Instant dbNow) {
        try (var ignored=SecurityCheckObservation.enter(SecurityCheckObservation.Check.VERIFIED_EVIDENCE)) {
            return revalidateResult(kycRunId,customerId,expectedBundleHash,dbNow);
        }
    }
    private EvidenceDecision revalidateResult(UUID kycRunId,String customerId,String expectedBundleHash,Instant dbNow) {
        Optional<Map<String,Object>> result=db.one("SELECT * FROM agent_result WHERE run_id=?",kycRunId);
        if(result.isEmpty() || !"VALIDATED".equals(str(result.get(),"status"))) return EvidenceDecision.blocked("EVIDENCE_INVALID");
        EvidenceDecision decision=validateResult(result.get(),customerId,dbNow);
        if(decision.validated() && !Objects.equals(expectedBundleHash,decision.evidenceBundleHash()))
            return EvidenceDecision.blocked("EVIDENCE_INVALID");
        return decision;
    }
    public EvidenceDecision validateStored(UUID kycResultId,Instant dbNow) {
        try (var ignored=SecurityCheckObservation.enter(SecurityCheckObservation.Check.VERIFIED_EVIDENCE)) {
            return validateStoredResult(kycResultId,dbNow);
        }
    }
    private EvidenceDecision validateStoredResult(UUID kycResultId,Instant dbNow) {
        Optional<Map<String,Object>> result=db.one("SELECT r.*,a.customer_id FROM agent_result r JOIN workflow w ON w.id=r.workflow_id JOIN loan_application a ON a.id=w.application_id WHERE r.id=? AND r.generation=w.generation",kycResultId);
        if(result.isEmpty() || !"VALIDATED".equals(str(result.get(),"status"))) return EvidenceDecision.blocked("EVIDENCE_INVALID");
        return validateResult(result.get(),str(result.get(),"customer_id"),dbNow);
    }
    private EvidenceDecision validateResult(Map<String,Object> row,String customer,Instant now) {
        try {
            Map<String,Object> body=json.map(str(row,"body_json"));
            if(body.get("proposal") instanceof Map<?,?> nested) {
                Map<String,Object> copy=new LinkedHashMap<>();nested.forEach((k,v)->copy.put(k.toString(),v));body=copy;
            }
            Object ids=body.get("evidenceIds");
            if(!(ids instanceof List<?> values)) return EvidenceDecision.blocked("EVIDENCE_INVALID");
            List<UUID> evidenceIds=values.stream().map(v->UUID.fromString(v.toString())).toList();
            EvidenceDecision result=validate(Objects.toString(body.get("status"),""),evidenceIds,uuid(row,"run_id"),customer,now);
            if(result.validated() && !Objects.equals(result.evidenceBundleHash(),str(row,"evidence_bundle_hash")))
                return EvidenceDecision.blocked("EVIDENCE_INVALID");
            return result;
        } catch (IllegalArgumentException malformed) { return EvidenceDecision.blocked("EVIDENCE_INVALID"); }
    }
    private Map<UUID,EvidenceRecord> load(Collection<UUID> ids) {
        Map<UUID,EvidenceRecord> records=new HashMap<>();
        for(UUID id:ids) db.one("SELECT * FROM trusted_evidence WHERE id=?",id).ifPresent(row->{
            Map<String,Object> original;
            try { original=json.map(str(row,"original_json")); } catch (RuntimeException malformed) { original=Map.of(); }
            records.put(id,new EvidenceRecord(uuid(row,"id"),str(row,"customer_id"),str(row,"evidence_type"),str(row,"issuer_id"),
                    integer(row,"version"),str(row,"outcome"),str(row,"status"),instant(row,"issued_at"),instant(row,"expires_at"),
                    instant(row,"revoked_at"),original,str(row,"original_hash")));
        });
        return records;
    }
}
