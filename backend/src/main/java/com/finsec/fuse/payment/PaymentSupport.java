package com.finsec.fuse.payment;

import static com.finsec.fuse.payment.PaymentValues.*;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.policy.EvidenceValidator;
import com.finsec.fuse.policy.QuarantineMatcher;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Component;

@Component
public class PaymentSupport {
    private final Db db;
    private final Json json;
    private final FusePolicy policy;
    private final EvidenceValidator evidence;
    private final QuarantineMatcher quarantines;
    public PaymentSupport(Db db, Json json, FusePolicy policy, EvidenceValidator evidence, QuarantineMatcher quarantines) {
        this.db=db; this.json=json; this.policy=policy; this.evidence=evidence; this.quarantines=quarantines;
    }
    public Map<String,Object> application(Map<String,Object> workflow) {
        return db.required("select * from loan_application where id=?",uuid(workflow,"application_id"));
    }
    /** The insertion order is the API's canonical review fingerprint contract. */
    public Map<String,Object> snapshot(Map<String,Object> workflow) {
        UUID kycId=uuid(workflow,"current_kyc_result_id"), loanId=uuid(workflow,"current_loan_result_id");
        if (kycId==null || loanId==null) throw new ApiException(409,"INVALID_STATE","Validated KYC and loan results are required.");
        var app=application(workflow);
        var kyc=db.required("select * from agent_result where id=?",kycId);
        var loan=db.required("select * from agent_result where id=?",loanId);
        if (!"VALIDATED".equals(str(kyc,"status")) || !"VALIDATED".equals(str(loan,"status")) ||
            integer(kyc,"generation")!=integer(workflow,"generation") || integer(loan,"generation")!=integer(workflow,"generation") ||
            !uuid(workflow,"id").equals(uuid(kyc,"workflow_id")) || !uuid(workflow,"id").equals(uuid(loan,"workflow_id")))
            throw new ApiException(409,"REVIEW_CHANGED","The current results are no longer valid for review.");
        return Json.ordered("workflowId",uuid(workflow,"id"),"generation",integer(workflow,"generation"),
            "customerId",str(app,"customer_id"),"amountKrw",number(app,"amount_krw"),"payoutAccountId",uuid(app,"payout_account_id"),
            "kycResultId",kycId,"loanResultId",loanId,"evidenceBundleHash",str(kyc,"evidence_bundle_hash"),
            "loanResultHash",str(loan,"result_hash"),"policyVersion",str(workflow,"policy_version"),
            "usedRisk",integer(workflow,"used_risk"),"reservedRisk",integer(workflow,"reserved_risk"),
            "riskLimitAfterApproval",policy.automaticRiskLimit()+policy.approvalExtraRisk());
    }
    public String currentFailure(Map<String,Object> workflow, Instant now) {
        UUID kycId=uuid(workflow,"current_kyc_result_id"),loanId=uuid(workflow,"current_loan_result_id");
        if (kycId==null || loanId==null) return "APPROVAL_INVALID";
        if (!policy.policyVersion().equals(str(workflow,"policy_version"))) return "CONTEXT_MISMATCH";
        if (quarantines.workflowQuarantined(uuid(workflow,"id"))) return "QUARANTINED";
        var app=application(workflow);
        var account=db.one("select * from mock_account where id=?",uuid(app,"payout_account_id"));
        if(account.isEmpty() || !"ACTIVE".equals(str(account.get(),"status")) || !Objects.equals(str(app,"customer_id"),str(account.get(),"customer_id"))) return "CONTEXT_MISMATCH";
        try { snapshot(workflow); } catch(ApiException ex) { return "APPROVAL_INVALID"; }
        var checked=evidence.validateStored(kycId,now);
        if(!checked.validated()) return checked.reasonCode();
        var kyc=db.required("select * from agent_result where id=?",kycId);
        var loan=db.required("select * from agent_result where id=?",loanId);
        if (!Objects.equals(str(kyc,"evidence_bundle_hash"), checked.evidenceBundleHash()) ||
            !Objects.equals(str(loan,"evidence_bundle_hash"),checked.evidenceBundleHash())) return "EVIDENCE_INVALID";
        return null;
    }
    public boolean exactApproval(Map<String,Object> workflow,Map<String,Object> approval,UUID actionId,Instant now, boolean reserved) {
        if(approval==null || !now.isBefore(instant(approval,"expires_at"))) return false;
        String required=reserved?"RESERVED":"AVAILABLE";
        if(!required.equals(str(approval,"status")) || (reserved && !actionId.equals(uuid(approval,"reserved_action_id")))) return false;
        Map<String,Object> snapshot;
        try { snapshot=snapshot(workflow); } catch(ApiException e) { return false; }
        return uuid(workflow,"id").equals(uuid(approval,"workflow_id")) &&
            integer(workflow,"generation")==integer(approval,"generation") &&
            Objects.equals(snapshot.get("customerId"),str(approval,"customer_id")) &&
            ((Number)snapshot.get("amountKrw")).longValue()==number(approval,"amount_krw") &&
            Objects.equals(snapshot.get("payoutAccountId"),uuid(approval,"payout_account_id")) &&
            Objects.equals(snapshot.get("kycResultId"),uuid(approval,"kyc_result_id")) &&
            Objects.equals(snapshot.get("loanResultId"),uuid(approval,"loan_result_id")) &&
            Objects.equals(snapshot.get("evidenceBundleHash"),str(approval,"evidence_bundle_hash")) &&
            Objects.equals(snapshot.get("loanResultHash"),str(approval,"loan_result_hash")) &&
            Objects.equals(snapshot.get("policyVersion"),str(approval,"policy_version")) &&
            integer(approval,"extra_risk")==policy.approvalExtraRisk() &&
            integer(approval,"risk_limit")==policy.automaticRiskLimit()+policy.approvalExtraRisk();
    }
    public Map<String,Object> actionBody(Map<String,Object> workflow, Map<String,Object> job) {
        var app=application(workflow);
        return Json.ordered("workflowId",uuid(workflow,"id"),"generation",integer(job,"generation"),
            "jobId",uuid(job,"id"),"approvalId",uuid(job,"approval_id"),"customerId",str(app,"customer_id"),
            "amountKrw",number(app,"amount_krw"),"payoutAccountId",uuid(app,"payout_account_id"),"policyVersion",str(workflow,"policy_version"));
    }
    public Map<String,Object> response(UUID actionId,Map<String,Object> workflow,String state,String decision,String reason,String message) {
        return Json.ordered("requestId",actionId,"workflowId",uuid(workflow,"id"),"generation",integer(workflow,"generation"),
            "state",state,"decision",decision,"reasonCodes",reason==null?List.of():List.of(reason),"message",message,"replayed",false);
    }
    public void state(UUID workflowId,String state,String decision,String reason,Instant now) {
        db.update("update workflow set state=?,last_decision=?,last_reason_code=?,reason_codes=?::jsonb,updated_at=? where id=?",
            state,decision,reason,json.write(reason==null?List.of():List.of(reason)),Timestamp.from(now),workflowId);
    }
    public void audit(UUID actionId,UUID workflowId,UUID runId,UUID quarantineId,String actor,String event,String reason,Object details,Instant now) {
        db.update("insert into audit_event(id,action_id,workflow_id,run_id,quarantine_id,actor_id,event_type,reason_code,details_json,created_at) values(?,?,?,?,?,?,?,?,?::jsonb,?)",
            UUID.randomUUID(),actionId,workflowId,runId,quarantineId,actor,event,reason,json.write(details),Timestamp.from(now));
    }
    public boolean liveLease(Map<String,Object> job,Map<String,Object> workflow,UUID token,Instant now) {
        return "RUNNING".equals(str(job,"state")) && Objects.equals(token,uuid(job,"lease_token")) &&
            instant(job,"lease_until")!=null && now.isBefore(instant(job,"lease_until")) && integer(job,"generation")==integer(workflow,"generation");
    }
}
