package com.finsec.fuse.workflow;

import com.finsec.fuse.auth.*;
import com.finsec.fuse.common.*;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.persistence.*;
import com.finsec.fuse.policy.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.*;
import static com.finsec.fuse.workflow.WorkflowValues.*;

@Service
public class WorkflowQueryService {
    private static final Set<String> STATES=Set.of("KYC_PENDING","KYC_VALIDATED","REVIEW_READY","WAIT_APPROVAL","APPROVED","PAYMENT_RESERVED","PAID","REJECTED","BLOCKED","ON_HOLD");
    private final Db db;private final TimeSource time;private final Json json;private final FusePolicy policy;
    private final EvidenceValidator evidence;private final QuarantineMatcher matcher;
    public WorkflowQueryService(Db db,TimeSource time,Json json,FusePolicy policy,EvidenceValidator evidence,QuarantineMatcher matcher) {
        this.db=db;this.time=time;this.json=json;this.policy=policy;this.evidence=evidence;this.matcher=matcher;
    }
    @Transactional
    public Map<String,Object> list(Actor actor,String state,int page,int size) {
        RoleGuard.require(actor,"CUSTOMER","LOAN_REVIEWER","SECURITY_OPERATOR");
        if(page<0 || size<1 || size>100 || (state!=null && !STATES.contains(state)))throw new ApiException(400,"INVALID_REQUEST","Invalid list filter or pagination");
        db.gate();Instant now=time.now();
        String predicate=" WHERE 1=1";List<Object> args=new ArrayList<>();
        {
            if(actor.customerIds().isEmpty())return Json.ordered("items",List.of(),"total",0,"page",page,"size",size);
            var customers=actor.customerIds().stream().sorted().toList();
            predicate+=" AND a.customer_id IN ("+String.join(",",Collections.nCopies(customers.size(),"?"))+")";args.addAll(customers);
        }
        if(state!=null){predicate+=" AND w.state=?";args.add(state);}
        String from=" FROM workflow w JOIN loan_application a ON a.id=w.application_id";
        long total=((Number)db.required("SELECT count(*) AS count"+from+predicate,args.toArray()).get("count")).longValue();
        args.add(size);args.add((long)page*size);
        var rows=db.query("SELECT w.*,a.customer_id,a.business_reference,a.amount_krw,a.payout_account_id"+from+predicate+" ORDER BY w.created_at DESC,w.id DESC LIMIT ? OFFSET ?",args.toArray());
        return Json.ordered("items",rows.stream().map(w->summary(actor,w,now)).toList(),"total",total,"page",page,"size",size);
    }
    @Transactional
    public Map<String,Object> detail(Actor actor,UUID workflowId) {
        RoleGuard.require(actor,"CUSTOMER","LOAN_REVIEWER","SECURITY_OPERATOR");db.gate();
        var w=accessible(actor,workflowId);return summary(actor,w,time.now());
    }
    @Transactional
    public Map<String,Object> trace(Actor actor,UUID workflowId) {
        RoleGuard.require(actor,"LOAN_REVIEWER","SECURITY_OPERATOR");db.gate();var w=accessible(actor,workflowId);
        return Json.ordered("workflowId",workflowId,"traceId",workflowId,"generation",integer(w,"generation"),
                "runs",rows("SELECT id AS run_id,generation,role,agent_id,agent_version,run_index,status,input_snapshot_hash,started_at,completed_at FROM agent_run WHERE workflow_id=? ORDER BY created_at,id",workflowId),
                "results",rows("SELECT id AS result_id,run_id,generation,status,body_json,result_hash,evidence_bundle_hash,created_at FROM agent_result WHERE workflow_id=? ORDER BY created_at,id",workflowId),
                "grants",rows("SELECT id AS grant_id,source_agent AS source,target_agent AS target,allowed_action AS action,depth,parent_grant_id AS parent,source_run_id,target_run_id,expires_at,status FROM delegation_grant WHERE workflow_id=? ORDER BY created_at,id",workflowId),
                "dependencies",rows("SELECT parent_run_id,child_run_id,parent_result_id,generation FROM run_dependency WHERE workflow_id=? ORDER BY parent_run_id,child_run_id",workflowId),
                "approvals",rows("SELECT id AS approval_id,generation,actor_id,status,review_snapshot_hash,extra_risk,risk_limit,expires_at,created_at FROM approval WHERE workflow_id=? ORDER BY created_at,id",workflowId),
                "riskEvents",rows("SELECT id,stage,event_type,points,generation,action_id,run_id,reservation_id,created_at FROM risk_ledger WHERE workflow_id=? ORDER BY created_at,id",workflowId),
                "payments",rows("SELECT id AS payment_id,amount_krw,payout_account_id,generation,approval_id,action_id,receipt_json,created_at FROM mock_payment WHERE workflow_id=? ORDER BY created_at,id",workflowId),
                "auditEvents",auditRows(workflowId),
                "sourceUses",rows("SELECT u.* FROM run_source_use u JOIN agent_run r ON r.id=u.run_id WHERE r.workflow_id=? ORDER BY u.run_id,u.document_id,u.document_version",workflowId),
                "evidenceUses",rows("SELECT u.run_id,e.id AS evidence_id,e.evidence_type,e.outcome,e.status,e.expires_at FROM run_evidence_use u JOIN agent_run r ON r.id=u.run_id JOIN trusted_evidence e ON e.id=u.evidence_id WHERE r.workflow_id=? ORDER BY u.run_id,e.id",workflowId));
    }
    private Map<String,Object> accessible(Actor actor,UUID workflowId) {
        var w=db.required("SELECT w.*,a.customer_id,a.business_reference,a.amount_krw,a.payout_account_id FROM workflow w JOIN loan_application a ON a.id=w.application_id WHERE w.id=?",workflowId);
        RoleGuard.requireCustomer(actor,str(w,"customer_id"));return w;
    }
    private Map<String,Object> summary(Actor actor,Map<String,Object> w,Instant now) {
        UUID workflowId=id(w,"id");String state=str(w,"state");boolean quarantined=matcher.workflowQuarantined(workflowId);
        int limit=effectiveLimit(w,now,quarantined);
        var activeJob=db.one("SELECT id AS job_id,phase,state FROM workflow_job WHERE workflow_id=? AND state IN ('PENDING','RUNNING')",workflowId).map(this::camelRow).orElse(null);
        var active=db.query("SELECT DISTINCT q.id AS quarantine_id,q.scope FROM quarantine q WHERE q.status='ACTIVE' AND (q.workflow_id=? OR q.run_id IN (SELECT id FROM agent_run WHERE workflow_id=? AND generation=?) OR q.result_id IN (SELECT id FROM agent_result WHERE workflow_id=? AND generation=?) OR EXISTS(SELECT 1 FROM run_source_use u JOIN agent_run r ON r.id=u.run_id WHERE r.workflow_id=? AND r.generation=? AND q.scope='SOURCE_VERSION' AND q.document_id=u.document_id AND q.document_version=u.document_version) OR EXISTS(SELECT 1 FROM agent_run r WHERE r.workflow_id=? AND r.generation=? AND q.scope='AGENT_VERSION' AND q.agent_id=r.agent_id AND q.agent_version=r.agent_version) OR EXISTS(SELECT 1 FROM quarantine_workflow_hold h WHERE h.quarantine_id=q.id AND h.workflow_id=? AND h.generation=?)) ORDER BY quarantine_id",
                workflowId,workflowId,integer(w,"generation"),workflowId,integer(w,"generation"),workflowId,integer(w,"generation"),workflowId,integer(w,"generation"),workflowId,integer(w,"generation"));
        boolean reviewer=actor.is("LOAN_REVIEWER");
        boolean evidenceReady=!quarantined && id(w,"current_kyc_result_id")!=null && evidence.validateStored(id(w,"current_kyc_result_id"),now).validated();
        int kycRuns=integer(db.required("SELECT run_count FROM workflow_stage WHERE workflow_id=? AND stage='KYC'",workflowId),"run_count");
        Object account=actor.is("CUSTOMER")?"••••"+id(w,"payout_account_id").toString().substring(32):id(w,"payout_account_id");
        var result=Json.ordered("workflowId",workflowId,"businessReference",str(w,"business_reference"),"customerId",str(w,"customer_id"),"amountKrw",number(w,"amount_krw"),"payoutAccountId",account,
                "generation",integer(w,"generation"),"state",state,"lastDecision",str(w,"last_decision"),"reasonCodes",json.read(str(w,"reason_codes"),List.class),
                "usedRisk",integer(w,"used_risk"),"reservedRisk",integer(w,"reserved_risk"),"riskLimit",limit,
                "activeQuarantines",active.stream().map(this::camelRow).toList(),"activeJob",activeJob,
                "canApprove",reviewer && "WAIT_APPROVAL".equals(state) && evidenceReady && id(w,"current_loan_result_id")!=null,
                "canResume",reviewer && Set.of("BLOCKED","ON_HOLD").contains(state) && !quarantined && kycRuns<policy.maxRunsPerStage());
        if("PAID".equals(state))db.one("SELECT a.risk_limit FROM approval a JOIN mock_payment p ON p.approval_id=a.id WHERE p.workflow_id=?",workflowId)
                .ifPresent(a->result.put("historicalApprovedRiskLimit",integer(a,"risk_limit")));
        return result;
    }
    private int effectiveLimit(Map<String,Object> w,Instant now,boolean quarantined) {
        if(quarantined || "PAID".equals(str(w,"state")) || id(w,"current_kyc_result_id")==null || id(w,"current_loan_result_id")==null)return policy.automaticRiskLimit();
        var approval=db.one("SELECT a.* FROM approval a JOIN agent_result k ON k.id=a.kyc_result_id JOIN agent_result l ON l.id=a.loan_result_id WHERE a.workflow_id=? AND a.generation=? AND a.status IN ('AVAILABLE','RESERVED') AND a.expires_at>? AND a.customer_id=? AND a.amount_krw=? AND a.payout_account_id=? AND a.kyc_result_id=? AND a.loan_result_id=? AND a.policy_version=? AND k.status='VALIDATED' AND l.status='VALIDATED' AND a.loan_result_hash=l.result_hash AND a.evidence_bundle_hash=k.evidence_bundle_hash",
                id(w,"id"),integer(w,"generation"),now,str(w,"customer_id"),number(w,"amount_krw"),id(w,"payout_account_id"),id(w,"current_kyc_result_id"),id(w,"current_loan_result_id"),str(w,"policy_version"));
        if(approval.isEmpty() || integer(approval.get(),"extra_risk")!=policy.approvalExtraRisk() || integer(approval.get(),"risk_limit")!=policy.approvedRiskLimit() ||
                !evidence.validateStored(id(w,"current_kyc_result_id"),now).validated())return policy.automaticRiskLimit();
        return policy.automaticRiskLimit()+integer(approval.get(),"extra_risk");
    }
    private List<Map<String,Object>> auditRows(UUID workflowId) {
        return db.query("SELECT id,action_id,run_id,quarantine_id,actor_id,event_type,reason_code,details_json,created_at FROM audit_event WHERE workflow_id=? ORDER BY created_at,id",workflowId)
            .stream().map(this::camelRow).map(row->{
                String event=Objects.toString(row.get("eventType"),"");
                if(Set.of("WORKFLOW_RESUMED","RECOVERY_CHECKED").contains(event))
                    row.put("detailsJson",safeRecoveryAuditDetails(event,row.get("detailsJson")));
                return row;
            }).toList();
    }
    /** Read projection only: legacy append-only records may still contain freeform notes. */
    private Map<String,Object> safeRecoveryAuditDetails(String event,Object value) {
        Map<?,?> original=value instanceof Map<?,?> map?map:Map.of();
        var safe=new LinkedHashMap<String,Object>();
        if("WORKFLOW_RESUMED".equals(event)) {
            for(String key:List.of("previousGeneration","generation","usedRiskRetained","runCountRetained"))
                copyAuditNumber(original,safe,key);
            copyAuditUuid(original,safe,"kycJobId");
            safe.put("reasonProvided",Boolean.TRUE.equals(original.get("reasonProvided")) ||
                original.get("reason") instanceof String reason && !reason.isBlank());
        } else {
            copyAuditUuid(original,safe,"safeDocumentId");
            copyAuditNumber(original,safe,"safeDocumentVersion");
            var checks=new ArrayList<Map<String,Object>>();
            if(original.get("checks") instanceof List<?> values)for(Object item:values) {
                if(!(item instanceof Map<?,?> check))continue;
                var selected=new LinkedHashMap<String,Object>();
                copyAuditUuid(check,selected,"workflowId");
                if(check.get("evidenceBundleHash") instanceof String hash && hash.matches("[0-9a-f]{64}"))
                    selected.put("evidenceBundleHash",hash);
                if(!selected.isEmpty())checks.add(selected);
            }
            safe.put("checks",checks);
            if(original.get("safeAgentId") instanceof String agent && original.get("safeAgentVersion") instanceof Number version &&
                policy.safeAgentVersions().contains(agent+":"+version)) {
                safe.put("safeAgentId",agent);safe.put("safeAgentVersion",version);
            }
            Map<?,?> legacy=original.get("remediation") instanceof Map<?,?> map?map:Map.of();
            safe.put("noteProvided",Boolean.TRUE.equals(original.get("noteProvided")) ||
                legacy.get("note") instanceof String note && !note.isBlank());
        }
        return safe;
    }
    private static void copyAuditNumber(Map<?,?> source,Map<String,Object> target,String key) {
        if(source.get(key) instanceof Number number)target.put(key,number);
    }
    private static void copyAuditUuid(Map<?,?> source,Map<String,Object> target,String key) {
        if(source.get(key) instanceof String text)try {
            UUID id=UUID.fromString(text);if(id.toString().equals(text))target.put(key,text);
        } catch(IllegalArgumentException ignored) { /* Unrecognized detail is not part of this projection. */ }
    }
    private List<Map<String,Object>> rows(String sql,UUID workflowId){return db.query(sql,workflowId).stream().map(this::camelRow).toList();}
    private Map<String,Object> camelRow(Map<String,Object> row) {
        var result=new LinkedHashMap<String,Object>();row.forEach((k,v)-> {
            if(v!=null && k.endsWith("_json"))v=json.read(v.toString(),Object.class);
            else if(v instanceof java.sql.Timestamp t)v=t.toInstant();
            result.put(camel(k),v);
        });return result;
    }
}
