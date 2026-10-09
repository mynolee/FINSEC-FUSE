package com.finsec.fuse.quarantine;

import static com.finsec.fuse.payment.PaymentValues.*;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.RoleGuard;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.payment.PaymentRiskService;
import com.finsec.fuse.payment.PaymentSupport;
import com.finsec.fuse.persistence.*;
import com.finsec.fuse.policy.EvidenceValidator;
import com.finsec.fuse.policy.QuarantineMatcher;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Release only removes a prohibition. Resume separately creates a new bounded evaluation generation. */
@Service
public class RecoveryService {
    private final Db db;private final TimeSource time;private final FusePolicy policy;private final ActionRequests actions;
    private final PaymentSupport support;private final PaymentRiskService risk;private final QuarantineMatcher matcher;
    private final QuarantineService quarantines;private final EvidenceValidator evidence;
    private final com.finsec.fuse.workflow.WorkflowJournal journal;
    public RecoveryService(Db db,TimeSource time,FusePolicy policy,ActionRequests actions,PaymentSupport support,
        PaymentRiskService risk,QuarantineMatcher matcher,QuarantineService quarantines,EvidenceValidator evidence,com.finsec.fuse.workflow.WorkflowJournal journal) {
        this.db=db;this.time=time;this.policy=policy;this.actions=actions;this.support=support;this.risk=risk;this.matcher=matcher;this.quarantines=quarantines;this.evidence=evidence;this.journal=journal;
    }
    @Transactional
    public Map<String,Object> resume(Actor actor,UUID workflowId,UUID actionId,ResumeRequest request) {
        RoleGuard.require(actor,"LOAN_REVIEWER");db.gate();var workflow=db.lockWorkflow(workflowId);var now=time.now();
        var app=support.application(workflow);RoleGuard.requireCustomer(actor,str(app,"customer_id"));
        var replay=actions.replay(actionId,actor.actorId(),"WORKFLOW_RESUME",workflowId,request);if(replay.isPresent())return replay.get();
        if(integer(workflow,"generation")!=request.expectedGeneration())throw new ApiException(409,"WORKFLOW_CHANGED","The workflow generation changed.");
        if(!Set.of("BLOCKED","ON_HOLD").contains(str(workflow,"state")) || db.one("select id from mock_payment where workflow_id=?",workflowId).isPresent())
            throw new ApiException(409,"INVALID_STATE","Only blocked or held unpaid workflows can resume.");
        if(matcher.workflowQuarantined(workflowId))throw new ApiException(409,"QUARANTINED","Resolve all current and ancestral quarantines before resuming.");
        var stage=db.required("select * from workflow_stage where workflow_id=? and stage='KYC'",workflowId);
        if(integer(stage,"run_count")>=policy.maxRunsPerStage()) {
            support.state(workflowId,"ON_HOLD","DENY","MANUAL_REVIEW_REQUIRED",now);
            support.audit(actionId,workflowId,null,null,actor.actorId(),"MANUAL_REVIEW_REQUIRED","MANUAL_REVIEW_REQUIRED",Json.ordered("runCount",integer(stage,"run_count")),now);
            var response=support.response(actionId,workflow,"ON_HOLD","DENY","MANUAL_REVIEW_REQUIRED","The automatic evaluation limit is exhausted; manual investigation is required.");
            actions.save(actionId,actor.actorId(),"WORKFLOW_RESUME",workflowId,request,response);return response;
        }
        UUID safeDocument=uuid(workflow,"recovery_document_id");Integer safeVersion=(Integer)workflow.get("recovery_document_version");
        if(safeDocument==null) {
            if("BLOCKED".equals(str(workflow,"state")))throw new ApiException(409,"RECOVERY_CHECK_FAILED","A reviewed quarantine release must record the remediation first.");
            var registered=db.required("select * from application_registry where business_reference=?",str(app,"business_reference"));
            safeDocument=uuid(registered,"document_id");safeVersion=integer(registered,"document_version");
        }
        quarantines.validateSafeDocument(safeDocument,safeVersion);
        var evidenceIds=db.query("select id from trusted_evidence where customer_id=? and status='ACTIVE' and outcome='PASS' order by id",str(app,"customer_id")).stream().map(row->uuid(row,"id")).toList();
        var checked=evidence.validateForCustomer(str(app,"customer_id"),evidenceIds,now);
        if(!checked.validated())throw new ApiException(409,"RECOVERY_CHECK_FAILED","Independent evidence must be repaired before resuming: "+checked.reasonCode());
        risk.releaseLocked(workflowId,now);
        db.update("update approval set status='REVOKED' where workflow_id=? and status in ('AVAILABLE','RESERVED')",workflowId);
        db.update("update delegation_grant set status='REVOKED' where workflow_id=? and status='ISSUED'",workflowId);
        db.update("update workflow_job set state='FAILED',last_error='STALE_GENERATION',completed_at=? where workflow_id=? and state in ('PENDING','RUNNING')",now,workflowId);
        int generation=integer(workflow,"generation")+1;
        db.update("update workflow set generation=?,current_kyc_result_id=null,current_loan_result_id=null,recovery_document_id=?,recovery_document_version=? where id=?",generation,safeDocument,safeVersion,workflowId);
        support.state(workflowId,"KYC_PENDING","ALLOW",null,now);
        UUID jobId=journal.enqueue(workflowId,generation,"KYC",now);
        support.audit(actionId,workflowId,null,null,actor.actorId(),"WORKFLOW_RESUMED",null,
            Json.ordered("previousGeneration",integer(workflow,"generation"),"generation",generation,"kycJobId",jobId,"usedRiskRetained",integer(workflow,"used_risk"),"runCountRetained",integer(stage,"run_count"),"reason",request.reason()),now);
        var response=support.response(actionId,workflow,"KYC_PENDING","ALLOW",null,"A fresh KYC generation is queued; existing costs and execution limits are retained.");
        response.put("generation",generation);response.put("kycJobId",jobId);
        actions.save(actionId,actor.actorId(),"WORKFLOW_RESUME",workflowId,request,response);return response;
    }
}
