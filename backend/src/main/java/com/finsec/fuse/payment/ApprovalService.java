package com.finsec.fuse.payment;

import static com.finsec.fuse.payment.PaymentValues.*;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.RoleGuard;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.persistence.TimeSource;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.persistence.ActionRequests;
import com.finsec.fuse.persistence.Db;
import java.sql.Timestamp;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ApprovalService {
    private final Db db; private final Json json; private final TimeSource time;
    private final FusePolicy policy; private final ActionRequests actions; private final PaymentSupport support;
    private final com.finsec.fuse.workflow.WorkflowJournal journal;
    private final com.finsec.fuse.config.FuseReadinessHealthIndicator readiness;
    public ApprovalService(Db db,Json json,TimeSource time,FusePolicy policy,ActionRequests actions,PaymentSupport support,com.finsec.fuse.workflow.WorkflowJournal journal,com.finsec.fuse.config.FuseReadinessHealthIndicator readiness) {
        this.db=db;this.json=json;this.time=time;this.policy=policy;this.actions=actions;this.support=support;this.journal=journal;this.readiness=readiness;
    }
    @Transactional
    public Map<String,Object> preview(Actor actor,UUID workflowId) {
        RoleGuard.require(actor,"LOAN_REVIEWER");
        db.gate(); var workflow=db.lockWorkflow(workflowId); var now=time.now();
        RoleGuard.requireCustomer(actor,str(support.application(workflow),"customer_id"));
        var snapshot=support.snapshot(workflow);
        var response=new LinkedHashMap<String,Object>(snapshot);
        response.put("reviewSnapshotHash",json.hash(snapshot));
        response.put("extraRiskLimit",policy.approvalExtraRisk());
        response.put("expiresInSeconds",policy.approvalTtlSeconds());
        response.put("canApprove","WAIT_APPROVAL".equals(str(workflow,"state")) && support.currentFailure(workflow,now)==null);
        return response;
    }
    @Transactional
    public Map<String,Object> decide(Actor actor,UUID workflowId,UUID actionId,ApprovalRequest request) {
        RoleGuard.require(actor,"LOAN_REVIEWER");
        db.gate(); var workflow=db.lockWorkflow(workflowId); var now=time.now();
        var app=support.application(workflow); RoleGuard.requireCustomer(actor,str(app,"customer_id"));
        var body=Json.ordered("decision",request.decision(),"reviewSnapshotHash",request.reviewSnapshotHash(),"comment",request.comment());
        var replay=actions.replay(actionId,actor.actorId(),"APPROVAL",workflowId,body);
        if(replay.isPresent()) return replay.get();
        if(request.decision()==ApprovalRequest.Decision.APPROVE) readiness.requireReady();
        if(!"WAIT_APPROVAL".equals(str(workflow,"state"))) throw new ApiException(409,"INVALID_STATE","The workflow is not waiting for a reviewer.");
        var snapshot=support.snapshot(workflow);
        if(!json.hash(snapshot).equals(request.reviewSnapshotHash())) throw new ApiException(409,"REVIEW_CHANGED","Review details changed. Fetch a new approval preview.");
        String failure=support.currentFailure(workflow,now);
        if(failure!=null) throw new ApiException(409,"APPROVAL_INVALID","The current review cannot be approved: "+failure);
        UUID approvalId=UUID.randomUUID();
        boolean approved=request.decision()==ApprovalRequest.Decision.APPROVE;
        var expires=now.plusSeconds(policy.approvalTtlSeconds());
        db.update("update approval set status=case when expires_at<=? then 'EXPIRED' else 'REVOKED' end where workflow_id=? and status in ('AVAILABLE','RESERVED')",Timestamp.from(now),workflowId);
        db.update("insert into approval(id,workflow_id,generation,actor_id,customer_id,amount_krw,payout_account_id,kyc_result_id,loan_result_id,loan_result_hash,evidence_bundle_hash,policy_version,review_snapshot_hash,extra_risk,risk_limit,status,comment,expires_at,created_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            approvalId,workflowId,integer(workflow,"generation"),actor.actorId(),str(app,"customer_id"),number(app,"amount_krw"),uuid(app,"payout_account_id"),
            snapshot.get("kycResultId"),snapshot.get("loanResultId"),snapshot.get("loanResultHash"),snapshot.get("evidenceBundleHash"),snapshot.get("policyVersion"),request.reviewSnapshotHash(),
            approved?policy.approvalExtraRisk():0,approved?policy.automaticRiskLimit()+policy.approvalExtraRisk():policy.automaticRiskLimit(),approved?"AVAILABLE":"REJECTED",request.comment(),Timestamp.from(expires),Timestamp.from(now));
        UUID payJobId=null;
        String state=approved?"APPROVED":"REJECTED",reason=approved?null:"REVIEWER_REJECTED";
        if(approved) {
            payJobId=journal.enqueue(workflowId,integer(workflow,"generation"),"PAY",approvalId,now);
        }
        support.state(workflowId,state,"ALLOW",reason,now);
        support.audit(actionId,workflowId,null,null,actor.actorId(),approved?"LOAN_REVIEWER_APPROVED":"LOAN_REVIEWER_REJECTED",reason,
            Json.ordered("approvalId",approvalId,"reviewSnapshotHash",request.reviewSnapshotHash(),"payJobId",payJobId),now);
        var response=support.response(actionId,workflow,state,"ALLOW",reason,approved?"Review approved; mock payment is queued.":"Reviewer rejected the application.");
        response.put("approvalId",approvalId);response.put("extraRiskLimit",approved?policy.approvalExtraRisk():0);
        response.put("riskLimit",approved?policy.automaticRiskLimit()+policy.approvalExtraRisk():policy.automaticRiskLimit());
        response.put("expiresAt",expires);response.put("payJobId",payJobId);
        actions.save(actionId,actor.actorId(),"APPROVAL",workflowId,body,response);
        return response;
    }
}
