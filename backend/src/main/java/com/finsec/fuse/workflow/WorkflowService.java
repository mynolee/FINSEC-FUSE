package com.finsec.fuse.workflow;

import com.finsec.fuse.auth.*;
import com.finsec.fuse.common.*;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.persistence.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.*;
import static com.finsec.fuse.workflow.WorkflowValues.*;

@Service
public class WorkflowService {
    private final Db db;private final TimeSource time;private final FusePolicy policy;
    private final ActionRequests actions;private final WorkflowJournal journal;
    private final com.finsec.fuse.config.FuseReadinessHealthIndicator readiness;
    public WorkflowService(Db db,TimeSource time,FusePolicy policy,ActionRequests actions,WorkflowJournal journal,com.finsec.fuse.config.FuseReadinessHealthIndicator readiness) {
        this.db=db;this.time=time;this.policy=policy;this.actions=actions;this.journal=journal;this.readiness=readiness;
    }
    @Transactional
    public Map<String,Object> start(Actor actor,UUID actionId,StartWorkflowRequest request) {
        RoleGuard.require(actor,"CUSTOMER","LOAN_REVIEWER");RoleGuard.requireCustomer(actor,request.customerId());
        if(request.amountKrw()==null || request.amountKrw()<1 || request.amountKrw()>policy.maxAmountKrw())
            throw new ApiException(400,"INVALID_REQUEST","Amount is outside the mock policy range");
        db.gate();Instant now=time.now();
        var replay=actions.replay(actionId,actor.actorId(),"START_WORKFLOW",null,request);
        if(replay.isPresent())return replay.get();
        readiness.requireReady();
        var registry=db.one("SELECT * FROM application_registry WHERE business_reference=?",request.businessReference())
                .orElseThrow(()->new ApiException(409,"APPLICATION_CONFLICT","Application is not registered"));
        if(!request.customerId().equals(str(registry,"customer_id")) || request.amountKrw()!=number(registry,"amount_krw") ||
                !request.payoutAccountId().equals(id(registry,"payout_account_id")))
            throw new ApiException(409,"APPLICATION_CONFLICT","Application does not match its registered terms");
        var account=db.required("SELECT * FROM mock_account WHERE id=?",request.payoutAccountId());
        if(!request.customerId().equals(str(account,"customer_id")) || !"ACTIVE".equals(str(account,"status")))
            throw new ApiException(403,"FORBIDDEN","A customer-owned active mock account is required");
        var previous=db.one("SELECT w.* FROM workflow w JOIN loan_application a ON a.id=w.application_id WHERE a.business_reference=?",request.businessReference());
        Map<String,Object> result;
        if(previous.isPresent()) {
            var w=previous.get();result=response(actionId,id(w,"id"),integer(w,"generation"),str(w,"state"),str(w,"last_decision"),str(w,"last_reason_code"));
        } else {
            UUID applicationId=UUID.randomUUID(),workflowId=UUID.randomUUID();
            db.update("INSERT INTO loan_application(id,business_reference,customer_id,amount_krw,payout_account_id,created_at) VALUES(?,?,?,?,?,?)",
                    applicationId,request.businessReference(),request.customerId(),request.amountKrw(),request.payoutAccountId(),now);
            db.update("INSERT INTO workflow(id,application_id,root_authorization_id,risk_ledger_id,principal_id,generation,policy_version,state,created_at,updated_at) VALUES(?,?,?,?,?,1,?,'KYC_PENDING',?,?)",
                    workflowId,applicationId,UUID.randomUUID(),UUID.randomUUID(),actor.actorId(),policy.policyVersion(),now,now);
            for(String stage:List.of("KYC","LOAN","PAYMENT"))db.update("INSERT INTO workflow_stage(workflow_id,stage) VALUES(?,?)",workflowId,stage);
            UUID jobId=journal.enqueue(workflowId,1,"KYC",now);
            journal.event(workflowId,null,actionId,actor.actorId(),"WORKFLOW_CREATED",null,Json.ordered("jobId",jobId,"businessReference",request.businessReference()),now);
            result=response(actionId,workflowId,1,"KYC_PENDING","ALLOW",null);
        }
        actions.save(actionId,actor.actorId(),"START_WORKFLOW",null,request,result);
        return result;
    }
    private Map<String,Object> response(UUID actionId,UUID workflowId,int generation,String state,String decision,String reason) {
        return Json.ordered("requestId",actionId,"workflowId",workflowId,"generation",generation,"state",state,"decision",decision,
                "reasonCodes",reason==null?List.of():List.of(reason),"message","Workflow request accepted","replayed",false);
    }
}
