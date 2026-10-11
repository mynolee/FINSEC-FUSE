package com.finsec.fuse.workflow;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.persistence.*;
import com.finsec.fuse.policy.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.*;
import static com.finsec.fuse.workflow.WorkflowValues.*;

@Service
public class LoanTransactions {
    private final Db db; private final TimeSource time; private final Json json; private final FusePolicy policy;
    private final EvidenceValidator evidence; private final DelegationService delegation; private final QuarantineMatcher matcher;
    private final WorkflowJournal journal; private final KycTransactions stages; private final LoanProfiles profiles; private final WorkflowAgentRegistry agents;
    public LoanTransactions(Db db,TimeSource time,Json json,FusePolicy policy,EvidenceValidator evidence,
                            DelegationService delegation,QuarantineMatcher matcher,WorkflowJournal journal,KycTransactions stages,LoanProfiles profiles,WorkflowAgentRegistry agents) {
        this.db=db;this.time=time;this.json=json;this.policy=policy;this.evidence=evidence;
        this.delegation=delegation;this.matcher=matcher;this.journal=journal;this.stages=stages;this.profiles=profiles;this.agents=agents;
    }
    @Transactional
    public void execute(UUID jobId,UUID leaseToken) {
        var initial=db.required("SELECT * FROM workflow_job WHERE id=?",jobId);
        db.gate(); var workflow=db.lockWorkflow(id(initial,"workflow_id"));
        var job=db.required("SELECT * FROM workflow_job WHERE id=? FOR UPDATE",jobId);Instant now=time.now();
        if(!JobTransactions.valid(job,workflow,leaseToken,now) || !"LOAN".equals(str(job,"phase")) ||
                !"KYC_VALIDATED".equals(str(workflow,"state")) || id(job,"run_id")!=null)return;
        UUID workflowId=id(workflow,"id"), actionId=id(job,"execution_action_id");
        var application=db.required("SELECT * FROM loan_application WHERE id=?",id(workflow,"application_id"));
        UUID kycResultId=id(workflow,"current_kyc_result_id");
        var kyc=db.required("SELECT r.*, a.status AS run_status FROM agent_result r JOIN agent_run a ON a.id=r.run_id WHERE r.id=?",kycResultId);
        UUID kycRunId=id(kyc,"run_id");
        if(!"VALIDATED".equals(str(kyc,"status")) || !"VALIDATED".equals(str(kyc,"run_status")) ||
                !workflowId.equals(id(kyc,"workflow_id")) || integer(kyc,"generation")!=integer(workflow,"generation")) {
            stages.stop(workflowId,jobId,null,actionId,"BLOCKED","DENY","CONTEXT_MISMATCH",now);return;
        }
        if(matcher.isQuarantined(kycRunId) || matcher.workflowQuarantined(workflowId)) {
            stages.stop(workflowId,jobId,null,actionId,"BLOCKED","DENY","QUARANTINED",now);return;
        }
        var checked=evidence.validateStored(kycResultId,now);
        if(!checked.validated()) {
            // Newly expired or revoked evidence is a hold; this is not a new model attack.
            stages.stop(workflowId,jobId,null,actionId,"ON_HOLD","DENY",checked.reasonCode(),now);return;
        }
        var stage=db.required("SELECT * FROM workflow_stage WHERE workflow_id=? AND stage='LOAN'",workflowId);
        if(integer(stage,"run_count")>=policy.maxRunsPerStage()) {
            stages.stop(workflowId,jobId,null,actionId,"ON_HOLD","ALLOW","MANUAL_REVIEW_REQUIRED",now);return;
        }
        int charge=integer(stage,"used_points")==0?policy.loanRisk():0;
        if(integer(workflow,"used_risk")+integer(workflow,"reserved_risk")+charge>policy.automaticRiskLimit()) {
            stages.stop(workflowId,jobId,null,actionId,"WAIT_APPROVAL","WAIT_APPROVAL","RISK_LIMIT_EXCEEDED",now);return;
        }
        var profile=profiles.get(str(application,"customer_id"));
        var account=db.required("SELECT * FROM mock_account WHERE id=?",id(application,"payout_account_id"));
        var input=Json.ordered("workflowId",workflowId,"generation",integer(workflow,"generation"),"kycResultId",kycResultId,
                "kycResultHash",str(kyc,"result_hash"),"evidenceBundleHash",checked.evidenceBundleHash(),
                "amountKrw",number(application,"amount_krw"),"payoutAccountId",id(application,"payout_account_id"),
                "loanPolicyVersion",str(profile,"policy_version"),"profileHash",str(profile,"profile_hash"));
        byte[] inputBytes=json.bytes(input);UUID runId=UUID.randomUUID();
        var selectedAgent=agents.select(workflow,"LOAN");
        if(selectedAgent.isEmpty()){stages.unavailableAgent(workflowId,jobId,actionId,"LOAN",now);return;}
        var agent=selectedAgent.get();
        db.update("UPDATE workflow_stage SET run_count=run_count+1 WHERE workflow_id=? AND stage='LOAN'",workflowId);
        db.update("INSERT INTO agent_run(id,workflow_id,generation,role,agent_id,agent_version,run_index,status,action_id,input_bytes,input_snapshot_hash,created_at) VALUES(?,?,?,'LOAN',?,?,?,'QUEUED',?,?,?,?)",
                runId,workflowId,integer(workflow,"generation"),str(agent,"agent_id"),integer(agent,"version"),integer(stage,"run_count")+1,actionId,inputBytes,Json.sha256(inputBytes),now);
        db.update("UPDATE workflow_job SET run_id=? WHERE id=?",runId,jobId);
        var parentGrant=db.required("SELECT id FROM delegation_grant WHERE target_run_id=? AND status='CONSUMED'",kycRunId);
        try {
            var transport=delegation.issue(workflowId,"LOAN",kycRunId,runId,kycResultId,id(parentGrant,"id"),actionId,null,checked.evidenceBundleHash(),inputBytes,now);
            var claims=delegation.validate(transport,"KYC",workflowId,runId,"CREATE_LOAN_RECOMMENDATION",now);
            delegation.consume(claims.grantId(),now);
            stages.start(workflow,job,runId,"LOAN",charge,now);
            db.update("INSERT INTO run_dependency(parent_run_id,child_run_id,parent_result_id,workflow_id,generation) VALUES(?,?,?,?,?)",
                    kycRunId,runId,kycResultId,workflowId,integer(workflow,"generation"));
            journal.state(workflowId,"REVIEW_READY","ALLOW",null,now);
            journal.event(workflowId,runId,actionId,"fuse-worker","DELEGATION_ALLOWED",null,Json.ordered("grantId",claims.grantId(),"sourceResultId",kycResultId),now);
            boolean recommend=LoanCalculation.recommendsApproval(number(profile,"monthly_income_krw"),number(profile,"max_loan_amount_krw"),number(application,"amount_krw"),
                    str(application,"customer_id").equals(str(account,"customer_id")) && "ACTIVE".equals(str(account,"status")));
            var result=Json.ordered("recommendation",recommend?"APPROVE_RECOMMENDED":"REJECT_RECOMMENDED","policyVersion",str(profile,"policy_version"),
                    "profileHash",str(profile,"profile_hash"),"customerId",str(application,"customer_id"),"amountKrw",number(application,"amount_krw"),
                    "payoutAccountId",id(application,"payout_account_id"),"kycResultId",kycResultId);
            UUID resultId=UUID.randomUUID();
            db.update("INSERT INTO agent_result(id,run_id,workflow_id,generation,status,body_json,result_hash,evidence_bundle_hash,created_at) VALUES(?,?,?,?,'VALIDATED',?::jsonb,?,?,?)",
                    resultId,runId,workflowId,integer(workflow,"generation"),json.write(result),json.hash(result),checked.evidenceBundleHash(),now);
            db.update("UPDATE agent_run SET status='VALIDATED',completed_at=? WHERE id=?",now,runId);
            db.update("UPDATE workflow SET current_loan_result_id=? WHERE id=?",resultId,workflowId);
            journal.finishJob(jobId,"SUCCEEDED",null,now);
            journal.state(workflowId,recommend?"WAIT_APPROVAL":"REJECTED",recommend?"WAIT_APPROVAL":"ALLOW",recommend?"APPROVAL_REQUIRED":"LOAN_NOT_ELIGIBLE",now);
            if(recommend)db.update("UPDATE workflow SET reason_codes=?::jsonb WHERE id=?",json.write(List.of("APPROVAL_REQUIRED","RISK_LIMIT_EXCEEDED")),workflowId);
            journal.event(workflowId,runId,actionId,"fuse-worker","LOAN_RECOMMENDED",null,Json.ordered("resultId",resultId,"recommendation",result.get("recommendation")),now);
            if(recommend)journal.event(workflowId,runId,actionId,"fuse-worker","APPROVAL_WAITING","APPROVAL_REQUIRED",Map.of(),now);
        }catch(PolicyException denial){stages.internalDenial(workflowId,jobId,runId,actionId,denial.reasonCode(),now);}
    }
}
