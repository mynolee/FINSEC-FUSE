package com.finsec.fuse.payment;

import static com.finsec.fuse.payment.PaymentValues.*;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.observation.QuarantineObservation;
import com.finsec.fuse.persistence.*;
import com.finsec.fuse.policy.DelegationService;
import com.finsec.fuse.policy.PolicyException;
import com.finsec.fuse.policy.QuarantineMatcher;
import com.finsec.fuse.quarantine.QuarantineService;
import java.time.Instant;
import java.util.*;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Exactly-once guarantees here apply only to the mock ledger in this same PostgreSQL transaction. */
@Service
public class PaymentTxService {
    private static final String WORKER="fuse-worker";
    private static final String ACTION="EXECUTE_MOCK_PAYMENT";
    private final Db db; private final Json json; private final TimeSource time; private final FusePolicy policy;
    private final ActionRequests actions; private final PaymentSupport support; private final PaymentRiskService risk;
    private final DelegationService grants; private final ObjectProvider<PaymentTestHooks> hooks; private final QuarantineService quarantine;
    private final QuarantineMatcher matcher;
    public PaymentTxService(Db db,Json json,TimeSource time,FusePolicy policy,ActionRequests actions,
        PaymentSupport support,PaymentRiskService risk,DelegationService grants,ObjectProvider<PaymentTestHooks> hooks,QuarantineService quarantine,QuarantineMatcher matcher) {
        this.db=db;this.json=json;this.time=time;this.policy=policy;this.actions=actions;this.support=support;this.risk=risk;this.grants=grants;this.hooks=hooks;this.quarantine=quarantine;this.matcher=matcher;
    }
    @Transactional
    public Map<String,Object> reserve(UUID jobId,UUID leaseToken) {
        db.gate(); var initial=db.required("select * from workflow_job where id=?",jobId);
        UUID workflowId=uuid(initial,"workflow_id"); var workflow=db.lockWorkflow(workflowId);
        var job=db.required("select * from workflow_job where id=? for update",jobId); var now=time.now();
        UUID actionId=uuid(job,"execution_action_id"); var body=support.actionBody(workflow,job);
        var prior=actions.replay(actionId,WORKER,ACTION,workflowId,body); if(prior.isPresent()) return prior.get();
        if(!"PAY".equals(str(job,"phase"))) throw new ApiException(409,"INVALID_STATE","A payment job is required.");
        if(!support.liveLease(job,workflow,leaseToken,now)) return late(workflow,job,leaseToken,now);
        if(db.one("select id from mock_payment where workflow_id=?",workflowId).isPresent())
            return stop(workflow,job,"INVALID_STATE","PAID","DENY",now);
        var reservation=db.one("select * from payment_reservation where execution_action_id=?",actionId);
        if(reservation.isPresent()) {
            if(!reservationMatches(reservation.get(),workflow,job))throw new ApiException(409,"REPLAY_CONFLICT","The reservation is bound to a different execution context.");
            if(!json.hash(body).equals(str(reservation.get(),"payload_hash"))) throw new ApiException(409,"REPLAY_CONFLICT","Payment terms changed for an existing execution.");
            if("RESERVED".equals(str(reservation.get(),"status"))) return support.response(actionId,workflow,"PAYMENT_RESERVED","ALLOW",null,"Existing reservation reused.");
            return stop(workflow,job,"APPROVAL_REQUIRED","WAIT_APPROVAL","WAIT_APPROVAL",now);
        }
        if(!"APPROVED".equals(str(workflow,"state"))) {
            if("WAIT_APPROVAL".equals(str(workflow,"state"))) return stop(workflow,job,"APPROVAL_REQUIRED","WAIT_APPROVAL","WAIT_APPROVAL",now);
            return stop(workflow,job,"INVALID_STATE",str(workflow,"state"),"DENY",now);
        }
        var approval=db.one("select * from approval where id=?",uuid(job,"approval_id")).orElse(null);
        if(approval==null || !now.isBefore(instant(approval,"expires_at"))) return stop(workflow,job,"APPROVAL_REQUIRED","WAIT_APPROVAL","WAIT_APPROVAL",now);
        String failure=support.currentFailure(workflow,now);
        if(failure!=null) return stop(workflow,job,failure,"QUARANTINED".equals(failure)?"BLOCKED":"ON_HOLD","DENY",now);
        if(!support.exactApproval(workflow,approval,actionId,now,false)) return rejectApproval(workflow,job,approval,now);
        if(integer(workflow,"used_risk")+integer(workflow,"reserved_risk")+policy.paymentRisk()>policy.approvedRiskLimit())
            return stop(workflow,job,"RISK_LIMIT_EXCEEDED","WAIT_APPROVAL","WAIT_APPROVAL",now);
        var loan=db.required("select * from agent_result where id=?",uuid(workflow,"current_loan_result_id"));
        UUID loanRunId=uuid(loan,"run_id");
        var parentGrant=db.required("select * from delegation_grant where target_run_id=?",loanRunId);
        var selectedAgent=paymentAgent(workflow);
        if(selectedAgent.isEmpty()) {
            // Absence is an operational hold unless an actual quarantine applies. This branch
            // precedes any payment run, grant or reservation; database failures still propagate.
            quarantine.recordAgentHold(workflowId,"PAYMENT");
            boolean quarantined=matcher.workflowQuarantined(workflowId);
            return stop(workflow,job,quarantined?"QUARANTINED":"DEPENDENCY_UNAVAILABLE",
                quarantined?"BLOCKED":"ON_HOLD",quarantined?"DENY":"ERROR",now);
        }
        var agent=selectedAgent.get();
        var stage=db.required("select * from workflow_stage where workflow_id=? and stage='PAYMENT'",workflowId);
        UUID runId=UUID.randomUUID(); int runIndex=integer(stage,"run_count")+1;
        db.update("update workflow_stage set run_count=? where workflow_id=? and stage='PAYMENT'",runIndex,workflowId);
        byte[] actionBytes=json.bytes(body);
        db.update("insert into agent_run(id,workflow_id,generation,role,agent_id,agent_version,run_index,status,action_id,input_bytes,input_snapshot_hash,created_at) values(?,?,?,'PAYMENT',?,?,?,'QUEUED',?,?,?,?)",
            runId,workflowId,integer(workflow,"generation"),str(agent,"agent_id"),integer(agent,"version"),runIndex,actionId,actionBytes,Json.sha256(actionBytes),now);
        db.update("update workflow_job set run_id=? where id=?",runId,jobId);
        UUID grantId;
        try {
            var transport=grants.issue(workflowId,"PAYMENT",loanRunId,runId,uuid(loan,"id"),uuid(parentGrant,"id"),actionId,uuid(approval,"id"),str(loan,"evidence_bundle_hash"),actionBytes,now);
            var claims=grants.validate(transport,"LOAN",workflowId,runId,ACTION,now);
            grantId=claims.grantId();
        } catch(PolicyException denied) {
            if(isSecurityDenial(denied.reasonCode())) {
                quarantine.automaticRun(runId,denied.reasonCode(),"Internally issued payment delegation failed validation");
                return support.response(actionId,workflow,"BLOCKED","DENY",denied.reasonCode(),"The prepared payment run was quarantined.");
            }
            db.update("update agent_run set status='BLOCKED',completed_at=? where id=?",now,runId);
            return stop(workflow,job,denied.reasonCode(),"GRANT_EXPIRED".equals(denied.reasonCode())?"WAIT_APPROVAL":"BLOCKED","GRANT_EXPIRED".equals(denied.reasonCode())?"WAIT_APPROVAL":"DENY",now);
        }
        db.update("update agent_run set status='RUNNING',started_at=? where id=?",now,runId);
        db.update("insert into run_dependency(parent_run_id,child_run_id,parent_result_id,workflow_id,generation) values(?,?,?,?,?)",loanRunId,runId,uuid(loan,"id"),workflowId,integer(workflow,"generation"));
        UUID reservationId=UUID.randomUUID();
        db.update("insert into payment_reservation(id,workflow_id,generation,job_id,execution_action_id,grant_id,run_id,approval_id,points,payload_hash,status,created_at) values(?,?,?,?,?,?,?,?,?,?,'RESERVED',?)",
            reservationId,workflowId,integer(workflow,"generation"),jobId,actionId,grantId,runId,uuid(approval,"id"),policy.paymentRisk(),json.hash(body),now);
        db.update("update approval set status='RESERVED',reserved_action_id=? where id=?",actionId,uuid(approval,"id"));
        db.update("update workflow set reserved_risk=reserved_risk+? where id=?",policy.paymentRisk(),workflowId);
        db.update("update workflow_stage set reserved_points=reserved_points+? where workflow_id=? and stage='PAYMENT'",policy.paymentRisk(),workflowId);
        ledger(workflow,reservationId,runId,actionId,"RESERVE",policy.paymentRisk(),now);
        support.state(workflowId,"PAYMENT_RESERVED","ALLOW",null,now);
        support.audit(actionId,workflowId,runId,null,WORKER,"PAYMENT_RESERVED",null,Json.ordered("reservationId",reservationId,"grantId",grantId),now);
        var response=support.response(actionId,workflow,"PAYMENT_RESERVED","ALLOW",null,"Mock payment reserved for a final security recheck.");
        response.put("reservationId",reservationId);return response;
    }
    @Transactional
    public Map<String,Object> commit(UUID jobId,UUID leaseToken) {
        db.gate(); hooks.ifAvailable(PaymentTestHooks::afterCommitGate);
        var initial=db.required("select * from workflow_job where id=?",jobId);
        UUID workflowId=uuid(initial,"workflow_id");var workflow=db.lockWorkflow(workflowId);
        var job=db.required("select * from workflow_job where id=? for update",jobId);var now=time.now();
        UUID actionId=uuid(job,"execution_action_id");var body=support.actionBody(workflow,job);
        var prior=actions.replay(actionId,WORKER,ACTION,workflowId,body); if(prior.isPresent())return prior.get();
        if(!support.liveLease(job,workflow,leaseToken,now)) return late(workflow,job,leaseToken,now);
        var reserved=db.one("select * from payment_reservation where execution_action_id=? for update",actionId);
        if(reserved.isEmpty() || !"RESERVED".equals(str(reserved.get(),"status"))) return stop(workflow,job,"APPROVAL_REQUIRED","WAIT_APPROVAL","WAIT_APPROVAL",now);
        var reservation=reserved.get();
        if(!reservationMatches(reservation,workflow,job))throw new ApiException(409,"REPLAY_CONFLICT","The reservation is bound to a different execution context.");
        if(!json.hash(body).equals(str(reservation,"payload_hash"))) throw new ApiException(409,"REPLAY_CONFLICT","Payment terms changed for the reserved execution.");
        if(!"PAYMENT_RESERVED".equals(str(workflow,"state")) || integer(reservation,"generation")!=integer(workflow,"generation"))
            return stop(workflow,job,"STALE_GENERATION","ON_HOLD","DENY",now);
        var run=db.required("select * from agent_run where id=?",uuid(reservation,"run_id"));
        if(!"RUNNING".equals(str(run,"status"))) return stop(workflow,job,"QUARANTINED","BLOCKED","DENY",now);
        var approval=db.required("select * from approval where id=?",uuid(reservation,"approval_id"));
        if(!now.isBefore(instant(approval,"expires_at")))return stop(workflow,job,"APPROVAL_REQUIRED","WAIT_APPROVAL","WAIT_APPROVAL",now);
        String failure=support.currentFailure(workflow,now);
        if(failure!=null)return stop(workflow,job,failure,"QUARANTINED".equals(failure)?"BLOCKED":"ON_HOLD","DENY",now);
        if(!support.exactApproval(workflow,approval,actionId,now,true))return rejectApproval(workflow,job,approval,now);
        if(integer(workflow,"used_risk")+integer(workflow,"reserved_risk")>policy.approvedRiskLimit() || integer(workflow,"reserved_risk")!=integer(reservation,"points"))
            return stop(workflow,job,"RISK_LIMIT_EXCEEDED","WAIT_APPROVAL","WAIT_APPROVAL",now);
        try {grants.validate(grants.transport(uuid(reservation,"grant_id")),"LOAN",workflowId,uuid(reservation,"run_id"),ACTION,now);}
        catch(PolicyException denied) {
            if(isSecurityDenial(denied.reasonCode())) {
                quarantine.automaticRun(uuid(reservation,"run_id"),denied.reasonCode(),"Reserved payment delegation failed its final validation");
                return support.response(actionId,workflow,"BLOCKED","DENY",denied.reasonCode(),"The reserved payment run was quarantined.");
            }
            return stop(workflow,job,denied.reasonCode(),"GRANT_EXPIRED".equals(denied.reasonCode())?"WAIT_APPROVAL":"BLOCKED","GRANT_EXPIRED".equals(denied.reasonCode())?"WAIT_APPROVAL":"DENY",now);
        }
        UUID paymentId=UUID.randomUUID(); var app=support.application(workflow);
        var receipt=support.response(actionId,workflow,"PAID","ALLOW",null,"Mock payment recorded.");
        receipt.put("paymentId",paymentId);receipt.put("amountKrw",number(app,"amount_krw"));receipt.put("payoutAccountId",uuid(app,"payout_account_id"));receipt.put("paidAt",now);
        db.update("insert into action_request(action_id,actor_id,action_type,workflow_id,payload_hash,status,created_at) values(?,?,?,?,?,'PROCESSING',?)",
            actionId,WORKER,ACTION,workflowId,actions.fingerprint(WORKER,ACTION,workflowId,body),now);
        db.update("insert into mock_payment(id,workflow_id,application_id,approval_id,reservation_id,action_id,run_id,generation,customer_id,amount_krw,payout_account_id,payload_hash,receipt_json,created_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?::jsonb,?)",
            paymentId,workflowId,uuid(app,"id"),uuid(approval,"id"),uuid(reservation,"id"),actionId,uuid(reservation,"run_id"),integer(workflow,"generation"),str(app,"customer_id"),number(app,"amount_krw"),uuid(app,"payout_account_id"),json.hash(body),json.write(receipt),now);
        db.update("update payment_reservation set status='COMMITTED',completed_at=? where id=?",now,uuid(reservation,"id"));
        db.update("update approval set status='CONSUMED',consumed_at=? where id=?",now,uuid(approval,"id"));
        grants.consume(uuid(reservation,"grant_id"),now);
        int points=integer(reservation,"points");
        db.update("update workflow_stage set used_points=used_points+?,reserved_points=reserved_points-? where workflow_id=? and stage='PAYMENT'",points,points,workflowId);
        db.update("update workflow set used_risk=used_risk+?,reserved_risk=reserved_risk-? where id=?",points,points,workflowId);
        support.state(workflowId,"PAID","ALLOW",null,now);
        db.update("update agent_run set status='SUCCEEDED',completed_at=? where id=?",now,uuid(reservation,"run_id"));
        db.update("update workflow_job set state='SUCCEEDED',completed_at=? where id=?",now,jobId);
        ledger(workflow,uuid(reservation,"id"),uuid(reservation,"run_id"),actionId,"CONSUME",points,now);
        db.update("update action_request set status='SUCCEEDED',decision='ALLOW',result_json=?::jsonb,completed_at=? where action_id=?",json.write(receipt),now,actionId);
        support.audit(actionId,workflowId,uuid(reservation,"run_id"),null,WORKER,"PAYMENT_COMMITTED",null,Json.ordered("paymentId",paymentId,"reservationId",uuid(reservation,"id"),"amountKrw",number(app,"amount_krw")),now);
        return receipt;
    }
    @Transactional
    public void reap(UUID jobId) {
        db.gate();var initial=db.required("select * from workflow_job where id=?",jobId);
        var workflow=db.lockWorkflow(uuid(initial,"workflow_id"));var job=db.required("select * from workflow_job where id=? for update",jobId);var now=time.now();
        if(!"PAY".equals(str(job,"phase")) || !"RUNNING".equals(str(job,"state")) || now.isBefore(instant(job,"lease_until")))return;
        var existing=db.one("select * from mock_payment where action_id=?",uuid(job,"execution_action_id"));
        if(existing.isPresent()) {
            // Restore the historical response only. No grant refresh, new reservation or debit is allowed.
            var receipt=json.map(str(existing.get(),"receipt_json"));var body=support.actionBody(workflow,job);
            if(db.one("select action_id from action_request where action_id=?",uuid(job,"execution_action_id")).isEmpty())
                actions.save(uuid(job,"execution_action_id"),WORKER,ACTION,uuid(workflow,"id"),body,receipt);
            db.update("update workflow_job set state='SUCCEEDED',completed_at=? where id=?",now,jobId);
            support.audit(uuid(job,"execution_action_id"),uuid(workflow,"id"),uuid(job,"run_id"),null,WORKER,"PAYMENT_RECEIPT_RESTORED",null,Json.ordered("paymentId",uuid(existing.get(),"id")),now);
        } else stop(workflow,job,"APPROVAL_REQUIRED","WAIT_APPROVAL","WAIT_APPROVAL",now);
    }
    private Map<String,Object> rejectApproval(Map<String,Object> workflow,Map<String,Object> job,Map<String,Object> approval,Instant now) {
        // Missing/expired approvals are handled separately as ordinary reapproval waits. An assigned
        // payment must never use revoked, foreign or content-mismatched authority as an operational hold.
        boolean sameWorkflow=Objects.equals(uuid(workflow,"id"),uuid(approval,"workflow_id")) &&
            integer(workflow,"generation")==integer(approval,"generation");
        boolean changedCustomer=sameWorkflow && !Objects.equals(str(support.application(workflow),"customer_id"),str(approval,"customer_id"));
        return stop(workflow,job,changedCustomer?"CONTEXT_MISMATCH":"APPROVAL_INVALID","BLOCKED","DENY",now);
    }
    private Map<String,Object> stop(Map<String,Object> workflow,Map<String,Object> job,String reason,String state,String decision,Instant now) {
        UUID workflowId=uuid(workflow,"id"),actionId=uuid(job,"execution_action_id");
        if("PAID".equals(str(workflow,"state"))) state="PAID";
        risk.releaseLocked(workflowId,now);
        // An invalid job may point at another workflow's approval. Cleanup must not revoke its authority.
        db.update("update approval set status=case when expires_at<=? then 'EXPIRED' else 'REVOKED' end where workflow_id=? and generation=? and status in ('AVAILABLE','RESERVED')",now,workflowId,integer(workflow,"generation"));
        db.update("update delegation_grant set status=case when expires_at<=? then 'EXPIRED' else 'REVOKED' end where action_id=? and status='ISSUED'",now,actionId);
        db.update("update workflow_job set state='FAILED',last_error=?,completed_at=? where id=? and state in ('PENDING','RUNNING')",reason,now,uuid(job,"id"));
        db.update("update agent_run set status='FAILED',completed_at=? where id=? and status in ('QUEUED','RUNNING')",now,uuid(job,"run_id"));
        support.state(workflowId,state,decision,reason,now);
        support.audit(actionId,workflowId,uuid(job,"run_id"),null,WORKER,"ERROR".equals(decision)?"SYSTEM_ERROR":"DENY".equals(decision)?"POLICY_DENIED":"APPROVAL_WAITING",reason,Json.ordered("jobId",uuid(job,"id")),now);
        return support.response(actionId,workflow,state,decision,reason,"Mock payment was not executed.");
    }
    private Map<String,Object> late(Map<String,Object> workflow,Map<String,Object> job,UUID leaseToken,Instant now) {
        if(QuarantineObservation.enabled() && "FAILED".equals(str(job,"state")) && "QUARANTINED".equals(str(job,"last_error")) &&
                "BLOCKED".equals(str(workflow,"state")) && integer(job,"generation")==integer(workflow,"generation") &&
                uuid(job,"run_id")!=null && Objects.equals(leaseToken,uuid(job,"lease_token")) &&
                instant(job,"lease_until")!=null && now.isBefore(instant(job,"lease_until")))
            QuarantineObservation.executionDenied(new QuarantineObservation.Execution(uuid(workflow,"id"),integer(job,"generation"),
                uuid(job,"id"),uuid(job,"run_id"),leaseToken),QuarantineObservation.Attempt.PAYMENT_EXECUTION);
        support.audit(uuid(job,"execution_action_id"),uuid(workflow,"id"),uuid(job,"run_id"),null,WORKER,"LATE_RESULT_DISCARDED","STALE_LEASE",Json.ordered("jobId",uuid(job,"id")),now);
        return support.response(uuid(job,"execution_action_id"),workflow,str(workflow,"state"),"DENY","STALE_LEASE","The execution lease is no longer current.");
    }
    private boolean reservationMatches(Map<String,Object> reservation,Map<String,Object> workflow,Map<String,Object> job) {
        return Objects.equals(uuid(reservation,"workflow_id"),uuid(workflow,"id")) &&
            Objects.equals(uuid(reservation,"job_id"),uuid(job,"id")) &&
            Objects.equals(uuid(reservation,"execution_action_id"),uuid(job,"execution_action_id")) &&
            Objects.equals(uuid(reservation,"run_id"),uuid(job,"run_id")) &&
            Objects.equals(uuid(reservation,"approval_id"),uuid(job,"approval_id")) &&
            integer(reservation,"generation")==integer(job,"generation") &&
            integer(reservation,"points")==policy.paymentRisk();
    }
    private boolean isSecurityDenial(String reason) {
        return Set.of("SIGNATURE_INVALID","CONTEXT_MISMATCH","SCOPE_EXCEEDED","EVIDENCE_MISSING","EVIDENCE_INVALID").contains(reason);
    }
    private Optional<Map<String,Object>> paymentAgent(Map<String,Object> workflow) {
        String recoveryAgent=str(workflow,"recovery_agent_id");
        Integer recoveryVersion=(Integer)workflow.get("recovery_agent_version");
        boolean paymentReplacement=recoveryAgent!=null && db.one("select agent_id from agent_registry where agent_id=? and version=? and role='PAYMENT'",recoveryAgent,recoveryVersion).isPresent();
        for(var candidate:db.query("select * from agent_registry where role='PAYMENT' and status='ACTIVE' order by version desc,agent_id")) {
            String agent=str(candidate,"agent_id");int version=integer(candidate,"version");
            if(paymentReplacement && (!agent.equals(recoveryAgent) || version!=recoveryVersion))continue;
            if(!policy.safeAgentVersions().contains(agent+":"+version))continue;
            if(db.one("select id from quarantine where scope='AGENT_VERSION' and agent_id=? and agent_version=? and status='ACTIVE'",agent,version).isEmpty())return Optional.of(candidate);
        }
        return Optional.empty();
    }
    private void ledger(Map<String,Object> workflow,UUID reservationId,UUID runId,UUID actionId,String event,int points,Instant now) {
        db.update("insert into risk_ledger(id,workflow_id,generation,stage,event_type,points,action_id,run_id,reservation_id,created_at) values(?,?,?,'PAYMENT',?,?,?,?,?,?)",
            UUID.randomUUID(),uuid(workflow,"id"),integer(workflow,"generation"),event,points,actionId,runId,reservationId,now);
    }
}
