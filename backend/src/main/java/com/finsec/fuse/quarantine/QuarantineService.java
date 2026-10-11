package com.finsec.fuse.quarantine;

import static com.finsec.fuse.payment.PaymentValues.*;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.RoleGuard;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.observation.QuarantineObservation;
import com.finsec.fuse.payment.PaymentRiskService;
import com.finsec.fuse.payment.PaymentSupport;
import com.finsec.fuse.persistence.*;
import com.finsec.fuse.policy.EvidenceValidator;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;

@Service
public class QuarantineService {
    private final Db db;private final Json json;private final TimeSource time;private final FusePolicy policy;
    private final ActionRequests actions;private final ImpactGraph graph;private final PaymentRiskService risk;
    private final PaymentSupport support;private final EvidenceValidator evidence;
    public QuarantineService(Db db,Json json,TimeSource time,FusePolicy policy,ActionRequests actions,ImpactGraph graph,
        PaymentRiskService risk,PaymentSupport support,EvidenceValidator evidence) {
        this.db=db;this.json=json;this.time=time;this.policy=policy;this.actions=actions;this.graph=graph;this.risk=risk;this.support=support;this.evidence=evidence;
    }
    @Transactional
    public Map<String,Object> apply(Actor actor,UUID actionId,QuarantineRequest request) {
        RoleGuard.require(actor,"SECURITY_OPERATOR");db.gate();
        var target=target(request);validateTarget(target);authorizeTarget(actor,target);
        var replay=actions.replay(actionId,actor.actorId(),"QUARANTINE",null,request);if(replay.isPresent())return replay.get();
        var response=applyLocked(actor.actorId(),actionId,target,request.reasonCode().name(),request.note(),time.now());
        actions.save(actionId,actor.actorId(),"QUARANTINE",null,request,response);return response;
    }
    /** Called only for an assigned run's verified security violation; joins the caller's transaction. */
    @Transactional
    public Map<String,Object> automaticRun(UUID runId,String reasonCode,String note) {
        db.gate();var run=db.required("select * from agent_run where id=?",runId);
        var target=Json.ordered("scope","RUN","run_id",runId);
        return applyLocked("fuse-worker",uuid(run,"action_id"),target,reasonCode,note,time.now());
    }
    /** Records a policy hold, not document consumption, before any run is prepared. */
    @Transactional(propagation=Propagation.MANDATORY)
    public void recordSourceHold(UUID workflowId,UUID documentId,int documentVersion) {
        recordHolds(workflowId,db.query("select id from quarantine where scope='SOURCE_VERSION' and status='ACTIVE' and document_id=? and document_version=?",documentId,documentVersion));
    }
    @Transactional(propagation=Propagation.MANDATORY)
    public void recordAgentHold(UUID workflowId,String role) {
        recordHolds(workflowId,db.query("select q.id from quarantine q join agent_registry a on a.agent_id=q.agent_id and a.version=q.agent_version where q.scope='AGENT_VERSION' and q.status='ACTIVE' and a.role=?",role));
    }
    private void recordHolds(UUID workflowId,List<Map<String,Object>> incidents) {
        var workflow=db.required("select * from workflow where id=?",workflowId);var now=time.now();
        for(var incident:incidents) {
            UUID incidentId=uuid(incident,"id");
            if(db.update("insert into quarantine_workflow_hold(quarantine_id,workflow_id,generation,created_at) values(?,?,?,?) on conflict do nothing",incidentId,workflowId,integer(workflow,"generation"),now)>0)
                support.audit(null,workflowId,null,incidentId,"fuse-worker","QUARANTINE_POLICY_HOLD","QUARANTINED",Json.ordered("generation",integer(workflow,"generation"),"actualRunCreated",false),now);
        }
    }
    private Map<String,Object> applyLocked(String actorId,UUID actionId,Map<String,Object> target,String reason,String note,Instant now) {
        var existing=activeDuplicate(target);if(existing.isPresent())return response(actionId,existing.get(),"ACTIVE","An active quarantine already covers this exact target.");
        var affected=graph.affected(target);
        Map<UUID,Map<String,Object>> workflows=new LinkedHashMap<>();
        for(UUID id:affected.currentWorkflowIds())workflows.put(id,db.lockWorkflow(id));
        long epoch=number(db.required("update execution_gate set epoch=epoch+1 where id=1 returning epoch"),"epoch");
        UUID quarantineId=UUID.randomUUID();
        db.update("insert into quarantine(id,scope,run_id,result_id,workflow_id,document_id,document_version,agent_id,agent_version,status,reason_code,note,actor_id,action_id,gate_epoch,created_at) values(?,?,?,?,?,?,?,?,?,'ACTIVE',?,?,?,?,?,?)",
            quarantineId,str(target,"scope"),uuid(target,"run_id"),uuid(target,"result_id"),uuid(target,"workflow_id"),uuid(target,"document_id"),target.get("document_version"),str(target,"agent_id"),target.get("agent_version"),reason,note,actorId,actionId,epoch,now);
        for(UUID runId:affected.historicalRunIds()) {
            db.update("update agent_result set status='INVALIDATED' where run_id=?",runId);
            db.update("update agent_run set status='BLOCKED',completed_at=? where id=? and status in ('QUEUED','RUNNING','PROPOSED')",now,runId);
        }
        int blockedPayments=0,paidCount=0;
        Set<QuarantineObservation.Execution> observedExecutions=new LinkedHashSet<>();
        for(var entry:workflows.entrySet()) {
            UUID id=entry.getKey();var workflow=entry.getValue();boolean paid="PAID".equals(str(workflow,"state")) || db.one("select id from mock_payment where workflow_id=?",id).isPresent();
            if(paid) {
                paidCount++;
                support.audit(actionId,id,null,quarantineId,actorId,"POST_PAYMENT_QUARANTINE",reason,Json.ordered("paidBeforeQuarantine",true),now);
                continue;
            }
            if("APPROVED".equals(str(workflow,"state")) || "PAYMENT_RESERVED".equals(str(workflow,"state")))blockedPayments++;
            if(QuarantineObservation.enabled()) {
                // Observe only concrete, already-started executions that this transaction invalidates.
                // The row locks/gate and all security decisions are unchanged by observation.
                for(var job:db.query("select j.* from workflow_job j join agent_run r on r.id=j.run_id where j.workflow_id=? and j.generation=? and j.state='RUNNING' and j.phase in ('KYC','PAY') and j.lease_until>? and r.started_at is not null",id,integer(workflow,"generation"),now))
                    observedExecutions.add(new QuarantineObservation.Execution(id,integer(job,"generation"),uuid(job,"id"),uuid(job,"run_id"),uuid(job,"lease_token")));
            }
            risk.releaseLocked(id,now);
            db.update("update approval set status='REVOKED' where workflow_id=? and status in ('AVAILABLE','RESERVED')",id);
            db.update("update delegation_grant set status='REVOKED' where workflow_id=? and generation=? and status='ISSUED'",id,integer(workflow,"generation"));
            db.update("update workflow_job set state='FAILED',last_error='QUARANTINED',completed_at=? where workflow_id=? and state in ('PENDING','RUNNING')",now,id);
            support.state(id,"BLOCKED","DENY",reason,now);
            support.audit(actionId,id,null,quarantineId,actorId,"QUARANTINE_APPLIED",reason,Json.ordered("scope",str(target,"scope"),"gateEpoch",epoch),now);
        }
        support.audit(actionId,null,null,quarantineId,actorId,"QUARANTINE_APPLIED",reason,
            Json.ordered("target",graph.targetView(target),"historicalRunIds",affected.historicalRunIds(),"currentAffectedWorkflowIds",affected.currentWorkflowIds(),"blockedPaymentCount",blockedPayments,"paidBeforeQuarantineCount",paidCount,"gateEpoch",epoch),now);
        QuarantineObservation.quarantineWillCommit(quarantineId,observedExecutions);
        return response(actionId,db.required("select * from quarantine where id=?",quarantineId),"ACTIVE","Quarantine applied to the recorded lineage.");
    }
    @Transactional
    public Map<String,Object> release(Actor actor,UUID quarantineId,UUID actionId,ReleaseRequest request) {
        RoleGuard.require(actor,"SECURITY_OPERATOR");db.gate();
        var quarantine=db.one("select * from quarantine where id=? for update",quarantineId).orElseThrow(this::inaccessible);authorizeTarget(actor,quarantine);var now=time.now();
        var body=Json.ordered("quarantineId",quarantineId,"remediation",request.remediation());
        var replay=actions.replay(actionId,actor.actorId(),"QUARANTINE_RELEASE",null,body);if(replay.isPresent())return replay.get();
        if(!"ACTIVE".equals(str(quarantine,"status")))throw new ApiException(409,"INVALID_STATE","This quarantine has already been released.");
        var affected=graph.affected(quarantine);Map<UUID,Map<String,Object>> unpaid=new LinkedHashMap<>();
        for(UUID workflowId:affected.currentWorkflowIds()) {
            var workflow=db.lockWorkflow(workflowId);
            if(!"PAID".equals(str(workflow,"state")) && db.one("select id from mock_payment where workflow_id=?",workflowId).isEmpty())unpaid.put(workflowId,workflow);
        }
        var remediation=request.remediation();validateSafeDocument(remediation.safeDocumentId(),remediation.safeDocumentVersion());
        if("AGENT_VERSION".equals(str(quarantine,"scope"))) {
            if(remediation.safeAgentId()==null || remediation.safeAgentVersion()==null)recoveryFailed("An explicitly reviewed replacement agent version is required.");
            var safe=db.one("select * from agent_registry where agent_id=? and version=? and status='ACTIVE'",remediation.safeAgentId(),remediation.safeAgentVersion());
            if(safe.isEmpty() || !policy.safeAgentVersions().contains(remediation.safeAgentId()+":"+remediation.safeAgentVersion()))recoveryFailed("The replacement agent is not in the reviewed registry.");
            if(db.one("select id from quarantine where scope='AGENT_VERSION' and agent_id=? and agent_version=? and status='ACTIVE'",remediation.safeAgentId(),remediation.safeAgentVersion()).isPresent())recoveryFailed("The replacement agent is still quarantined.");
            var original=db.required("select * from agent_registry where agent_id=? and version=?",str(quarantine,"agent_id"),integer(quarantine,"agent_version"));
            if(!Objects.equals(str(original,"role"),str(safe.orElseThrow(),"role")))recoveryFailed("The replacement agent must have the same registered role.");
        }
        Map<String,List<UUID>> grouped=new HashMap<>();
        for(UUID id:new LinkedHashSet<>(remediation.checkEvidenceIds())) {
            var record=db.one("select customer_id from trusted_evidence where id=?",id);
            if(record.isEmpty() || !actor.canAccess(str(record.orElseThrow(),"customer_id")))throw inaccessible();
            grouped.computeIfAbsent(str(record.orElseThrow(),"customer_id"),k->new ArrayList<>()).add(id);
        }
        var checks=new ArrayList<Map<String,Object>>();
        for(var entry:unpaid.entrySet()) {
            String customer=str(support.application(entry.getValue()),"customer_id");
            var checked=evidence.validateForCustomer(customer,grouped.getOrDefault(customer,List.of()),now);
            if(!checked.validated())recoveryFailed("Every affected unpaid customer needs current independent evidence: "+checked.reasonCode());
            checks.add(Json.ordered("workflowId",entry.getKey(),"customerId",customer,"evidenceBundleHash",checked.evidenceBundleHash()));
        }
        // Audit only the independently checked authority. Freeform business notes remain separate.
        var checkedDetails=Json.ordered("safeDocumentId",remediation.safeDocumentId(),
            "safeDocumentVersion",remediation.safeDocumentVersion(),"checks",checks,
            "noteProvided",remediation.note()!=null && !remediation.note().isBlank());
        if("AGENT_VERSION".equals(str(quarantine,"scope"))) {
            checkedDetails.put("safeAgentId",remediation.safeAgentId());
            checkedDetails.put("safeAgentVersion",remediation.safeAgentVersion());
        }
        support.audit(actionId,null,null,quarantineId,actor.actorId(),"RECOVERY_CHECKED",null,checkedDetails,now);
        db.update("update quarantine set status='RELEASED',released_by=?,released_at=?,remediation_json=?::jsonb where id=?",actor.actorId(),now,json.write(remediation),quarantineId);
        db.update("update execution_gate set epoch=epoch+1 where id=1");
        for(UUID workflowId:unpaid.keySet()) {
            db.update("update workflow set recovery_document_id=?,recovery_document_version=?,updated_at=? where id=?",remediation.safeDocumentId(),remediation.safeDocumentVersion(),now,workflowId);
            if("AGENT_VERSION".equals(str(quarantine,"scope")))
                db.update("update workflow set recovery_agent_id=?,recovery_agent_version=? where id=?",remediation.safeAgentId(),remediation.safeAgentVersion(),workflowId);
            support.audit(actionId,workflowId,null,quarantineId,actor.actorId(),"QUARANTINE_RELEASED",null,Json.ordered("explicitResumeRequired",true),now);
        }
        support.audit(actionId,null,null,quarantineId,actor.actorId(),"QUARANTINE_RELEASED",null,Json.ordered("explicitResumeRequired",true),now);
        var response=response(actionId,quarantine,"RELEASED","Quarantine released. A separate explicit resume is required.");
        actions.save(actionId,actor.actorId(),"QUARANTINE_RELEASE",null,body,response);return response;
    }
    public void validateSafeDocument(UUID documentId,int version) {
        var source=db.one("select * from source_document_version where document_id=? and version=?",documentId,version);
        if(source.isEmpty() || !policy.safeSources().contains(documentId+":"+version) || !Boolean.TRUE.equals(source.get().get("reviewed_safe")))recoveryFailed("The document version is not in the reviewed safe-source registry.");
        if(!Json.sha256(str(source.orElseThrow(),"content").getBytes(java.nio.charset.StandardCharsets.UTF_8)).equals(str(source.get(),"content_hash")))recoveryFailed("The safe source content does not match its stored hash.");
        if(db.one("select id from quarantine where scope='SOURCE_VERSION' and document_id=? and document_version=? and status='ACTIVE'",documentId,version).isPresent())recoveryFailed("The selected safe document is still quarantined.");
    }
    @Transactional
    public Map<String,Object> impact(Actor actor,UUID quarantineId) {
        RoleGuard.require(actor,"SECURITY_OPERATOR");db.gate();
        var quarantine=db.one("select * from quarantine where id=?",quarantineId).orElseThrow(this::inaccessible);authorizeTarget(actor,quarantine);
        for(UUID workflowId:graph.affected(quarantine).currentWorkflowIds())db.lockWorkflow(workflowId);
        return graph.describe(quarantineId);
    }
    private Optional<Map<String,Object>> activeDuplicate(Map<String,Object> target) {
        return switch(str(target,"scope")) {
            case "RUN" -> db.one("select * from quarantine where scope='RUN' and run_id=? and status='ACTIVE'",uuid(target,"run_id"));
            case "RESULT" -> db.one("select * from quarantine where scope='RESULT' and result_id=? and status='ACTIVE'",uuid(target,"result_id"));
            case "WORKFLOW" -> db.one("select * from quarantine where scope='WORKFLOW' and workflow_id=? and status='ACTIVE'",uuid(target,"workflow_id"));
            case "SOURCE_VERSION" -> db.one("select * from quarantine where scope='SOURCE_VERSION' and document_id=? and document_version=? and status='ACTIVE'",uuid(target,"document_id"),target.get("document_version"));
            case "AGENT_VERSION" -> db.one("select * from quarantine where scope='AGENT_VERSION' and agent_id=? and agent_version=? and status='ACTIVE'",str(target,"agent_id"),target.get("agent_version"));
            default -> throw new ApiException(400,"INVALID_REQUEST","Unknown scope.");
        };
    }
    private Map<String,Object> target(QuarantineRequest r) {
        if(r.scope()==null)throw new ApiException(400,"INVALID_REQUEST","A quarantine scope is required.");
        return Json.ordered("scope",r.scope().name(),"run_id",r.runId(),"result_id",r.resultId(),"workflow_id",r.workflowId(),"document_id",r.documentId(),"document_version",r.documentVersion(),"agent_id",r.agentId(),"agent_version",r.agentVersion());
    }
    private void validateTarget(Map<String,Object> target) {
        String scope=str(target,"scope");List<String> expected=switch(scope) {
            case "RUN"->List.of("run_id");case "RESULT"->List.of("result_id");case "WORKFLOW"->List.of("workflow_id");
            case "SOURCE_VERSION"->List.of("document_id","document_version");case "AGENT_VERSION"->List.of("agent_id","agent_version");
            default->throw new ApiException(400,"INVALID_REQUEST","Unknown scope.");};
        for(String key:List.of("run_id","result_id","workflow_id","document_id","document_version","agent_id","agent_version"))
            if(expected.contains(key)!=(target.get(key)!=null))throw new ApiException(400,"INVALID_REQUEST","Only the target fields for the selected scope may be supplied.");
    }
    /** Broad source/agent scopes require access to every recorded and registered potential consumer. */
    private void authorizeTarget(Actor actor,Map<String,Object> target) {
        Set<String> customers=new HashSet<>();String scope=str(target,"scope");
        Optional<Map<String,Object>> owner=Optional.empty();boolean exists;
        switch(scope) {
            case "RUN" -> {
                owner=db.one("select a.customer_id from agent_run r join workflow w on w.id=r.workflow_id join loan_application a on a.id=w.application_id where r.id=?",uuid(target,"run_id"));exists=owner.isPresent();
            }
            case "RESULT" -> {
                owner=db.one("select a.customer_id from agent_result r join workflow w on w.id=r.workflow_id join loan_application a on a.id=w.application_id where r.id=?",uuid(target,"result_id"));exists=owner.isPresent();
            }
            case "WORKFLOW" -> {
                owner=db.one("select a.customer_id from workflow w join loan_application a on a.id=w.application_id where w.id=?",uuid(target,"workflow_id"));exists=owner.isPresent();
            }
            case "SOURCE_VERSION" -> {
                exists=db.one("select document_id from source_document_version where document_id=? and version=?",uuid(target,"document_id"),integer(target,"document_version")).isPresent();
                for(var row:db.query("select distinct customer_id from application_registry where document_id=? and document_version=?",uuid(target,"document_id"),integer(target,"document_version")))customers.add(str(row,"customer_id"));
            }
            case "AGENT_VERSION" -> {
                exists=db.one("select agent_id from agent_registry where agent_id=? and version=?",str(target,"agent_id"),integer(target,"agent_version")).isPresent();
                for(var row:db.query("select distinct customer_id from application_registry"))customers.add(str(row,"customer_id"));
            }
            default -> throw inaccessible();
        }
        if(!exists)throw inaccessible();
        owner.ifPresent(row->customers.add(str(row,"customer_id")));
        var affected=graph.affected(target);
        for(var run:affected.runs())customers.add(str(run,"customer_id"));
        for(UUID heldId:affected.heldWorkflowIds())customers.add(str(db.required("select a.customer_id from workflow w join loan_application a on a.id=w.application_id where w.id=?",heldId),"customer_id"));
        // A source without consumers still changes a global policy target; an empty scope is never authority.
        if(customers.isEmpty())for(var row:db.query("select distinct customer_id from application_registry"))customers.add(str(row,"customer_id"));
        if(customers.isEmpty() || !customers.stream().allMatch(actor::canAccess))throw inaccessible();
    }
    private ApiException inaccessible() {return new ApiException(403,"FORBIDDEN","The target is outside the authenticated security access scope.");}
    private Map<String,Object> response(UUID actionId,Map<String,Object> quarantine,String state,String message) {
        return Json.ordered("requestId",actionId,"workflowId",uuid(quarantine,"workflow_id"),"generation",null,"state",state,"decision","ALLOW","reasonCodes",List.of(),"message",message,"replayed",false,
            "quarantineId",uuid(quarantine,"id"),"scope",str(quarantine,"scope"),"target",graph.targetView(quarantine));
    }
    private void recoveryFailed(String message) {throw new ApiException(409,"RECOVERY_CHECK_FAILED",message);}
}
