package com.finsec.fuse.workflow;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.observation.QuarantineObservation;
import com.finsec.fuse.persistence.*;
import com.finsec.fuse.policy.*;
import com.finsec.fuse.quarantine.QuarantineService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import static com.finsec.fuse.workflow.WorkflowValues.*;

/** Every method is invoked through this separate transaction bean; HTTP never holds its locks. */
@Service
public class KycTransactions {
    private final Db db; private final TimeSource time; private final Json json; private final FusePolicy policy;
    private final DelegationService delegation; private final EvidenceValidator evidence;
    private final QuarantineMatcher matcher; private final QuarantineService quarantine; private final WorkflowJournal journal; private final WorkflowAgentRegistry agents;
    public KycTransactions(Db db,TimeSource time,Json json,FusePolicy policy,DelegationService delegation,
                           EvidenceValidator evidence,QuarantineMatcher matcher,QuarantineService quarantine,WorkflowJournal journal,WorkflowAgentRegistry agents) {
        this.db=db;this.time=time;this.json=json;this.policy=policy;this.delegation=delegation;
        this.evidence=evidence;this.matcher=matcher;this.quarantine=quarantine;this.journal=journal;this.agents=agents;
    }

    @Transactional
    public Optional<KycContract.Prepared> prepare(UUID jobId,UUID leaseToken) {
        var initial=db.required("SELECT * FROM workflow_job WHERE id=?",jobId);
        db.gate(); var workflow=db.lockWorkflow(id(initial,"workflow_id"));
        var job=db.required("SELECT * FROM workflow_job WHERE id=? FOR UPDATE",jobId); Instant now=time.now();
        if(!JobTransactions.valid(job,workflow,leaseToken,now) || !"KYC".equals(str(job,"phase")) ||
                !"KYC_PENDING".equals(str(workflow,"state")) || id(job,"run_id")!=null)return Optional.empty();
        UUID workflowId=id(workflow,"id"), actionId=id(job,"execution_action_id");
        var application=db.required("SELECT * FROM loan_application WHERE id=?",id(workflow,"application_id"));
        var stage=db.required("SELECT * FROM workflow_stage WHERE workflow_id=? AND stage='KYC'",workflowId);
        if(integer(stage,"run_count")>=policy.maxRunsPerStage()) {
            stop(workflowId,jobId,null,actionId,"ON_HOLD","ALLOW","MANUAL_REVIEW_REQUIRED",now); return Optional.empty();
        }
        if(matcher.workflowQuarantined(workflowId)) {
            stop(workflowId,jobId,null,actionId,"BLOCKED","DENY","QUARANTINED",now);return Optional.empty();
        }
        int charge=integer(stage,"used_points")==0?policy.kycRisk():0;
        if(integer(workflow,"used_risk")+integer(workflow,"reserved_risk")+charge>policy.automaticRiskLimit()) {
            stop(workflowId,jobId,null,actionId,"WAIT_APPROVAL","WAIT_APPROVAL","RISK_LIMIT_EXCEEDED",now);return Optional.empty();
        }
        var registry=db.required("SELECT * FROM application_registry WHERE business_reference=?",str(application,"business_reference"));
        UUID documentId=id(workflow,"recovery_document_id")!=null?id(workflow,"recovery_document_id"):id(registry,"document_id");
        int version=id(workflow,"recovery_document_id")!=null?integer(workflow,"recovery_document_version"):integer(registry,"document_version");
        if(db.one("SELECT id FROM quarantine WHERE scope='SOURCE_VERSION' AND status='ACTIVE' AND document_id=? AND document_version=?",documentId,version).isPresent()) {
            quarantine.recordSourceHold(workflowId,documentId,version);
            stop(workflowId,jobId,null,actionId,"BLOCKED","DENY","QUARANTINED",now);return Optional.empty();
        }
        var doc=db.required("SELECT * FROM source_document_version WHERE document_id=? AND version=?",documentId,version);
        if(!Json.sha256(str(doc,"content").getBytes(StandardCharsets.UTF_8)).equals(str(doc,"content_hash"))) {
            stop(workflowId,jobId,null,actionId,"ON_HOLD","ERROR","DEPENDENCY_UNAVAILABLE",now);return Optional.empty();
        }
        var evidenceRows=db.query("SELECT id,evidence_type,outcome FROM trusted_evidence WHERE customer_id=? AND status='ACTIVE' ORDER BY id LIMIT 10",str(application,"customer_id"));
        var facts=evidenceRows.stream().map(e->new KycContract.EvidenceFact(id(e,"id"),str(e,"evidence_type"),str(e,"outcome"))).toList();
        UUID runId=UUID.randomUUID();
        var input0=new KycContract.Input(actionId,workflowId,integer(workflow,"generation"),runId,str(application,"customer_id"),
                str(workflow,"policy_version"),null,facts,List.of(new KycContract.Document(documentId,version,str(doc,"content_hash"),str(doc,"content"))));
        byte[] inputBytes=json.bytes(input0.unhashed()); var input=input0.withHash(Json.sha256(inputBytes));
        var selectedAgent=agents.select(workflow,"KYC");
        if(selectedAgent.isEmpty()){unavailableAgent(workflowId,jobId,actionId,"KYC",now);return Optional.empty();}
        var agent=selectedAgent.get();
        db.update("UPDATE workflow_stage SET run_count=run_count+1 WHERE workflow_id=? AND stage='KYC'",workflowId);
        db.update("INSERT INTO agent_run(id,workflow_id,generation,role,agent_id,agent_version,run_index,status,action_id,input_bytes,input_snapshot_hash,created_at) VALUES(?,?,?,'KYC',?,?,?,'QUEUED',?,?,?,?)",
                runId,workflowId,integer(workflow,"generation"),str(agent,"agent_id"),integer(agent,"version"),integer(stage,"run_count")+1,actionId,inputBytes,input.inputSnapshotHash(),now);
        db.update("UPDATE workflow_job SET run_id=? WHERE id=?",runId,jobId);
        db.update("INSERT INTO run_source_use(run_id,document_id,document_version,content_hash) VALUES(?,?,?,?)",runId,documentId,version,str(doc,"content_hash"));
        for(var fact:facts)db.update("INSERT INTO run_evidence_use(run_id,evidence_id) VALUES(?,?)",runId,fact.evidenceId());
        if(matcher.isQuarantined(runId)) {
            stop(workflowId,jobId,runId,actionId,"BLOCKED","DENY","QUARANTINED",now);return Optional.empty();
        }
        try {
            var transport=delegation.issue(workflowId,"KYC",null,runId,null,null,actionId,null,null,json.bytes(input),now);
            var claims=delegation.validate(transport,"FUSE",workflowId,runId,"EVALUATE_KYC",now);
            delegation.consume(claims.grantId(),now);
            start(workflow,job,runId,"KYC",charge,now);
            journal.event(workflowId,runId,actionId,"fuse-worker","DELEGATION_ALLOWED",null,Json.ordered("grantId",claims.grantId()),now);
            return Optional.of(new KycContract.Prepared(jobId,leaseToken,input));
        } catch(PolicyException denial) {
            internalDenial(workflowId,jobId,runId,actionId,denial.reasonCode(),now);return Optional.empty();
        }
    }

    @Transactional
    public void apply(KycContract.Prepared prepared,KycContract.Response response) {
        var input=prepared.input(); db.gate(); var workflow=db.lockWorkflow(input.workflowId());
        var job=db.required("SELECT * FROM workflow_job WHERE id=? FOR UPDATE",prepared.jobId()); Instant now=time.now();
        var run=db.required("SELECT * FROM agent_run WHERE id=?",input.runId());
        if(!JobTransactions.valid(job,workflow,prepared.leaseToken(),now) || !input.runId().equals(id(job,"run_id")) ||
                !Set.of("RUNNING","PROPOSED").contains(str(run,"status")) || !"KYC_PENDING".equals(str(workflow,"state"))) {
            if(QuarantineObservation.enabled() && "FAILED".equals(str(job,"state")) && "QUARANTINED".equals(str(job,"last_error")) &&
                    "BLOCKED".equals(str(workflow,"state")) && "BLOCKED".equals(str(run,"status")) &&
                    input.generation()==integer(workflow,"generation") && input.generation()==integer(job,"generation") &&
                    input.generation()==integer(run,"generation") && input.workflowId().equals(id(run,"workflow_id")) &&
                    input.requestId().equals(id(job,"execution_action_id")) && inputSnapshotMatches(input,run) &&
                    input.runId().equals(id(job,"run_id")) && prepared.leaseToken().equals(id(job,"lease_token")) &&
                    instant(job,"lease_until")!=null && now.isBefore(instant(job,"lease_until")) && response.boundTo(input))
                QuarantineObservation.executionDenied(new QuarantineObservation.Execution(input.workflowId(),input.generation(),
                    prepared.jobId(),input.runId(),prepared.leaseToken()),QuarantineObservation.Attempt.KYC_RESULT_APPLY);
            journal.event(input.workflowId(),input.runId(),input.requestId(),"fuse-worker","LATE_RESULT_DISCARDED","WORKFLOW_CHANGED",Map.of(),now);return;
        }
        if(!response.boundTo(input) || !inputSnapshotMatches(input,run) ||
                !input.workflowId().equals(id(run,"workflow_id")) || input.generation()!=integer(run,"generation")) {
            stop(input.workflowId(),prepared.jobId(),input.runId(),input.requestId(),"ON_HOLD","ERROR","MODEL_OUTPUT_INVALID",now);return;
        }
        if(!recordedInputsMatch(input)) {
            stop(input.workflowId(),prepared.jobId(),input.runId(),input.requestId(),"ON_HOLD","ERROR","DEPENDENCY_UNAVAILABLE",now);return;
        }
        if(matcher.isQuarantined(input.runId()) || matcher.workflowQuarantined(input.workflowId())) {
            stop(input.workflowId(),prepared.jobId(),input.runId(),input.requestId(),"BLOCKED","DENY","QUARANTINED",now);return;
        }
        // Preserve the untrusted proposal before judging it. A refusal commits rather than throwing.
        var body=Json.ordered("status",response.proposal().status().name(),"evidenceIds",response.proposal().evidenceIds(),
                "explanation",response.proposal().explanation(),"modelMetadata",response.modelMetadata());
        UUID resultId=UUID.randomUUID();
        db.update("INSERT INTO agent_result(id,run_id,workflow_id,generation,status,body_json,result_hash,created_at) VALUES(?,?,?,?,'PROPOSED',?::jsonb,?,?)",
                resultId,input.runId(),input.workflowId(),input.generation(),json.write(body),json.hash(body),now);
        db.update("UPDATE agent_run SET status='PROPOSED' WHERE id=?",input.runId());
        journal.event(input.workflowId(),input.runId(),input.requestId(),"fuse-worker","KYC_PROPOSED",null,
                Json.ordered("resultId",resultId,"proposalStatus",response.proposal().status().name()),now);
        var decision=evidence.validate(response.proposal().status().name(),response.proposal().evidenceIds(),input.runId(),input.customerId(),now);
        if(decision.validated()) {
            db.update("UPDATE agent_result SET status='VALIDATED',evidence_bundle_hash=? WHERE id=?",decision.evidenceBundleHash(),resultId);
            db.update("UPDATE agent_run SET status='VALIDATED',completed_at=? WHERE id=?",now,input.runId());
            db.update("UPDATE workflow SET current_kyc_result_id=? WHERE id=?",resultId,input.workflowId());
            journal.state(input.workflowId(),"KYC_VALIDATED","ALLOW",null,now);
            journal.finishJob(prepared.jobId(),"SUCCEEDED",null,now); // Release active-job unique slot before inserting successor.
            journal.enqueue(input.workflowId(),input.generation(),"LOAN",now);
            journal.event(input.workflowId(),input.runId(),input.requestId(),"fuse-worker","EVIDENCE_VALIDATED",null,
                    Json.ordered("resultId",resultId,"evidenceBundleHash",decision.evidenceBundleHash()),now);
        } else if(decision.securityViolation()) {
            quarantine.automaticRun(input.runId(),decision.reasonCode(),"KYC proposal contradicted independent evidence");
        } else {
            db.update("UPDATE agent_run SET status='FAILED',completed_at=? WHERE id=?",now,input.runId());
            journal.finishJob(prepared.jobId(),"SUCCEEDED",decision.reasonCode(),now);
            journal.state(input.workflowId(),decision.state(),decision.decision(),decision.reasonCode(),now);
            journal.event(input.workflowId(),input.runId(),input.requestId(),"fuse-worker","KYC_REVIEW_COMPLETED",decision.reasonCode(),Json.ordered("state",decision.state()),now);
        }
    }

    /** A copied digest is insufficient: both the actual request and persisted bytes must match it. */
    private boolean inputSnapshotMatches(KycContract.Input input,Map<String,Object> run) {
        String hash=input.inputSnapshotHash();
        return hash!=null && hash.equals(str(run,"input_snapshot_hash")) &&
                run.get("input_bytes") instanceof byte[] bytes && hash.equals(Json.sha256(bytes)) &&
                hash.equals(json.hash(input.unhashed()));
    }

    private boolean recordedInputsMatch(KycContract.Input input) {
        var recorded=db.query("SELECT u.document_id,u.document_version,u.content_hash,d.content,d.content_hash AS current_hash FROM run_source_use u JOIN source_document_version d ON d.document_id=u.document_id AND d.version=u.document_version WHERE u.run_id=?",input.runId());
        if(recorded.size()!=input.documents().size())return false;
        for(var document:input.documents()) {
            boolean found=recorded.stream().anyMatch(row->document.documentId().equals(id(row,"document_id")) && document.documentVersion()==integer(row,"document_version") &&
                    document.contentHash().equals(str(row,"content_hash")) && document.contentHash().equals(str(row,"current_hash")) &&
                    document.text().equals(str(row,"content")) && document.contentHash().equals(Json.sha256(document.text().getBytes(StandardCharsets.UTF_8))));
            if(!found)return false;
        }
        var provided=db.query("SELECT evidence_id FROM run_evidence_use WHERE run_id=?",input.runId()).stream().map(row->id(row,"evidence_id")).collect(java.util.stream.Collectors.toSet());
        var actual=input.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).collect(java.util.stream.Collectors.toSet());
        return provided.equals(actual);
    }

    void unavailableAgent(UUID workflowId,UUID jobId,UUID actionId,String role,Instant now) {
        quarantine.recordAgentHold(workflowId,role);
        if(matcher.workflowQuarantined(workflowId))stop(workflowId,jobId,null,actionId,"BLOCKED","DENY","QUARANTINED",now);
        else stop(workflowId,jobId,null,actionId,"ON_HOLD","ERROR","DEPENDENCY_UNAVAILABLE",now);
    }

    void start(Map<String,Object> workflow,Map<String,Object> job,UUID runId,String stage,int charge,Instant now) {
        UUID workflowId=id(workflow,"id"),actionId=id(job,"execution_action_id");
        db.update("UPDATE agent_run SET status='RUNNING',started_at=? WHERE id=?",now,runId);
        if(charge>0) {
            db.update("UPDATE workflow_stage SET used_points=used_points+? WHERE workflow_id=? AND stage=?",charge,workflowId,stage);
            db.update("UPDATE workflow SET used_risk=used_risk+?,updated_at=? WHERE id=?",charge,now,workflowId);
            db.update("INSERT INTO risk_ledger(id,workflow_id,generation,stage,event_type,points,action_id,run_id,created_at) VALUES(?,?,?,?,'CHARGE',?,?,?,?)",
                    UUID.randomUUID(),workflowId,integer(workflow,"generation"),stage,charge,actionId,runId,now);
            journal.event(workflowId,runId,actionId,"fuse-worker","RISK_CHARGED",null,Json.ordered("stage",stage,"points",charge),now);
        }
    }
    void stop(UUID workflowId,UUID jobId,UUID runId,UUID actionId,String state,String decision,String reason,Instant now) {
        if(runId!=null)db.update("UPDATE agent_run SET status=?,completed_at=? WHERE id=?","BLOCKED".equals(state)?"BLOCKED":"FAILED",now,runId);
        journal.finishJob(jobId,"FAILED",reason,now);journal.state(workflowId,state,decision,reason,now);
        journal.event(workflowId,runId,actionId,"fuse-worker","ERROR".equals(decision)?"SYSTEM_ERROR":"POLICY_DENIED",reason,Json.ordered("state",state),now);
    }
    void internalDenial(UUID workflowId,UUID jobId,UUID runId,UUID actionId,String reason,Instant now) {
        if("RISK_LIMIT_EXCEEDED".equals(reason) || "APPROVAL_REQUIRED".equals(reason))stop(workflowId,jobId,runId,actionId,"WAIT_APPROVAL","WAIT_APPROVAL",reason,now);
        else if("DEPENDENCY_UNAVAILABLE".equals(reason))stop(workflowId,jobId,runId,actionId,"ON_HOLD","ERROR",reason,now);
        else if("GRANT_EXPIRED".equals(reason))stop(workflowId,jobId,runId,actionId,"ON_HOLD","DENY",reason,now);
        else if("QUARANTINED".equals(reason))stop(workflowId,jobId,runId,actionId,"BLOCKED","DENY",reason,now);
        else quarantine.automaticRun(runId,reason,"Internally issued delegation failed validation");
    }
}
