package com.finsec.fuse.workflow;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.persistence.Db;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.util.*;

/** Small SQL adapter; callers own the gate/workflow transaction. */
@Component
public class WorkflowJournal {
    private final Db db; private final Json json; private final com.finsec.fuse.config.SecurityPolicy security;
    public WorkflowJournal(Db db, Json json, com.finsec.fuse.config.SecurityPolicy security) {this.db=db;this.json=json;this.security=security;}
    public void event(UUID workflowId, UUID runId, UUID actionId, String actor, String event, String reason, Object detail, Instant now) {
        db.update("INSERT INTO audit_event(id,action_id,workflow_id,run_id,actor_id,event_type,reason_code,details_json,created_at) VALUES(?,?,?,?,?,?,?,?::jsonb,?)",
                UUID.randomUUID(),actionId,workflowId,runId,actor,event,reason,json.write(detail),now);
    }
    public UUID enqueue(UUID workflowId, int generation, String phase, Instant now) {
        return enqueue(workflowId,generation,phase,null,now);
    }
    public UUID enqueue(UUID workflowId, int generation, String phase, UUID approvalId, Instant now) {
        // Serialize admission with all other gate-first workflow mutations.
        db.gate();
        long queued=((Number)db.required("SELECT count(*) AS n FROM workflow_job WHERE state='PENDING'").get("n")).longValue();
        if(queued>=security.queuedJobsMax())throw new com.finsec.fuse.common.ApiException(429,"RATE_LIMITED","Job queue capacity reached");
        UUID jobId=UUID.randomUUID();
        db.update("INSERT INTO workflow_job(id,workflow_id,generation,phase,state,execution_action_id,approval_id,created_at) VALUES(?,?,?,?,'PENDING',?,?,?)",
                jobId,workflowId,generation,phase,UUID.randomUUID(),approvalId,now);
        return jobId;
    }
    public void state(UUID workflowId, String state, String decision, String reason, Instant now) {
        String previous=db.required("SELECT state FROM workflow WHERE id=?",workflowId).get("state").toString();
        db.update("UPDATE workflow SET state=?,last_decision=?,last_reason_code=?,reason_codes=?::jsonb,updated_at=? WHERE id=?",
                state,decision,reason,json.write(reason==null?List.of():List.of(reason)),now,workflowId);
        if(!previous.equals(state))event(workflowId,null,null,"fuse-worker","WORKFLOW_STATE_CHANGED",reason,Json.ordered("from",previous,"to",state),now);
    }
    public void finishJob(UUID jobId, String state, String reason, Instant now) {
        db.update("UPDATE workflow_job SET state=?,last_error=?,completed_at=? WHERE id=?",state,reason,now,jobId);
    }
}
