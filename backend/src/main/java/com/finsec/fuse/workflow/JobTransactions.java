package com.finsec.fuse.workflow;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.persistence.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.*;
import static com.finsec.fuse.workflow.WorkflowValues.*;

@Service
public class JobTransactions {
    private final Db db; private final TimeSource time; private final FusePolicy policy; private final WorkflowJournal journal;
    public JobTransactions(Db db, TimeSource time, FusePolicy policy, WorkflowJournal journal) {
        this.db=db;this.time=time;this.policy=policy;this.journal=journal;
    }
    public record Lease(UUID jobId, UUID workflowId, UUID token, String phase, int generation) {}

    /** SKIP LOCKED is used exclusively for job distribution, never a policy check. */
    @Transactional
    public Optional<Lease> claim() {
        // Claim audit rows reference workflow; gate-first avoids a job→FK-workflow lock inversion.
        db.gate();
        var candidate=db.one("SELECT * FROM workflow_job WHERE state='PENDING' ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED");
        if(candidate.isEmpty())return Optional.empty();
        var job=candidate.get(); Instant now=time.now(); UUID token=UUID.randomUUID(), jobId=id(job,"id");
        db.update("UPDATE workflow_job SET state='RUNNING',lease_token=?,lease_until=?,started_at=? WHERE id=?",
                token,now.plusSeconds(policy.leaseSeconds()),now,jobId);
        journal.event(id(job,"workflow_id"),null,id(job,"execution_action_id"),"fuse-worker","JOB_CLAIMED",null,
                Json.ordered("jobId",jobId,"phase",str(job,"phase")),now);
        return Optional.of(new Lease(jobId,id(job,"workflow_id"),token,str(job,"phase"),integer(job,"generation")));
    }

    /** Full completion predicate; an old token can never write a new generation. */
    static boolean valid(Map<String,Object> job, Map<String,Object> workflow, UUID token, Instant now) {
        return "RUNNING".equals(str(job,"state")) && token.equals(id(job,"lease_token")) &&
                instant(job,"lease_until") != null && now.isBefore(instant(job,"lease_until")) &&
                integer(job,"generation")==integer(workflow,"generation");
    }

    @Transactional
    public void fail(UUID jobId, UUID token, String reason) {
        var job0=db.one("SELECT * FROM workflow_job WHERE id=?",jobId); if(job0.isEmpty())return;
        db.gate(); var workflow=db.lockWorkflow(id(job0.get(),"workflow_id"));
        var job=db.required("SELECT * FROM workflow_job WHERE id=? FOR UPDATE",jobId); Instant now=time.now();
        if(!valid(job,workflow,token,now)) {
            journal.event(id(workflow,"id"),id(job,"run_id"),id(job,"execution_action_id"),"fuse-worker","LATE_RESULT_DISCARDED",reason,Map.of(),now);
            return;
        }
        if("PAID".equals(str(workflow,"state")) || "BLOCKED".equals(str(workflow,"state")))return;
        journal.finishJob(jobId,"FAILED",reason,now);
        if(id(job,"run_id")!=null)db.update("UPDATE agent_run SET status='FAILED',completed_at=? WHERE id=? AND status IN ('RUNNING','PROPOSED','QUEUED')",now,id(job,"run_id"));
        journal.state(id(workflow,"id"),"ON_HOLD","ERROR",reason,now);
        journal.event(id(workflow,"id"),id(job,"run_id"),id(job,"execution_action_id"),"fuse-worker","SYSTEM_ERROR",reason,Map.of(),now);
    }

    public List<Map<String,Object>> expired() {
        Instant now=time.now();
        return db.query("SELECT id,phase FROM workflow_job WHERE state='RUNNING' AND lease_until<=? ORDER BY workflow_id,id",now);
    }

    @Transactional
    public void reapNonPayment(UUID jobId) {
        var job0=db.one("SELECT * FROM workflow_job WHERE id=?",jobId); if(job0.isEmpty())return;
        db.gate(); var workflow=db.lockWorkflow(id(job0.get(),"workflow_id"));
        var job=db.required("SELECT * FROM workflow_job WHERE id=? FOR UPDATE",jobId); Instant now=time.now();
        if(!"RUNNING".equals(str(job,"state")) || now.isBefore(instant(job,"lease_until")) || "PAY".equals(str(job,"phase")))return;
        journal.finishJob(jobId,"FAILED","DEPENDENCY_UNAVAILABLE",now);
        if(id(job,"run_id")!=null)db.update("UPDATE agent_run SET status='FAILED',completed_at=? WHERE id=? AND status IN ('RUNNING','PROPOSED','QUEUED')",now,id(job,"run_id"));
        if(integer(job,"generation")==integer(workflow,"generation") && !Set.of("PAID","BLOCKED").contains(str(workflow,"state")))
            journal.state(id(workflow,"id"),"ON_HOLD","ERROR","DEPENDENCY_UNAVAILABLE",now);
        journal.event(id(workflow,"id"),id(job,"run_id"),id(job,"execution_action_id"),"fuse-worker","SYSTEM_ERROR","DEPENDENCY_UNAVAILABLE",Json.ordered("leaseExpired",true),now);
    }
}
