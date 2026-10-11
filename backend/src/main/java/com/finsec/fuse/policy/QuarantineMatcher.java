package com.finsec.fuse.policy;

import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.observation.SecurityCheckObservation;
import java.util.UUID;
import org.springframework.stereotype.Component;

/** Checks every actual ancestor and all delivered sources, not a model's chosen citations. */
@Component
public class QuarantineMatcher {
    private final Db db;
    public QuarantineMatcher(Db db) { this.db=db; }
    public boolean isQuarantined(UUID runId) {
        try (var ignored=SecurityCheckObservation.enter(SecurityCheckObservation.Check.QUARANTINE_MATCH)) {
            return matchRun(runId);
        }
    }
    private boolean matchRun(UUID runId) {
        return !db.query("""
            WITH RECURSIVE ancestors(id) AS (
              SELECT id FROM agent_run WHERE id=?
              UNION SELECT d.parent_run_id FROM run_dependency d JOIN ancestors a ON d.child_run_id=a.id
            )
            SELECT q.id FROM ancestors x JOIN agent_run r ON r.id=x.id
            JOIN quarantine q ON q.status='ACTIVE' AND (
              (q.scope='RUN' AND q.run_id=r.id) OR
              (q.scope='WORKFLOW' AND q.workflow_id=r.workflow_id) OR
              (q.scope='RESULT' AND EXISTS(SELECT 1 FROM agent_result z WHERE z.run_id=r.id AND z.id=q.result_id)) OR
              (q.scope='SOURCE_VERSION' AND EXISTS(SELECT 1 FROM run_source_use s WHERE s.run_id=r.id AND s.document_id=q.document_id AND s.document_version=q.document_version)) OR
              (q.scope='AGENT_VERSION' AND q.agent_id=r.agent_id AND q.agent_version=r.agent_version)
            ) LIMIT 1
            """,runId).isEmpty();
    }
    public boolean workflowQuarantined(UUID workflowId) {
        try (var ignored=SecurityCheckObservation.enter(SecurityCheckObservation.Check.QUARANTINE_MATCH)) {
            return matchWorkflow(workflowId);
        }
    }
    private boolean matchWorkflow(UUID workflowId) {
        if(!db.query("SELECT h.quarantine_id FROM quarantine_workflow_hold h JOIN quarantine q ON q.id=h.quarantine_id JOIN workflow w ON w.id=h.workflow_id WHERE h.workflow_id=? AND h.generation=w.generation AND q.status='ACTIVE' LIMIT 1",workflowId).isEmpty())return true;
        if(!db.query("SELECT id FROM quarantine WHERE scope='WORKFLOW' AND workflow_id=? AND status='ACTIVE' LIMIT 1",workflowId).isEmpty()) return true;
        for(var run:db.query("""
            SELECT r.id FROM agent_run r JOIN workflow w ON w.id=r.workflow_id
            WHERE w.id=? AND (r.generation=w.generation OR r.id IN (
              SELECT run_id FROM agent_result WHERE id IN(w.current_kyc_result_id,w.current_loan_result_id)))
            """,workflowId)) if(isQuarantined(PolicyRows.uuid(run,"id")))return true;
        return false;
    }
}
