package com.finsec.fuse.persistence;

import com.finsec.fuse.common.Json;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Component;

@Component
public final class AuditLog {
    private final Db db; private final Json json; private final TimeSource time;
    public AuditLog(Db db,Json json,TimeSource time) { this.db=db;this.json=json;this.time=time; }
    public UUID write(String eventType,String actorId,UUID workflowId,UUID runId,UUID actionId,String reasonCode,Object details) {
        return append(actionId,workflowId,runId,null,actorId,eventType,reasonCode,details);
    }
    public UUID append(UUID actionId,UUID workflowId,UUID runId,UUID quarantineId,String actorId,String eventType,String reasonCode,Object details) {
        UUID id=UUID.randomUUID();
        db.update("INSERT INTO audit_event(id,action_id,workflow_id,run_id,quarantine_id,actor_id,event_type,reason_code,details_json,created_at) VALUES(?,?,?,?,?,?,?,?,?::jsonb,?)",
            id,actionId,workflowId,runId,quarantineId,actorId,eventType,reasonCode,json.write(details==null?Map.of():details),time.now());
        return id;
    }
}
