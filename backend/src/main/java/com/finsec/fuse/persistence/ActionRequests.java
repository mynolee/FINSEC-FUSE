package com.finsec.fuse.persistence;

import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.common.Json;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Component;

/** Invoke only while the execution gate is held. The original receipt survives later expiry. */
@Component
public final class ActionRequests {
    private final Db db; private final Json json; private final TimeSource time;
    public ActionRequests(Db db,Json json,TimeSource time) { this.db=db;this.json=json;this.time=time; }
    public String fingerprint(String actorId,String actionType,UUID workflowId,Object canonicalBody) {
        return json.hash(Json.ordered("actorId",actorId,"actionType",actionType,"workflowId",workflowId,"body",canonicalBody));
    }
    public Optional<Map<String,Object>> replay(UUID actionId,String actorId,String actionType,UUID workflowId,Object canonicalBody) {
        var prior=db.one("SELECT * FROM action_request WHERE action_id=?",actionId);
        if(prior.isEmpty())return Optional.empty();
        var row=prior.get();
        if(!java.util.Objects.equals(actorId,row.get("actor_id")))
            throw new ApiException(403,"FORBIDDEN","Action receipt is outside the current actor's access");
        String expected=fingerprint(actorId,actionType,workflowId,canonicalBody);
        if(!expected.equals(row.get("payload_hash")))throw new ApiException(409,"REPLAY_CONFLICT","Idempotency key was already used for a different request");
        if(row.get("result_json")==null)throw new ApiException(409,"REQUEST_IN_PROGRESS","Request is still processing");
        var result=new LinkedHashMap<String,Object>(json.map(row.get("result_json").toString()));
        result.put("replayed",true); return Optional.of(result);
    }
    public void save(UUID actionId,String actorId,String actionType,UUID workflowId,Object canonicalBody,Map<String,Object> response) {
        String hash=fingerprint(actorId,actionType,workflowId,canonicalBody);
        db.update("INSERT INTO action_request(action_id,actor_id,action_type,workflow_id,payload_hash,status,decision,result_json,created_at,completed_at) VALUES(?,?,?,?,?,'SUCCEEDED',?,?::jsonb,?,?)",
            actionId,actorId,actionType,workflowId,hash,response.get("decision"),json.write(response),time.now(),time.now());
    }
}
