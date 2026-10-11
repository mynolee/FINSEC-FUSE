package com.finsec.fuse.workflow;

import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.persistence.Db;
import org.springframework.stereotype.Component;
import java.util.*;
import static com.finsec.fuse.workflow.WorkflowValues.*;

@Component
public class WorkflowAgentRegistry {
    private final Db db;private final FusePolicy policy;
    public WorkflowAgentRegistry(Db db,FusePolicy policy){this.db=db;this.policy=policy;}
    public Optional<Map<String,Object>> select(Map<String,Object> workflow,String role) {
        String recovered=str(workflow,"recovery_agent_id");
        Integer version=workflow.get("recovery_agent_version")==null?null:integer(workflow,"recovery_agent_version");
        if(recovered!=null && version!=null) {
            var exact=db.one("SELECT * FROM agent_registry WHERE agent_id=? AND version=?",recovered,version);
            if(exact.isPresent() && role.equals(str(exact.get(),"role")))return usable(exact.get())?exact:Optional.empty();
        }
        return db.query("SELECT * FROM agent_registry WHERE role=? AND status='ACTIVE' ORDER BY version DESC,agent_id",role)
                .stream().filter(this::usable).findFirst();
    }
    private boolean usable(Map<String,Object> agent) {
        return "ACTIVE".equals(str(agent,"status")) && policy.safeAgentVersions().contains(str(agent,"agent_id")+":"+integer(agent,"version")) &&
                db.one("SELECT id FROM quarantine WHERE scope='AGENT_VERSION' AND status='ACTIVE' AND agent_id=? AND agent_version=?",str(agent,"agent_id"),integer(agent,"version")).isEmpty();
    }
}
