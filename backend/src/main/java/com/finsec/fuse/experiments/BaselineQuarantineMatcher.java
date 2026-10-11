package com.finsec.fuse.experiments;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.policy.QuarantineMatcher;
import java.util.UUID;
/** No lineage quarantine in the isolated baseline. Never registered in the serving context. */
final class BaselineQuarantineMatcher extends QuarantineMatcher {
    BaselineQuarantineMatcher(Db db){super(db);}
    @Override public boolean isQuarantined(UUID run){return false;}
    @Override public boolean workflowQuarantined(UUID workflow){return false;}
}
