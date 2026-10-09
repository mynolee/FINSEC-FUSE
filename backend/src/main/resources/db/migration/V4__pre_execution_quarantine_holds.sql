-- A blocked attempt is not an executed agent run or a consumed source edge.
-- Persist its incident linkage separately so reviewed remediation can clear the exact held generation.
CREATE TABLE quarantine_workflow_hold (
 quarantine_id uuid NOT NULL REFERENCES quarantine(id),
 workflow_id uuid NOT NULL REFERENCES workflow(id),
 generation integer NOT NULL CHECK(generation>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(quarantine_id,workflow_id,generation)
);
CREATE INDEX quarantine_hold_workflow_idx ON quarantine_workflow_hold(workflow_id,generation);
CREATE TRIGGER quarantine_hold_append_only BEFORE UPDATE OR DELETE ON quarantine_workflow_hold
FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
