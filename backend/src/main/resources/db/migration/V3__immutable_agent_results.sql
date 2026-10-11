-- Results preserve the exact reviewed candidate. Only lifecycle state and first validation may change.
CREATE FUNCTION protect_agent_result_integrity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'agent_result candidates and their history cannot be deleted' USING ERRCODE='55000';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.run_id IS DISTINCT FROM OLD.run_id
     OR NEW.workflow_id IS DISTINCT FROM OLD.workflow_id
     OR NEW.generation IS DISTINCT FROM OLD.generation
     OR NEW.body_json IS DISTINCT FROM OLD.body_json
     OR NEW.result_hash IS DISTINCT FROM OLD.result_hash
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'agent_result identity, candidate body and result hash are immutable' USING ERRCODE='55000';
  END IF;
  IF NEW.evidence_bundle_hash IS DISTINCT FROM OLD.evidence_bundle_hash
     AND NOT (OLD.status='PROPOSED' AND OLD.evidence_bundle_hash IS NULL
              AND NEW.status='VALIDATED' AND NEW.evidence_bundle_hash IS NOT NULL) THEN
    RAISE EXCEPTION 'agent_result evidence binding can only be set at first validation' USING ERRCODE='55000';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status
     AND NOT ((OLD.status='PROPOSED' AND NEW.status IN ('VALIDATED','INVALIDATED'))
              OR (OLD.status='VALIDATED' AND NEW.status='INVALIDATED')) THEN
    RAISE EXCEPTION 'agent_result lifecycle cannot move backwards or resurrect invalidated data' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER agent_result_integrity BEFORE UPDATE OR DELETE ON agent_result
FOR EACH ROW EXECUTE FUNCTION protect_agent_result_integrity();
