-- Preserve immutable records against statement-level removal as well as row mutations.
CREATE FUNCTION reject_immutable_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is immutable: TRUNCATE is forbidden', TG_TABLE_NAME USING ERRCODE='55000';
END;
$$;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_event
FOR EACH STATEMENT EXECUTE FUNCTION reject_immutable_truncate();
CREATE TRIGGER risk_no_truncate BEFORE TRUNCATE ON risk_ledger
FOR EACH STATEMENT EXECUTE FUNCTION reject_immutable_truncate();
CREATE TRIGGER source_no_truncate BEFORE TRUNCATE ON source_document_version
FOR EACH STATEMENT EXECUTE FUNCTION reject_immutable_truncate();
CREATE TRIGGER application_no_truncate BEFORE TRUNCATE ON loan_application
FOR EACH STATEMENT EXECUTE FUNCTION reject_immutable_truncate();
CREATE TRIGGER payment_no_truncate BEFORE TRUNCATE ON mock_payment
FOR EACH STATEMENT EXECUTE FUNCTION reject_immutable_truncate();
CREATE TRIGGER agent_result_no_truncate BEFORE TRUNCATE ON agent_result
FOR EACH STATEMENT EXECUTE FUNCTION reject_immutable_truncate();
CREATE TRIGGER quarantine_hold_no_truncate BEFORE TRUNCATE ON quarantine_workflow_hold
FOR EACH STATEMENT EXECUTE FUNCTION reject_immutable_truncate();
REVOKE ALL ON FUNCTION reject_immutable_truncate() FROM PUBLIC;

-- Table-level REVOKE does not remove previously granted column privileges.
-- Keep the existing read-only runtime contract; do not create or alter roles.
REVOKE ALL (id, registry_id, format_version, initialized_at)
  ON demo_auth_registry FROM PUBLIC;
REVOKE ALL (fingerprint, registry_id, actor_id, role, initial_scope, current_scope,
  issued_at, expires_at, security_policy, issuance_ttl_seconds, status, revoked_at, revision)
  ON demo_token FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='fuse_runtime') THEN
    REVOKE ALL (id, registry_id, format_version, initialized_at)
      ON demo_auth_registry FROM fuse_runtime;
    REVOKE ALL (fingerprint, registry_id, actor_id, role, initial_scope, current_scope,
      issued_at, expires_at, security_policy, issuance_ttl_seconds, status, revoked_at, revision)
      ON demo_token FROM fuse_runtime;
    GRANT SELECT ON demo_auth_registry,demo_token TO fuse_runtime;
  END IF;
END;
$$;
