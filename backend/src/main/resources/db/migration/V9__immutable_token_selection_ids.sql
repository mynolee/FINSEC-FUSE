-- Add opaque selectors without assigning identities or changing historical rows.
-- Legacy NULL values remain unmapped; only new token rows require a selector.
ALTER TABLE demo_token ADD COLUMN selection_id uuid;
ALTER TABLE demo_token ADD CONSTRAINT demo_token_registry_selection_unique
  UNIQUE (registry_id, selection_id);

CREATE OR REPLACE FUNCTION protect_demo_token() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP IN ('DELETE','TRUNCATE') THEN
    RAISE EXCEPTION 'Authentication history cannot be removed' USING ERRCODE='55000';
  END IF;
  IF ROW(NEW.selection_id,NEW.fingerprint,NEW.registry_id,NEW.actor_id,NEW.role,NEW.initial_scope,
         NEW.issued_at,NEW.expires_at,NEW.security_policy,NEW.issuance_ttl_seconds)
     IS DISTINCT FROM ROW(OLD.selection_id,OLD.fingerprint,OLD.registry_id,OLD.actor_id,OLD.role,OLD.initial_scope,
         OLD.issued_at,OLD.expires_at,OLD.security_policy,OLD.issuance_ttl_seconds) THEN
    RAISE EXCEPTION 'Authentication issuance is immutable' USING ERRCODE='55000';
  END IF;
  IF OLD.status='REVOKED' AND (NEW.status IS DISTINCT FROM OLD.status OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
    RAISE EXCEPTION 'Authentication revocation is permanent' USING ERRCODE='55000';
  END IF;
  IF NEW.revision <> OLD.revision + 1 THEN
    RAISE EXCEPTION 'Authentication revision must advance once per change' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;
CREATE FUNCTION require_demo_token_selection() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.selection_id IS NULL THEN
    RAISE EXCEPTION 'New authentication records require an opaque selector' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER demo_token_selection_required BEFORE INSERT ON demo_token
FOR EACH ROW EXECUTE FUNCTION require_demo_token_selection();
REVOKE ALL ON FUNCTION require_demo_token_selection() FROM PUBLIC;

-- Preserve the existing read-only runtime contract. Table SELECT still covers
-- this new column; column revocation is not a selector-confidentiality boundary.
REVOKE ALL (selection_id) ON demo_token FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='fuse_runtime') THEN
    REVOKE ALL (selection_id) ON demo_token FROM fuse_runtime;
  END IF;
END;
$$;
