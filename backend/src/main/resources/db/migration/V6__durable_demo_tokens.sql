-- Structures only. Initialization and credential issuance are explicit offline operations.
CREATE FUNCTION demo_scope_valid(scope_values text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT scope_values IS NOT NULL
    AND cardinality(scope_values) <= 256
    AND (cardinality(scope_values)=0 OR array_ndims(scope_values)=1)
    AND array_position(scope_values,NULL) IS NULL
    AND NOT EXISTS (SELECT 1 FROM unnest(scope_values) value
                    WHERE value !~ '^customer-[A-Za-z0-9][A-Za-z0-9_-]{0,118}$')
    AND scope_values = COALESCE((SELECT array_agg(value ORDER BY value COLLATE "C")
                                FROM (SELECT DISTINCT unnest(scope_values) AS value) canonical),ARRAY[]::text[])
$$;

CREATE TABLE demo_auth_registry (
  id smallint PRIMARY KEY CHECK (id=1),
  registry_id uuid NOT NULL UNIQUE,
  format_version integer NOT NULL CHECK (format_version=1),
  initialized_at timestamptz NOT NULL
);
CREATE TABLE demo_token (
  fingerprint bytea PRIMARY KEY CHECK (octet_length(fingerprint)=32),
  registry_id uuid NOT NULL REFERENCES demo_auth_registry(registry_id),
  actor_id text NOT NULL CHECK (actor_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  role text NOT NULL CHECK (role IN ('CUSTOMER','LOAN_REVIEWER','SECURITY_OPERATOR','DEVELOPER','KYC_SERVICE','FUSE_WORKER')),
  initial_scope text[] NOT NULL CHECK (demo_scope_valid(initial_scope)),
  current_scope text[] NOT NULL CHECK (demo_scope_valid(current_scope)),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  security_policy text NOT NULL CHECK (security_policy='FUSE-SECURITY-1'),
  issuance_ttl_seconds integer NOT NULL CHECK (issuance_ttl_seconds=7200),
  status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  revoked_at timestamptz,
  revision bigint NOT NULL DEFAULT 0 CHECK (revision>=0),
  CHECK (expires_at > issued_at AND expires_at=issued_at + interval '7200 seconds'),
  CHECK ((status='ACTIVE' AND revoked_at IS NULL) OR (status='REVOKED' AND revoked_at IS NOT NULL))
);
CREATE INDEX demo_token_actor ON demo_token(actor_id,fingerprint);

CREATE FUNCTION protect_demo_registry() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Authentication registry identity and history are immutable' USING ERRCODE='55000';
END;
$$;
CREATE TRIGGER demo_registry_immutable BEFORE UPDATE OR DELETE ON demo_auth_registry
FOR EACH ROW EXECUTE FUNCTION protect_demo_registry();
CREATE TRIGGER demo_registry_no_truncate BEFORE TRUNCATE ON demo_auth_registry
FOR EACH STATEMENT EXECUTE FUNCTION protect_demo_registry();

CREATE FUNCTION protect_demo_token() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP IN ('DELETE','TRUNCATE') THEN
    RAISE EXCEPTION 'Authentication history cannot be removed' USING ERRCODE='55000';
  END IF;
  IF ROW(NEW.fingerprint,NEW.registry_id,NEW.actor_id,NEW.role,NEW.initial_scope,
         NEW.issued_at,NEW.expires_at,NEW.security_policy,NEW.issuance_ttl_seconds)
     IS DISTINCT FROM ROW(OLD.fingerprint,OLD.registry_id,OLD.actor_id,OLD.role,OLD.initial_scope,
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
CREATE TRIGGER demo_token_immutable BEFORE UPDATE OR DELETE ON demo_token
FOR EACH ROW EXECUTE FUNCTION protect_demo_token();
CREATE TRIGGER demo_token_no_truncate BEFORE TRUNCATE ON demo_token
FOR EACH STATEMENT EXECUTE FUNCTION protect_demo_token();

REVOKE ALL ON demo_auth_registry,demo_token FROM PUBLIC;
REVOKE ALL ON FUNCTION demo_scope_valid(text[]),protect_demo_registry(),protect_demo_token() FROM PUBLIC;
-- Tests can migrate in an isolated cluster without this deployment role.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='fuse_runtime') THEN
    REVOKE ALL ON demo_auth_registry,demo_token FROM fuse_runtime;
    GRANT SELECT ON demo_auth_registry,demo_token TO fuse_runtime;
  END IF;
END;
$$;
