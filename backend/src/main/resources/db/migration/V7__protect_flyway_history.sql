-- Restrict the migration history in Flyway's CURRENT schema, including owned test schemas.
-- Do not change V1–V6 checksums, roles, default privileges or historical migration rows.
REVOKE ALL ON flyway_schema_history FROM PUBLIC;
-- Table-level REVOKE does not remove separately granted column privileges.
REVOKE ALL (installed_rank, version, description, type, script, checksum, installed_by, installed_on, execution_time, success)
  ON flyway_schema_history FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='fuse_runtime') THEN
    REVOKE ALL ON flyway_schema_history FROM fuse_runtime;
    REVOKE ALL (installed_rank, version, description, type, script, checksum, installed_by, installed_on, execution_time, success)
      ON flyway_schema_history FROM fuse_runtime;
    GRANT SELECT ON flyway_schema_history TO fuse_runtime;
  END IF;
END;
$$;
