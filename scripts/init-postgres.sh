#!/usr/bin/env bash
set -euo pipefail
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=runtime_password="$FUSE_DB_PASSWORD" --set=experiment_password="$FUSE_EXPERIMENT_DB_PASSWORD" <<'SQL'
CREATE ROLE fuse_runtime LOGIN PASSWORD :'runtime_password';
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO fuse_runtime;
GRANT CONNECT ON DATABASE fuse TO fuse_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE fuse_owner IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO fuse_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE fuse_owner IN SCHEMA public GRANT USAGE,SELECT ON SEQUENCES TO fuse_runtime;
CREATE ROLE fuse_experiment_owner LOGIN PASSWORD :'experiment_password';
CREATE DATABASE fuse_experiments OWNER fuse_experiment_owner;
REVOKE CONNECT ON DATABASE fuse FROM PUBLIC;
GRANT CONNECT ON DATABASE fuse TO fuse_owner,fuse_runtime;
REVOKE CONNECT ON DATABASE fuse_experiments FROM PUBLIC;
GRANT CONNECT ON DATABASE fuse_experiments TO fuse_experiment_owner;
SQL
