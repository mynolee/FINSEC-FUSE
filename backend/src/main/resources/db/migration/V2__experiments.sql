CREATE TABLE experiment (
 id uuid PRIMARY KEY, actor_id varchar(64) NOT NULL, fixture_set_id text NOT NULL,
 mode text NOT NULL CHECK(mode='PAIRED'), model_mode text NOT NULL CHECK(model_mode IN ('REPLAY','LIVE')),
 repeat_count integer NOT NULL CHECK(repeat_count BETWEEN 1 AND 10), case_ids jsonb NOT NULL,
 status text NOT NULL CHECK(status IN ('PENDING','RUNNING','COMPLETED','FAILED','INTERRUPTED')),
 total_runs integer NOT NULL, completed_runs integer NOT NULL DEFAULT 0, config_json jsonb NOT NULL,
 metrics_json jsonb, error_message text, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz);
CREATE TABLE experiment_case_result (
 id uuid PRIMARY KEY, experiment_id uuid NOT NULL REFERENCES experiment(id), case_id text NOT NULL,
 environment text NOT NULL CHECK(environment IN ('BASELINE','FUSE')), repeat_index integer NOT NULL,
 status text NOT NULL, fixture_hash varchar(64) NOT NULL, model_version text NOT NULL, policy_version text NOT NULL,
 mock_reviewer_version text NOT NULL, output_json jsonb NOT NULL, excluded_reason text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(experiment_id,case_id,environment,repeat_index));
