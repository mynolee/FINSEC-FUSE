-- Private evidence retention. Export APIs expose references and digests, never these byte bodies.
CREATE TABLE experiment_arm_binding (
 id uuid PRIMARY KEY,
 case_result_id uuid NOT NULL REFERENCES experiment_case_result(id),
 request_id uuid NOT NULL, workflow_id uuid NOT NULL, run_id uuid NOT NULL,
 generation integer NOT NULL CHECK(generation>0),
 input_bytes bytea NOT NULL, request_bytes bytea NOT NULL, response_bytes bytea NOT NULL,
 input_snapshot_hash varchar(64) NOT NULL CHECK(input_snapshot_hash ~ '^[0-9a-f]{64}$'),
 request_byte_hash varchar(64) NOT NULL CHECK(request_byte_hash ~ '^[0-9a-f]{64}$'),
 response_byte_hash varchar(64) NOT NULL CHECK(response_byte_hash ~ '^[0-9a-f]{64}$'),
 UNIQUE(case_result_id,run_id)
);
