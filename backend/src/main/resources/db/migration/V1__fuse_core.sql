-- PostgreSQL 16. No external bank, money transfer, or real identity data is used.
CREATE TABLE execution_gate (id smallint PRIMARY KEY CHECK (id=1), epoch bigint NOT NULL DEFAULT 0 CHECK(epoch>=0));
INSERT INTO execution_gate(id) VALUES(1);
CREATE TABLE agent_registry (
 agent_id text NOT NULL, version integer NOT NULL CHECK(version>0), role text NOT NULL,
 auth_subject text NOT NULL, status text NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED')),
 PRIMARY KEY(agent_id,version));
CREATE TABLE mock_account (id uuid PRIMARY KEY, customer_id text NOT NULL, status text NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','CLOSED')));
CREATE TABLE mock_profile (customer_id text PRIMARY KEY, monthly_income_krw bigint NOT NULL, max_loan_amount_krw bigint NOT NULL, profile_hash text NOT NULL, policy_version text NOT NULL DEFAULT 'LOAN-MOCK-1');
CREATE TABLE application_registry (
 business_reference varchar(80) PRIMARY KEY, customer_id varchar(64) NOT NULL,
 amount_krw bigint NOT NULL CHECK(amount_krw BETWEEN 1 AND 50000000), payout_account_id uuid NOT NULL REFERENCES mock_account(id),
 document_id uuid NOT NULL, document_version integer NOT NULL CHECK(document_version>0));
CREATE TABLE source_document_version (
 document_id uuid NOT NULL, version integer NOT NULL CHECK(version>0), content text NOT NULL, content_hash varchar(64) NOT NULL,
 reviewed_safe boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(document_id,version));
CREATE TABLE trusted_evidence (
 id uuid PRIMARY KEY, customer_id varchar(64) NOT NULL, evidence_type text NOT NULL CHECK(evidence_type IN ('ID_DOC','FACE_MATCH')),
 issuer_id text NOT NULL, version integer NOT NULL CHECK(version>0), outcome text NOT NULL CHECK(outcome IN ('PASS','FAIL')),
 original_json text NOT NULL, original_hash varchar(64) NOT NULL, status text NOT NULL CHECK(status IN ('ACTIVE','REVOKED')),
 issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, revoked_at timestamptz,
 CHECK(expires_at>issued_at), CHECK((status='ACTIVE' AND revoked_at IS NULL) OR status='REVOKED'));
CREATE INDEX evidence_customer_idx ON trusted_evidence(customer_id);
CREATE TABLE loan_application (
 id uuid PRIMARY KEY, business_reference varchar(80) NOT NULL UNIQUE REFERENCES application_registry(business_reference),
 customer_id varchar(64) NOT NULL, amount_krw bigint NOT NULL CHECK(amount_krw BETWEEN 1 AND 50000000),
 payout_account_id uuid NOT NULL REFERENCES mock_account(id), created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE workflow (
 id uuid PRIMARY KEY, application_id uuid NOT NULL UNIQUE REFERENCES loan_application(id), root_authorization_id uuid NOT NULL UNIQUE,
 risk_ledger_id uuid NOT NULL UNIQUE, principal_id varchar(64) NOT NULL, origin_intent text NOT NULL DEFAULT 'LOAN_APPLICATION',
 generation integer NOT NULL DEFAULT 1 CHECK(generation>0), policy_version text NOT NULL,
 state text NOT NULL CHECK(state IN ('KYC_PENDING','KYC_VALIDATED','REVIEW_READY','WAIT_APPROVAL','APPROVED','PAYMENT_RESERVED','PAID','REJECTED','BLOCKED','ON_HOLD')),
 current_kyc_result_id uuid, current_loan_result_id uuid,
 used_risk integer NOT NULL DEFAULT 0 CHECK(used_risk>=0), reserved_risk integer NOT NULL DEFAULT 0 CHECK(reserved_risk>=0),
 last_decision text NOT NULL DEFAULT 'ALLOW' CHECK(last_decision IN ('ALLOW','WAIT_APPROVAL','DENY','ERROR')),
 last_reason_code text, reason_codes jsonb NOT NULL DEFAULT '[]'::jsonb,
 recovery_document_id uuid, recovery_document_version integer, recovery_agent_id text, recovery_agent_version integer,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(recovery_document_id,recovery_document_version) REFERENCES source_document_version(document_id,version),
 FOREIGN KEY(recovery_agent_id,recovery_agent_version) REFERENCES agent_registry(agent_id,version));
CREATE INDEX workflow_created_idx ON workflow(created_at DESC,id DESC);
CREATE TABLE workflow_stage (
 workflow_id uuid NOT NULL REFERENCES workflow(id), stage text NOT NULL CHECK(stage IN ('KYC','LOAN','PAYMENT')),
 run_count integer NOT NULL DEFAULT 0 CHECK(run_count>=0), used_points integer NOT NULL DEFAULT 0 CHECK(used_points>=0),
 reserved_points integer NOT NULL DEFAULT 0 CHECK(reserved_points>=0), PRIMARY KEY(workflow_id,stage));
CREATE TABLE agent_run (
 id uuid PRIMARY KEY, workflow_id uuid NOT NULL REFERENCES workflow(id), generation integer NOT NULL CHECK(generation>0),
 role text NOT NULL CHECK(role IN ('KYC','LOAN','PAYMENT')), agent_id text NOT NULL, agent_version integer NOT NULL,
 run_index integer NOT NULL CHECK(run_index>0), status text NOT NULL CHECK(status IN ('QUEUED','RUNNING','PROPOSED','VALIDATED','BLOCKED','FAILED','INVALIDATED','SUCCEEDED')),
 action_id uuid NOT NULL, input_bytes bytea, input_snapshot_hash varchar(64), started_at timestamptz, completed_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), FOREIGN KEY(agent_id,agent_version) REFERENCES agent_registry(agent_id,version),
 UNIQUE(workflow_id,role,run_index), UNIQUE(id,workflow_id,generation));
CREATE INDEX agent_run_workflow_idx ON agent_run(workflow_id,generation);
CREATE TABLE agent_result (
 id uuid PRIMARY KEY, run_id uuid NOT NULL UNIQUE REFERENCES agent_run(id), workflow_id uuid NOT NULL REFERENCES workflow(id),
 generation integer NOT NULL CHECK(generation>0), status text NOT NULL CHECK(status IN ('PROPOSED','VALIDATED','INVALIDATED')),
 body_json jsonb NOT NULL, result_hash varchar(64) NOT NULL, evidence_bundle_hash varchar(64),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(id,run_id,workflow_id,generation), FOREIGN KEY(run_id,workflow_id,generation) REFERENCES agent_run(id,workflow_id,generation));
ALTER TABLE workflow ADD CONSTRAINT workflow_kyc_result_fk FOREIGN KEY(current_kyc_result_id) REFERENCES agent_result(id);
ALTER TABLE workflow ADD CONSTRAINT workflow_loan_result_fk FOREIGN KEY(current_loan_result_id) REFERENCES agent_result(id);
CREATE TABLE run_source_use (
 run_id uuid NOT NULL REFERENCES agent_run(id), document_id uuid NOT NULL, document_version integer NOT NULL,
 content_hash varchar(64) NOT NULL, PRIMARY KEY(run_id,document_id,document_version),
 FOREIGN KEY(document_id,document_version) REFERENCES source_document_version(document_id,version));
CREATE INDEX run_source_lookup_idx ON run_source_use(document_id,document_version);
CREATE TABLE run_evidence_use (
 run_id uuid NOT NULL REFERENCES agent_run(id), evidence_id uuid NOT NULL REFERENCES trusted_evidence(id),
 PRIMARY KEY(run_id,evidence_id));
CREATE TABLE run_dependency (
 parent_run_id uuid NOT NULL REFERENCES agent_run(id), child_run_id uuid NOT NULL UNIQUE REFERENCES agent_run(id),
 parent_result_id uuid NOT NULL REFERENCES agent_result(id), workflow_id uuid NOT NULL REFERENCES workflow(id), generation integer NOT NULL,
 PRIMARY KEY(parent_run_id,child_run_id), CHECK(parent_run_id<>child_run_id),
 FOREIGN KEY(parent_run_id,workflow_id,generation) REFERENCES agent_run(id,workflow_id,generation),
 FOREIGN KEY(child_run_id,workflow_id,generation) REFERENCES agent_run(id,workflow_id,generation),
 FOREIGN KEY(parent_result_id,parent_run_id,workflow_id,generation) REFERENCES agent_result(id,run_id,workflow_id,generation));
CREATE TABLE action_request (
 action_id uuid PRIMARY KEY, actor_id varchar(64) NOT NULL, action_type text NOT NULL, workflow_id uuid REFERENCES workflow(id),
 payload_hash varchar(64) NOT NULL, status text NOT NULL CHECK(status IN ('PROCESSING','SUCCEEDED','FAILED')),
 decision text CHECK(decision IN ('ALLOW','WAIT_APPROVAL','DENY','ERROR')), result_json jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz);
CREATE TABLE approval (
 id uuid PRIMARY KEY, workflow_id uuid NOT NULL REFERENCES workflow(id), generation integer NOT NULL,
 actor_id varchar(64) NOT NULL, customer_id varchar(64) NOT NULL, amount_krw bigint NOT NULL CHECK(amount_krw BETWEEN 1 AND 50000000),
 payout_account_id uuid NOT NULL REFERENCES mock_account(id), kyc_result_id uuid NOT NULL REFERENCES agent_result(id),
 loan_result_id uuid NOT NULL REFERENCES agent_result(id), loan_result_hash varchar(64) NOT NULL, evidence_bundle_hash varchar(64) NOT NULL,
 policy_version text NOT NULL, review_snapshot_hash varchar(64) NOT NULL,
 extra_risk integer NOT NULL CHECK(extra_risk>=0), risk_limit integer NOT NULL CHECK(risk_limit>=0),
 status text NOT NULL CHECK(status IN ('AVAILABLE','RESERVED','CONSUMED','REVOKED','EXPIRED','REJECTED')),
 reserved_action_id uuid, comment varchar(1000), expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), consumed_at timestamptz);
CREATE UNIQUE INDEX approval_current_available ON approval(workflow_id) WHERE status IN ('AVAILABLE','RESERVED');
CREATE TABLE workflow_job (
 id uuid PRIMARY KEY, workflow_id uuid NOT NULL REFERENCES workflow(id), generation integer NOT NULL CHECK(generation>0),
 phase text NOT NULL CHECK(phase IN ('KYC','LOAN','PAY')), state text NOT NULL CHECK(state IN ('PENDING','RUNNING','SUCCEEDED','FAILED')),
 execution_action_id uuid NOT NULL UNIQUE, run_id uuid REFERENCES agent_run(id), approval_id uuid REFERENCES approval(id),
 lease_token uuid, lease_until timestamptz, last_error text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), started_at timestamptz, completed_at timestamptz,
 CHECK(state<>'RUNNING' OR (lease_token IS NOT NULL AND lease_until IS NOT NULL)));
CREATE UNIQUE INDEX workflow_one_active_job ON workflow_job(workflow_id) WHERE state IN ('PENDING','RUNNING');
CREATE INDEX job_claim_idx ON workflow_job(created_at,id) WHERE state='PENDING';
CREATE TABLE delegation_grant (
 id uuid PRIMARY KEY, workflow_id uuid NOT NULL REFERENCES workflow(id), generation integer NOT NULL,
 root_authorization_id uuid NOT NULL, principal_id varchar(64) NOT NULL, origin_intent text NOT NULL,
 issuer text NOT NULL, source_agent text NOT NULL, target_agent text NOT NULL,
 source_run_id uuid REFERENCES agent_run(id), target_run_id uuid NOT NULL UNIQUE REFERENCES agent_run(id),
 allowed_action text NOT NULL CHECK(allowed_action IN ('EVALUATE_KYC','CREATE_LOAN_RECOMMENDATION','EXECUTE_MOCK_PAYMENT')),
 customer_id varchar(64) NOT NULL, amount_krw bigint NOT NULL, payout_account_id uuid NOT NULL REFERENCES mock_account(id),
 source_result_id uuid REFERENCES agent_result(id), evidence_bundle_hash varchar(64), parent_grant_id uuid REFERENCES delegation_grant(id),
 depth integer NOT NULL CHECK(depth BETWEEN 1 AND 3), action_id uuid NOT NULL UNIQUE,
 payload_hash varchar(64) NOT NULL, policy_version text NOT NULL, risk_ledger_id uuid NOT NULL,
 approval_id uuid REFERENCES approval(id), format text NOT NULL DEFAULT 'FUSE-GRANT-v1', kid text NOT NULL,
 claims_bytes bytea NOT NULL, action_bytes bytea NOT NULL, mac_bytes bytea NOT NULL CHECK(octet_length(mac_bytes)=32),
 expires_at timestamptz NOT NULL, status text NOT NULL CHECK(status IN ('ISSUED','CONSUMED','REVOKED','EXPIRED')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), consumed_at timestamptz,
 CHECK((depth=1 AND source_run_id IS NULL AND source_result_id IS NULL AND parent_grant_id IS NULL AND approval_id IS NULL) OR
       (depth=2 AND source_run_id IS NOT NULL AND source_result_id IS NOT NULL AND parent_grant_id IS NOT NULL AND approval_id IS NULL) OR
       (depth=3 AND source_run_id IS NOT NULL AND source_result_id IS NOT NULL AND parent_grant_id IS NOT NULL AND approval_id IS NOT NULL)));
CREATE TABLE payment_reservation (
 id uuid PRIMARY KEY, workflow_id uuid NOT NULL REFERENCES workflow(id), generation integer NOT NULL,
 job_id uuid NOT NULL UNIQUE REFERENCES workflow_job(id), execution_action_id uuid NOT NULL UNIQUE,
 grant_id uuid NOT NULL UNIQUE REFERENCES delegation_grant(id), run_id uuid NOT NULL UNIQUE REFERENCES agent_run(id),
 approval_id uuid NOT NULL UNIQUE REFERENCES approval(id), points integer NOT NULL CHECK(points>0),
 payload_hash varchar(64) NOT NULL, status text NOT NULL CHECK(status IN ('RESERVED','COMMITTED','RELEASED')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz);
CREATE UNIQUE INDEX payment_one_active_reservation ON payment_reservation(workflow_id) WHERE status='RESERVED';
CREATE TABLE risk_ledger (
 id uuid PRIMARY KEY, workflow_id uuid NOT NULL REFERENCES workflow(id), generation integer NOT NULL,
 stage text NOT NULL CHECK(stage IN ('KYC','LOAN','PAYMENT')), event_type text NOT NULL CHECK(event_type IN ('CHARGE','RESERVE','CONSUME','RELEASE')),
 points integer NOT NULL CHECK(points>0), action_id uuid NOT NULL, run_id uuid REFERENCES agent_run(id),
 reservation_id uuid REFERENCES payment_reservation(id), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(action_id,event_type));
CREATE UNIQUE INDEX risk_stage_first_charge ON risk_ledger(workflow_id,stage) WHERE event_type='CHARGE';
CREATE TABLE mock_payment (
 id uuid PRIMARY KEY, workflow_id uuid NOT NULL UNIQUE REFERENCES workflow(id), application_id uuid NOT NULL UNIQUE REFERENCES loan_application(id),
 approval_id uuid NOT NULL UNIQUE REFERENCES approval(id), reservation_id uuid NOT NULL UNIQUE REFERENCES payment_reservation(id),
 action_id uuid NOT NULL UNIQUE, run_id uuid NOT NULL UNIQUE REFERENCES agent_run(id), generation integer NOT NULL,
 customer_id varchar(64) NOT NULL, amount_krw bigint NOT NULL CHECK(amount_krw BETWEEN 1 AND 50000000),
 payout_account_id uuid NOT NULL REFERENCES mock_account(id), payload_hash varchar(64) NOT NULL,
 receipt_json jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE quarantine (
 id uuid PRIMARY KEY, scope text NOT NULL CHECK(scope IN ('RUN','RESULT','WORKFLOW','SOURCE_VERSION','AGENT_VERSION')),
 run_id uuid REFERENCES agent_run(id), result_id uuid REFERENCES agent_result(id), workflow_id uuid REFERENCES workflow(id),
 document_id uuid, document_version integer, agent_id text, agent_version integer,
 status text NOT NULL CHECK(status IN ('ACTIVE','RELEASED')), reason_code text NOT NULL, note varchar(1000),
 actor_id varchar(64) NOT NULL, action_id uuid, released_by varchar(64), remediation_json jsonb,
 gate_epoch bigint NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), released_at timestamptz,
 FOREIGN KEY(document_id,document_version) REFERENCES source_document_version(document_id,version),
 FOREIGN KEY(agent_id,agent_version) REFERENCES agent_registry(agent_id,version),
 CHECK((scope='RUN' AND run_id IS NOT NULL AND num_nonnulls(result_id,workflow_id,document_id,document_version,agent_id,agent_version)=0) OR
       (scope='RESULT' AND result_id IS NOT NULL AND num_nonnulls(run_id,workflow_id,document_id,document_version,agent_id,agent_version)=0) OR
       (scope='WORKFLOW' AND workflow_id IS NOT NULL AND num_nonnulls(run_id,result_id,document_id,document_version,agent_id,agent_version)=0) OR
       (scope='SOURCE_VERSION' AND document_id IS NOT NULL AND document_version IS NOT NULL AND num_nonnulls(run_id,result_id,workflow_id,agent_id,agent_version)=0) OR
       (scope='AGENT_VERSION' AND agent_id IS NOT NULL AND agent_version IS NOT NULL AND num_nonnulls(run_id,result_id,workflow_id,document_id,document_version)=0)));
CREATE UNIQUE INDEX quarantine_active_run ON quarantine(run_id) WHERE scope='RUN' AND status='ACTIVE';
CREATE UNIQUE INDEX quarantine_active_result ON quarantine(result_id) WHERE scope='RESULT' AND status='ACTIVE';
CREATE UNIQUE INDEX quarantine_active_workflow ON quarantine(workflow_id) WHERE scope='WORKFLOW' AND status='ACTIVE';
CREATE UNIQUE INDEX quarantine_active_source ON quarantine(document_id,document_version) WHERE scope='SOURCE_VERSION' AND status='ACTIVE';
CREATE UNIQUE INDEX quarantine_active_agent ON quarantine(agent_id,agent_version) WHERE scope='AGENT_VERSION' AND status='ACTIVE';
CREATE TABLE audit_event (
 id uuid PRIMARY KEY, action_id uuid, workflow_id uuid REFERENCES workflow(id), run_id uuid REFERENCES agent_run(id),
 quarantine_id uuid REFERENCES quarantine(id), actor_id varchar(64) NOT NULL, event_type text NOT NULL, reason_code text,
 details_json jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE INDEX audit_workflow_idx ON audit_event(workflow_id,created_at,id);
-- Records that authorize later decisions must not be silently rewritten.
CREATE FUNCTION reject_immutable_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION '% is immutable: UPDATE and DELETE are forbidden', TG_TABLE_NAME USING ERRCODE='55000'; END; $$;
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_event FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER risk_append_only BEFORE UPDATE OR DELETE ON risk_ledger FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER source_append_only BEFORE UPDATE OR DELETE ON source_document_version FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER application_immutable BEFORE UPDATE OR DELETE ON loan_application FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER payment_immutable BEFORE UPDATE OR DELETE ON mock_payment FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
