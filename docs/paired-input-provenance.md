# Paired comparison and arm binding contract

Contract version: `FUSE-PAIRED-INPUT-1`. New execution reports identify themselves as
`FUSE-EVALUATION-2`. This document describes implementation behavior, not measured
policy effectiveness or model robustness.

## Three different digests

- `pairedInputHash` compares the semantic conditions supplied to two isolated arms.
  It is computed by the Java harness from registered fixtures and prepared database
  state, before either arm executes. Each arm independently recomputes it from its
  actual initial prepared input. A mismatch excludes the complete pair.
- `inputSnapshotHash` binds one arm's exact stored KYC input bytes, including that
  arm's request, workflow, generation, and run identifiers. The normal KYC binding
  validator remains mandatory. Different arm UUIDs ordinarily produce different
  hashes. Equality of these arm-specific hashes is not a pairing requirement.
- `responseByteHash` is SHA-256 of the exact serialized, rebound KYC response the
  harness supplies to that arm. The original shared candidate is rebound separately;
  a complete response from one arm is never copied into another arm.

`modelOutputHash` remains the digest of the shared canonical candidate proposal,
without request binding. It is not the arm response digest or the provider's HTTP
response digest. A matching comparison digest is evidence of consistency, not
truth, valid evidence, permission, or successful policy enforcement.

## Canonical input projection

Encode a JSON object as UTF-8, without insignificant whitespace or ASCII escaping.
Sort every object key lexicographically, including nested records after projecting
records to objects. Preserve list order. Hash the resulting bytes with SHA-256,
represented by 64 lowercase hexadecimal characters.

The root fields are fixed by version 1:

1. `version`: `FUSE-PAIRED-INPUT-1`
2. `fixtureHash`: the registered complete fixture-manifest fingerprint
3. `fixture`: only `caseId`, `kind`, `family`, `split`, `customerId`, `amountKrw`,
   `payoutAccountId`, `documentVersion`, `evidenceVariant`, `mockReviewer`,
   `injection`, and `forbiddenGoal`; unavailable fields are null
4. `business`: the prepared database application's `business_reference`,
   `customer_id`, `amount_krw`, and `payout_account_id`; its profile's
   `monthly_income_krw`, `max_loan_amount_krw`, `profile_hash`, and
   `loan_policy_version`; its account's `account_customer_id` and `account_status`
5. `customerId` and `policyVersion`: actual prepared model-input values
6. `evidenceFacts`: ordered actual model facts (`evidenceId`, `kind`, `result`)
7. `documents`: ordered `documentId`, `documentVersion`, and `contentHash`, after
   independently verifying the content hash against the actual UTF-8 document bytes
8. `modelMode`, resolved `model`, `promptVersion`, and `promptHash`
9. `mockReviewerVersion`

The numbered list defines the projection, not insertion order: the final object
keys are sorted. Transport/execution IDs, application row IDs, job/action/run IDs,
arm names, wall-clock timings, and generations are absent from this comparison
projection. Stable fixture evidence/document/account IDs remain because they
identify common business inputs rather than per-arm transport.

REPLAY uses `model=replay`, `promptVersion=KYC-PROMPT-1`, and null `promptHash`.
This explicitly does not claim that private prompt text was loaded or measured.
LIVE includes the capture endpoint's fingerprint of the actual complete model
messages and resolved model/prompt metadata. The captured document objects are
frozen and reused in both arm inputs; later private-file changes cannot silently
alter one arm. Private document or prompt bodies are never included in the
canonical projection or exported hash metadata.

The first prepared KYC input represents the common starting conditions. Registered
multi-step probes may apply additional prerequisite or secondary KYC responses;
all actual response bindings appear in `trace.armBindings`.

## Evidence storage and privacy

Each arm exports its own top-level `inputSnapshotHash` and `responseByteHash` plus
`trace.armBindings` entries containing a generated `bindingId`, request/workflow/
run IDs, generation, input snapshot hash, request byte hash, response byte hash,
and binding verification result. These entries contain no document bodies.

For service-run experiments, `experiment_arm_binding` retains exact input snapshot,
serialized request, and serialized response bytes in the experiment database.
The binding row and corresponding `experiment_case_result` are inserted in the
same pair transaction. The public experiment read route exposes hashes/references,
not those byte columns. Access to these private byte rows requires the database's
existing access controls. A test using disposable schemas may validate raw bytes
before dropping its schema; its exported references alone do not imply durable
raw retention.

Report files under the ignored local export directory may include diagnostic model
candidate text. Only the sanitized evidence bundle is suitable for deliberate
sharing. No permission to publish private model inputs or AI instructions follows
from generating these local files.

## Exclusions and compatibility

Both arms need the supported pairing version, a valid paired hash, and their own
valid snapshot/response digests. Different paired hashes or disagreement with the
server's expected prepared digest yield `UNPAIRED_INPUT`. Missing provenance yields
`PAIRED_INPUT_MISSING` or `ARM_BINDING_MISSING`; an unknown pairing version yields
`PAIRED_INPUT_VERSION_UNSUPPORTED`. These exclusions affect the common denominator
and do not remove raw result rows or count as policy blocks.

The Python normalizer preserves `inputReportVersion`. Version 1 or unversioned
reports are retained but excluded as `PAIRED_INPUT_REPORT_VERSION_UNSUPPORTED`;
unknown report versions are rejected without rewriting the retained raw report.
The Java read route recalculates metrics under current provenance rules instead
of trusting cached legacy eligibility.

REPLAY execution requires exactly one repeat; LIVE requires exactly three repeats
and explicit LIVE enablement. `COMPLETED` is the existing persisted/API completion
status. It denotes finished execution, not that every outcome matched expectations
or that excluded cases became eligible.
