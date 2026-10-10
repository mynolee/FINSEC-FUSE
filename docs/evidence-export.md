# Evaluation evidence bundles

The exporter transforms a validated `FUSE-EVALUATION-2` execution report into a
versioned, sanitized disk bundle. It does not run a scenario, call a model, fill
missing outcomes, or authenticate a hand-written report. Tests of the exporter
use synthetic input records and do not establish financial-policy effectiveness.

## Commands and output locations

From the repository root, with the documented Python dependencies installed:

```sh
python -m evaluation.scenario_runner run \
  --fixture-set security-evaluation-v1 \
  --model-mode REPLAY \
  --output evaluation/exported_runs/full
```

The runner first obtains and validates the real Java/PostgreSQL results. It then
writes the bundle to `evaluation/exported_runs/full/<experimentId>/`. REPLAY has
one repeat per case; LIVE requires explicit authorization and three repeats.
Source response/request binding bytes remain in the private database. A safe
trace carries binding IDs and hashes for an authorized independent comparison.

An already normalized report can be exported without running an experiment again:

```sh
python -m evaluation.export \
  --report evaluation/exported_runs/full/report.json \
  --output evaluation/exported_runs/reexport
```

The registered fixture set and exact selected case order are taken from the
saved report. A fixture hash, selection, metric, mode or repeat mismatch stops
export. The CLI prints the resulting bundle path and preserves the experiment's
actual status, including FAILED and INTERRUPTED. Successful export alone does
not mean the experiment succeeded or had no excluded pairs.

All generated evidence belongs in ignored local storage. The runner's sibling
`raw-java-report.json`, `report.json`, `request.json`, and `accepted.json` are
private diagnostics. In particular, raw/normalized report traces can contain
private model-candidate text. Never commit them or upload the whole output root
to CI artifacts. Upload only the completed `<experimentId>` bundle directory.
Do not include private prompts, personal AI instructions, credentials, or raw
customer documents in repository artifacts.

## Bundle contract

- `manifest.json`: bundle/sanitizer/report versions, experiment status, model
  mode, repeat count, fixture and selected-plan fingerprints, source-report
  fingerprint, source-code content hashes, observed version labels, selection
  and execution counts, Mock reviewer assumption, export timestamp, and a
  SHA-256/byte-size inventory of every other bundle file.
- `case_results.json`: one row for each selected case, repeat and environment.
  Planned expectation columns and actual observation columns are separate.
- `case_results.csv`: the same rows and columns, in the same deterministic order.
  Null is the literal `null`; booleans and lists use JSON literals. Machine labels
  cannot begin with spreadsheet formula prefixes.
- `metrics.json`: recomputed overall metrics and independent DEV, TUNE, FINAL,
  and NORMAL partitions. DEVELOPMENT and TUNING source labels map to DEV and
  TUNE; unknown splits are rejected.
- `traces/*.json`: allowlisted trace projections referenced by individual rows.
  Their byte hashes are recorded in the manifest; each projection also records
  its source trace hash.

`FUSE-EVIDENCE-BUNDLE-1` and `FUSE-EXPORT-ALLOWLIST-1` define this representation.
Canonical fingerprints use sorted JSON keys, UTF-8, compact separators, and no
non-finite numbers. The manifest's file hashes instead cover the exact emitted
bytes. The manifest does not self-hash. Source-code hashes describe the files
present at export time, not proof that those files produced an older saved run.
Record the execution revision separately when importing older reports. Hashes
are reproducibility links, not digital signatures or proof of origin.

## Outcomes, exclusions and denominators

Both arms remain in the result table. A missing arm becomes an explicit NOT_RUN
observation with null actual fields. The observed partner is retained, while
the common pair is excluded. An ERROR row retains its actual error status,
decision and machine reasons; numeric measurements and outcome booleans are
null because the error record does not establish an observation. Expected
outcomes are never copied into an actual column.

The shared metric calculator determines common exclusions, including missing
arms, environment failures, mismatched paired inputs/candidate hashes and failed
attack induction. Export checks the report's metrics against recomputation and
rejects disagreement. A pair's common exclusion appears on both arm rows, while
each arm's original exclusion remains separately visible. Policy-block rates
with no eligible attack pairs have a null rate.

`registeredPlannedCaseCount` describes the full current registered plan only
when its hash matches the report; otherwise it is null. `selectedCaseCount`
describes this run. Environment-result counts, case-repeat pair counts, induced
attack pairs, common exclusions and eligible attack pairs are separate fields.
A partial run is never presented as completion of the entire registered plan.

Each split uses the same shared exclusion rules and its own denominator. The
all-case aggregate must not be labeled FINAL performance. LIVE denominators
count case-repeat pairs, so three repeats of one case are not three independent
attack designs. Per-repeat case rows remain available for case-level review.

Observed Mock ledger counts and amounts are extracted from trace payment rows;
forbidden-payment values come from actual scenario outputs. Payment-goal
occurrence is derived from the actual forbidden-payment count; an unsupported
non-payment goal stays null rather than being inferred from an expected outcome. Missing ledger data
is null, while an observed empty ledger is zero. `quarantined` remains null when
current quarantine state was not explicitly recorded. Commit/denial counts and
measured latency, when present, remain separate observations. Unmeasured timing
is null; it is never populated with a target or an invented zero.

## Privacy and preservation

Sanitization is an allowlist, not a recursive copy with a few forbidden keys.
It retains measured numbers, versioned public machine labels, valid timestamps,
UUIDs and hashes. The shared `evaluation/export_labels.json` vocabulary is closed:
unknown model/version/reason labels become hashes, even when they look like single
words or well-formed access tokens. Add new public protocol labels deliberately;
never populate this vocabulary from private provider responses or configuration. It excludes prompt text, explanations, request/response bytes, document
bodies, arbitrary SQL/JSON bodies, receipts, actor identities, authentication
material and unknown nested objects. Model capture exports only candidate
status, evidence IDs and a candidate fingerprint. Unexpected IDs and free-text
labels become opaque SHA-256 references. No raw error messages are emitted by
the import CLI.

Quarantine observations retain the recorded commit timestamp and first actual
execution-denial endpoint metadata, including delta, workflow/run/job IDs and
attempt type. Null first-denial observations stay null. Lease tokens are never
included. The projection is not a complete substitute for private database
records; authorized QA must use binding/source hashes to inspect those separately.

Bundle directories and files are owner-only. A new bundle is assembled in a
private staging directory and renamed into place after all files are ready.
Identical repeat exports are idempotent. A changed, damaged, symlinked or
unexpectedly expanded existing bundle is not overwritten or accepted. A changed
policy or rerun requires a new experiment ID; previous evidence remains intact.

## Verification

```sh
python -m pytest -q evaluation/tests/test_export.py
```

The suite checks JSON/CSV parity, file hashes, split denominators, expected/actual
separation, paired error exclusions, null missing measurements, private-content
removal, quarantine measurement projection, source/selection consistency,
immutable/idempotent exports, filesystem path safety and import failure redaction.
Actual Java/PostgreSQL runs and independent DB/UI/CSV comparisons are separate
checks and must be reported with their own command, scope and observed results.

## Browser downloads

The experiment screen's CSV and **정제 JSON 내보내기** buttons use a separate
`FUSE-UI-EVIDENCE-1` projection. The JSON contains allowlisted server metadata,
observed rows, sanitized traces and known numeric metrics; CSV uses fixed columns
and excludes trace bodies. Raw JSON is no longer a default browser download.
Both formats omit arbitrary fields, prompt/document text, candidate explanations,
raw database/receipt bodies and credentials. Unknown machine labels become null
in the browser; unknown reasons have a fixed REDACTED_LABEL marker.

The browser uses the same closed label vocabulary as the disk exporter. It does
not recompute policy metrics, create absent fixture observations, or claim the
disk bundle's file hashes. Use the Python bundle for full fixture-plan provenance
and immutable file inventories. Formula-like CSV strings, including whitespace-
prefixed values, are neutralized; null, zero and false remain distinct.

```sh
npm --prefix frontend test -- --run src/experimentExport.test.tsx
npm --prefix frontend run build
```

## Backend JUnit evidence

Backend CI also produces a separate, privacy-safe three-file evidence set:

- `backend-test-summary.json`: existing independently calculated unit and
  integration aggregate counts and bounded source-allowlisted failure locations.
- `backend-test-inventory.json`: observed JUnit case outcomes grouped by
  conservative checkout-derived class/method identities. Unknown identities are
  counted separately; raw XML names, display/parameter values, failures and
  stdout/stderr are never copied into the inventory.
- `backend-test-evidence.json`: exact-byte SHA-256/size bindings for both safe
  JSON inputs, checked-out Git HEAD and tree, and the supplied CI run ID/attempt.

These files are generated in `safe-artifacts/`. The backend artifact upload
explicitly names only these three JSON files, never the directory, raw Gradle
XML, process stdout/stderr or private originals. Upload runs after binding and
verification succeed, even if the backend tests or aggregate gate failed.
Malformed or inconsistent evidence is not uploaded. Build and aggregate failures
remain failures; missing reports, zero-test tasks, failures and skips cannot be
turned into passing backend verification by successfully exporting evidence.

CI first checks that tracked source is clean before backend execution. After the
run, binding and verification compare the working source against committed blobs
and require the expected checkout revision. The expected revision is
`GITHUB_SHA`, which can be GitHub's synthetic merge commit on a pull-request run;
it must not be replaced with the pull request's head revision. CI supplies the
actual `GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT`, rather than fabricated local IDs.

The commands used by CI, from the repository root, are:

```sh
python scripts/ci-test-report.py
python scripts/ci-test-inventory.py backend/build/test-results \
  --output safe-artifacts/backend-test-inventory.json
python scripts/ci-test-evidence.py bind \
  --repository "$GITHUB_WORKSPACE" --artifacts safe-artifacts \
  --head "$GITHUB_SHA" --run-id "$GITHUB_RUN_ID" \
  --run-attempt "$GITHUB_RUN_ATTEMPT"
python scripts/ci-test-evidence.py verify \
  --repository "$GITHUB_WORKSPACE" --artifacts safe-artifacts \
  --head "$GITHUB_SHA" --run-id "$GITHUB_RUN_ID" \
  --run-attempt "$GITHUB_RUN_ATTEMPT"
```

CI runs the inventory and binding steps even when preceding test steps fail;
this is not a shell recipe for suppressing a failed command. The inventory's
output parent must already exist (the summary exporter creates it). Binding
requires exactly the two input JSON files, creates a new evidence file without
overwriting an existing one, and verification requires exactly all three files.
Use a fresh dedicated directory for a new run.

`complete` refers only to whether every observed JUnit testcase identity could
be mapped safely. Dynamic, generated, inherited, custom-display or ambiguous
identities remain explicitly unknown when the conservative parser cannot prove
the mapping. Partial mapping yields `complete=false` and
`EVIDENCE_INCOMPLETE`; it does not reduce or rewrite independently verified
aggregate test counts. The inventory's identity parser is deliberately stricter
than the existing summary's failure-location parser. If a summary failure ID has
no corresponding mapped failed/error inventory row, the binder rejects the
inconsistent pair and withholds the upload; it does not silently discard that
failure ID or downgrade the mismatch to partial evidence.
Even `EVIDENCE_COMPLETE` is not source coverage, a test
pass verdict, full acceptance, Compose/browser verification or LIVE robustness.

This is an integrity binding, not execution attestation, a digital signature or
proof that these sources actually produced the reports. A pre-run clean check
and post-run committed-blob comparison do not prove source was immutable
throughout execution, prevent malicious temporary edit-and-restore, authenticate
a hand-written report, or establish the origin of locally supplied run IDs.
Independent trusted execution records remain necessary for those claims.

Standalone safeguards can be checked without services or provider calls:

```sh
python scripts/ci-test-inventory-test.py
python scripts/ci-test-evidence-test.py
```
