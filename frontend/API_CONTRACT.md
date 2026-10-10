# Browser → Spring contract

Prefix: same-origin `/api/v1`. All reads use `Authorization: Bearer <memory-only token>`, `Accept: application/json`, and `cache: no-store`. Mutations add JSON content type and a UUID `Idempotency-Key`. The browser never supplies actor, role, approver identity, grant authority, evidence validity, risk score, or payment status.

| Method/path                            | Browser input                                                     | Required response/view                                                                                                                                                          |
| -------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET `/workflows`                       | page 0+, size 20, optional state                                  | items/total/page/size                                                                                                                                                           |
| POST `/workflows`                      | businessReference/customerId/amountKrw/payoutAccountId            | decision/state/workflowId/requestId/replayed                                                                                                                                    |
| GET `/workflows/{id}`                  | UUID                                                              | workflowId/state/generation/customerId/businessReference/amountKrw/payoutAccountId/usedRisk/reservedRisk/riskLimit/reasonCodes/activeQuarantines/activeJob/canApprove/canResume |
| GET `/workflows/{id}/trace`            | UUID                                                              | runs/results/grants/dependencies/approvals/riskEvents/payments/auditEvents; sourceUses/evidenceUses extensions                                                                  |
| GET `/workflows/{id}/approval-preview` | UUID                                                              | exact preview fields below                                                                                                                                                      |
| POST `/workflows/{id}/approvals`       | decision APPROVE or REJECT/reviewSnapshotHash/comment             | decision/state/approvalId/requestId; approval is not payment                                                                                                                    |
| POST `/workflows/{id}/resume`          | expectedGeneration/reason                                         | accepted state + new generation                                                                                                                                                 |
| POST `/quarantines`                    | scope + only that scope's target fields/reasonCode/note           | quarantineId                                                                                                                                                                    |
| GET `/incidents/{quarantineId}/impact` | UUID                                                              | incidentId/scope/target/historicalRunIds/currentAffectedWorkflowIds/paidBeforeQuarantine/actual/potential/calculationRefs                                                       |
| POST `/quarantines/{id}/release`       | remediation object                                                | release response; no resume side effect                                                                                                                                         |
| POST `/experiments`                    | fixtureSetId/caseIds/mode PAIRED; REPLAY/1 default, LIVE/3 opt-in | experimentId/state/status                                                                                                                                                       |
| GET `/experiments/{id}`                | UUID                                                              | experimentId/status/fixtureSetId/modelMode/progress/caseOutputs/metrics/limitations                                                                                             |

## Exact approval preview

The UI displays and sends back the server's `reviewSnapshotHash` unchanged. It does not calculate or normalize the hash. Displayed binding:

- workflowId, generation, customerId, amountKrw, payoutAccountId
- kycResultId, loanResultId, evidenceBundleHash, loanResultHash
- policyVersion, usedRisk, reservedRisk, riskLimitAfterApproval
- reviewSnapshotHash

The submit button additionally requires an explicit checkbox. On `409 REVIEW_CHANGED`, the old preview is unusable until a new one is loaded and confirmed. The server remains authoritative for current state and permissions.

## Trace fields

Arrays use camelCase from WorkflowQueryService. Known identifiers: runId, resultId, grantId, approvalId, paymentId. Candidate content is `results[].bodyJson`. Grants use source/target/action/depth/parent/expiresAt/status, without signing material. Risk events have eventType/points/stage/runId. Audit events use eventType/reasonCode/detailsJson/createdAt. Source/evidence records use `sourceUses[]` and `evidenceUses[]`.

Only runs with a non-null startedAt count as actually started in the local graph. Prepared records remain visible but are labeled separately. No missing Loan or Payment nodes are synthesized. Graph counts include historical generations and are labeled accordingly. Full incident metrics remain server-calculated.

PAID details can include `historicalApprovedRiskLimit`. It is shown separately from the current effective limit; it grants no new payment authority.

## Quarantine payloads

Exactly one scope's fields is sent:

- RUN: runId (UUID)
- RESULT: resultId (UUID)
- WORKFLOW: workflowId (UUID)
- SOURCE_VERSION: documentId (UUID), documentVersion (integer)
- AGENT_VERSION: agentId (string), agentVersion (integer)

Release `remediation` includes safeDocumentId/safeDocumentVersion/checkEvidenceIds/note. AGENT_VERSION additionally includes safeAgentId/safeAgentVersion (integer). Evidence IDs are deduplicated. An empty list is allowed in the UI only when the server's actual pending impact amount is zero; the server validates the complete recovery conditions.

Optional `policyHeldWorkflowIds` marks workflows held before any actual source consumption or run. The current affected list labels these separately and never fabricates graph execution.

Actual impact fields: runCount/roleCount/workflowCount/customerCount/paymentCount/paidAmountKrw/atRiskPendingAmountKrw. Potential fields: roles/maxDownstreamDepth/registeredCustomerCount/perApplicationLimitKrw/missingPolicyFields/applicationCount/totalAmountKrw/currency. Null does not become zero. paidBeforeQuarantine can be an array of payment bindings.

Potential `applicationCount` is an integer; `totalAmountKrw` is an exact nonnegative decimal integer **string**, and `currency` is `KRW`. An empty eligible population returns 0/"0"/"KRW". The UI labels the amount **잠재 영향 금액**, explained as **영향받을 수 있는 신청 금액의 합계**. See the [incident impact API contract](../docs/incident-impact-api.md) for included current states, incident scope, application-ID deduplication, and aggregation rules.

## Experiments

`mvp-security-v1` sends the exact six case IDs from the specification. `security-evaluation-v1` sends caseIds=[] to select every registered case in that fixture. This is a server-supported convention, not a locally invented list of measured outcomes.

Default requests use modelMode=REPLAY/repeatCount=1. Optional LIVE uses repeatCount=3 and requires both the ordinary experiment confirmation and a separate affirmative checkbox acknowledging external transmission of the selected synthetic fixture data and possible provider charges. Fixture or model-mode changes clear both confirmations. The submit handler checks confirmation state as well as disabling the button. Consent is a UI control, not a replacement for server authorization; no extra unrecognized DTO fields are sent.

LIVE also requires the server's FUSE_EXPERIMENT_LIVE_ENABLED=true and configured internal KYC capture route/provider. LIVE_NOT_AVAILABLE remains an explicit failure; the UI never falls back to another mode or calls a provider directly. No model URL or provider credential is accepted from the browser.

For LIVE results, top-level syntheticModelOutputs/liveRobustnessMeasured metadata (or metrics fields when absent at the top level) determines the display. A LIVE request without a valid capture or common eligible attack measurements is not presented as completed live robustness evaluation. Each case row can carry trace.modelCapture with modelMode/model/promptVersion/promptHash/modelOutputHash/inputSnapshotHash/modelOutput/captureRequestId/captureRunId. The UI displays shared capture IDs and preserves the full capture details in raw export. Duplicate BASELINE/FUSE metadata does not imply two model calls. Non-RAG injected perturbations remain harness-based.

Capture failures MODEL_OUTPUT_INVALID, DEPENDENCY_UNAVAILABLE and CAPTURE_ERROR, plus INDUCTION_FAILED, are explained separately from policy success. Both members of an excluded pair remain excluded.

Per-row securityCheckDurationMs is labeled dedicated security-check time. It excludes model/reviewer waits and common approval/accounting, is not total latency or a baseline-minus-FUSE differential, and details are preserved under trace.securityMeasurement. Null quarantineLatencyMs is shown as unmeasured, never zero.

The UI supports `progress.{completed,total}` and `{completedRuns,totalRuns}`. It displays paired numeric comparisons from `metrics.environments.{BASELINE,FUSE}`, including denominators. Rates remain missing when the server returns null. Exclusions come from either top-level exclusions or metrics.exclusions; a `caseId:repeat` excluded pair labels both arms. Errors are never changed to policy-block success. Completed comparison pairs are labeled as such instead of assuming every pair belongs in an attack denominator.

CSV and JSON exports are derived only from the fetched experiment. CSV preserves nested records as JSON strings and neutralizes formula-leading text. There is no direct DB query, synthetic success fallback, or browser-side model call.

## Error and lifecycle behavior

- HTTP 401/403: explicit authentication/permission error, never a policy defense success.
- HTTP 409: conflict code preserved. REVIEW_CHANGED requires fresh preview.
- Network or 5xx mutation outcome: uncertain; exact body/key retained for explicit retry.
- Invalid JSON: explicit INVALID_RESPONSE error.
- GET failure after a successful read: the prior record is marked as the last successful snapshot.
- Unmount/new route/token: obsolete GET aborted and late completion ignored.
- API response 202/201: accepted/approved status, never inferred PAID.

The app does not use a client role selector as authority. Token switching clears the entire mounted workspace. Screens that require staff/security/developer roles rely on the corresponding server response.
