# Security-check timing boundary

Specification §18.2 defines additional FUSE inspection time separately from model and employee
waiting time. `SecurityCheckObservation` implements an explicitly enabled, synchronous measurement
for isolated experiment scenarios. It does not start automatically in serving requests or workers.

## What is measured

Boundary version: `FUSE-DEDICATED-POLICY-CHECKS-2`.

| Check name | Instrumented methods |
| --- | --- |
| `VERIFIED_EVIDENCE` | `EvidenceValidator.validate` for `VERIFIED` proposals, `validateStored`, `revalidate` |
| `DELEGATION_VALIDATION` | `DelegationService.validate`, including FUSE-specific action binding, lineage, current prerequisite, and budget validation |
| `QUARANTINE_MATCH` | `QuarantineMatcher.isQuarantined`, `workflowQuarantined` |

The duration includes database reads performed inside these policy checks. A denied check and a
check that throws still contribute their actual elapsed time. Nested checks contribute once to
the elapsed total; the per-check counters include nested calls and therefore are not independent
latency components.

Common work is excluded: public authentication/RBAC, basic MAC/body-hash verification shared with BASELINE, general workflow accounting and database
writes, exact employee approval handling, grant issuance/consumption outside the named checks,
`validateForCustomer`, and non-`VERIFIED` proposal handling retained by the baseline. Evidence and
quarantine checks invoked from grant issuance still count because those implementations are
replaced by the baseline ablation. `EnvelopeValidator` is not independently timed because its
issuance checks are shared with the baseline; consumption-time validation is already inside
`DelegationService.validate`.

Only the listed boundaries are covered. This is not exhaustive profiling of every inline guard,
a CPU-time measurement, or a subtraction of whole-workflow BASELINE and FUSE runtimes. Do not
present it as end-to-end workflow overhead. Model HTTP requests, provider retries, workflow gaps,
and human waiting are not timed. Ordinary query/report construction outside these boundaries is
not timed either.

## Measurement lifecycle

The synchronous experiment wrapper uses:

```java
var observation = SecurityCheckObservation.begin();
Map<String, Object> output;
try (observation) {
    output = runObserved(fixture, fixtureHash, repeat);
}
var timing = observation.result();
output.put("securityCheckDurationMs", timing.securityCheckDurationMs());
```

The clock is `System.nanoTime()`, independent of the fixed database time used for policy tests.
Only outermost check entry/exit reads the clock. There is no session-wide stopwatch. Fractional
milliseconds are exported without rounding tiny measurements up or down to a made-up value.
`elapsedNanos`, `completedCheckCount`, and immutable `completedChecks` support inspection of the
recorded boundary. No inputs, outputs, identifiers, SQL, credentials, or exception messages are
retained by the observation utility.

The session is thread-confined and is not inherited by child threads. Nested sessions are rejected.
Try-with-resources closes spans on denial or failure; closing a session removes the thread-local
state. An incomplete span prevents publishing a partial result and still clears the active state.
Read `result()` only after all scopes and the session have closed.

BASELINE overrides skip the ablated methods naturally, so a completed measured run with no
additional checks has a real measured duration of `0.0` and a completed-check count of zero.
This zero must not be substituted for an unmeasured or failed experiment. Failed/environment-error
rows retain the experiment runner's exclusion semantics; timing alone never means policy success.
FUSE coverage should be asserted with recorded counts, not a flaky assertion that a wall-clock
duration must exceed a chosen threshold.

## Quarantine commit-to-execution-denial latency

`QuarantineObservation` is a separate opt-in, thread-confined session opened by the synchronous
experiment wrapper. Boundary version: `QUARANTINE-COMMIT-TO-EXECUTION-DENIAL-1`.

A newly inserted quarantine registers a Spring transaction synchronization. Its monotonic origin
is captured by `System.nanoTime()` in `afterCommit`, only after the outermost physical transaction
commits. A service return inside an open transaction, request duration, fixed policy clock,
`quarantine.created_at`, and an uncommitted write are never used as the origin. The timestamp is the
application's commit-notification boundary, not a database-server hardware timestamp. JVM callback
scheduling overhead between database commit and notification is outside this measured interval.

The service records the exact already-started, live KYC/PAY executions whose jobs it invalidates.
Correlation includes incident, workflow, generation, job, run, and lease identity. An actual
`KycTransactions.apply` or `PaymentTxService` attempt must reach its existing rejection guard with
that same context, a current generation, an unexpired matching lease, and quarantine-invalidated
job/workflow state. A KYC response must also be bound to its prepared input. The observation hook
does not decide the outcome or change the existing rejection response/reason code. In particular,
a payment discarded by the existing stale-lease guard retains that public reason; the recorded
quarantine-caused job invalidation provides the measurement's causal correlation.

The endpoint is captured when that real guard rejects the attempt. It is published only after the
denial transaction itself commits. This prevents a later technical rollback from publishing a
policy outcome; the endpoint excludes audit writes and denial-transaction commit time. The first
committed denial per incident is retained. If several incidents are observed, the scalar
`quarantineLatencyMs` is the interval for the first observed denial in the case; each incident's own
first denial remains separately inspectable in `trace.quarantineMeasurement.incidents`.

Trace contains incident/workflow/job/run/generation identifiers, attempt boundary,
`commitObservedNanos`, `executionDeniedNanos`, `elapsedNanos`, committed incident count, and observed
denial count. Fractional milliseconds are `elapsedNanos / 1_000_000.0`. The raw monotonic readings
are process-local and must not be compared across JVMs. Lease tokens are used only for in-memory
correlation and are omitted from exported results, then discarded at session close.

The following do not produce a latency: matcher/UI/impact reads; unrelated or wrong-lease denials;
expired leases; recovered generations; quarantines or denial transactions that roll back; attempts
before the quarantine commits; and previously paid workflows replaying their existing receipt.
A committed quarantine without a later observed affected execution has `null` latency. This includes
automatic evidence quarantine that ends the workflow without another execution attempt. Zero is
valid only when two actual monotonic observations have identical values; it is never a missing-data
replacement. BASELINE arms do not gain an artificial quarantine event.

Coverage is deliberately the synchronous, same-thread experiment/test boundary for already-started
KYC application and payment attempts. No session is automatically opened for ordinary workers, and
child threads/processes do not inherit it. Future-run admission, Loan attempts, cross-thread races,
server restarts, and distributed propagation remain unmeasured by this utility. An unobserved event
is not evidence of instant enforcement or of a failure to enforce. Existing policy decisions,
transaction ordering, locks, grants, risk accounting, and public APIs are unchanged.

## Local verification

`SecurityCheckObservationTest` uses a deterministic nanosecond clock to cover gaps, nesting,
exceptions, disabled sessions, repeated close, thread isolation, and malformed scope cleanup.
`PolicyObservationTest` uses only local read-only policy fakes to verify the actual evidence,
delegation, and quarantine boundaries. Neither test calls a model, creates a database, or adds an
attack fixture.

```sh
./gradlew test --tests '*SecurityCheckObservationTest' --tests '*PolicyObservationTest'
```

`QuarantineObservationTest` uses deterministic monotonic readings and synthetic synchronization to
verify commit/guard boundaries, exact correlation, rollback exclusion, earliest-event retention,
null versus measured zero, and session cleanup/isolation. `QuarantineObservationIT` exercises the
real PostgreSQL service transactions, including outer-transaction rollback and late KYC/payment
attempts. `ExperimentQuarantineObservationIT` verifies all five paired quarantine-bypass fixtures
and a terminal automatic quarantine with no subsequent execution. Timing tests assert recorded
events and deterministic deltas, never an arbitrary positive wall-clock threshold.

```sh
./gradlew test --tests '*QuarantineObservationTest'
./gradlew integrationTest --tests '*QuarantineObservationIT' --tests '*ExperimentQuarantineObservationIT'
```

Commands above are verification entry points, not a claim that a particular run passed. Run results
belong in the current verification report and Gradle XML outputs.
