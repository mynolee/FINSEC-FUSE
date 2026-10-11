# Scheduled KYC capacity acceptance

`ScheduledKycCapacityLifecycleIT.scheduledPollEnforcesFourSlotsAndReusesReleasedFailureCapacity`
exercises the production `JobWorker.poll()` admission path, its default four permits,
real worker executor, real KYC HTTP adapter, and isolated PostgreSQL transactions.
A test-owned scheduler invokes `poll()` at the unchanged policy interval only after
five independent synthetic workflows have been created. The normal Spring worker
remains disabled in the test profile, preventing claims during schema reset.

The local HTTP fixture has six handler threads, so it cannot impose the four-call
bound itself. Four requests wait behind controlled response barriers. Three further
completed polls must leave those four jobs/runs running and charged once, while the
fifth stays pending without a run, lease token, result, or charge. Releasing one
request with HTTP 503 must produce `ON_HOLD` / `DEPENDENCY_UNAVAILABLE`, one failed
job/run, and exactly one bound KYC charge. A later scheduled poll admits the fifth
request while the other three remain waiting. The maximum number of requests awaiting
responses stays four. This counter ends immediately before response publication;
it deliberately does not count socket-close callbacks that can overlap a new call.

The remaining responses bind to their own workflow, generation, action, run, input
snapshot and genuine synthetic failing evidence. They finish as `NOT_VERIFIED`
without downstream loan/payment work. Further polls must preserve the failed
workflow snapshot and total request count: no automatic retry, duplicate result,
quarantine, payment reservation, or payment. Cleanup stops and joins the test
scheduler, then every production worker task, then every HTTP handler before a
subsequent database reset. Reflection observes only the executor for that join;
there is no new production accessor or modified semaphore.

## Evidence scope

The fixed `FUSE-SCHEDULED-KYC-CAPACITY-METHODS-1` projection is enabled with
`--require-scheduled-kyc-capacity`. Bind/verify checks its exact class, source path,
method identity, source digest, revision, CI run/attempt, and shared raw-report set.
It appends to the seven existing named groups. Unmapped unrelated identities still
make the global result `EVIDENCE_INCOMPLETE`; named passing projections do not change
that status. The offline reporter regressions exercise rejection and privacy paths,
not Java execution.

This short controlled barrier test does not establish the 30-second HTTP deadline,
90-second real lease survival, Spring scheduling activation/timing, wall-clock
authority behavior, or HTTP connection-pool reuse. Successful Java runtime evidence
requires execution in the authorized disposable CI environment. Source inspection
or offline Python reporter tests alone are not runtime acceptance.
