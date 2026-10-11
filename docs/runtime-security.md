# Runtime security controls

The server requires an explicit `demo` or `test` profile for development capabilities. Normal profiles reject demo seed, experiments, test-hook flags, mock automatic approval, replay mode and development token registry configuration. Combining a development profile with another profile fails startup. Normal runtime defaults to live KYC; this is still a mock financial system, not production banking authorization.

Signing material is loaded only from operator-configured regular files, with POSIX permissions exactly 0600, size 32–4096 bytes and no placeholder. Unsupported filesystem permission validation fails closed. Windows private-ACL support has not been implemented; startup there is not certified. Only isolated `test` may generate an ephemeral CSPRNG key. Service-token strength is checked before workers become eligible to poll.

`FUSE_SIGNING_KEY_ID` and `FUSE_SIGNING_KEY_PATH` select the single issuing key. `FUSE_VERIFY_KEYS` optionally registers comma-separated `kid:VERIFY_ONLY:/private/path` or `kid:REVOKED:/private/path` entries. IDs are fixed identifiers, never client-selected paths. During a planned rotation retain the old key as VERIFY_ONLY for at least the maximum existing Grant TTL (60 seconds in the current policy); afterward remove or revoke it. Compromise requires immediate REVOKED status and process restart with the new registry. Rotation changes verification of new executions, not historical payment receipts. Keys and token bytes must not be published.

Admission counts PENDING durable jobs under the existing execution gate in the caller's transaction. At 1000 queued jobs it throws 429 RATE_LIMITED; transaction rollback removes all partially created application, workflow and action rows. RUNNING jobs do not count as queued. Model concurrency remains four.

Each pooled PostgreSQL connection sets lock_timeout=2s and statement_timeout=5s. Existing retries permit at most two retries only for known rolled-back lock/deadlock failures, using the same operation closure. Other database failures, including unknown commit outcomes, are not retried automatically. Integration race tests requiring a longer barrier window must declare a test-only override and must not claim it is the normal runtime limit.

Actuator exposes health only with details disabled. Scheduled workers check the required agent registry/policy/key readiness before claiming jobs. Tests verify actual PostgreSQL timeout SQLSTATEs, queue rollback and slot reuse, exact decoded Grant limits and key rotation/revocation. Recorded test execution results remain separate from this implementation description.

## Developer Compose private key ownership

Linux Compose file-backed secrets retain host ownership; declaring secret `uid` or `mode` does not reliably materialize a differently owned private file. The developer bootstrap now records the invoking user's nonzero UID and primary GID in the untracked environment file. Compose uses that identity for the backend JVM, so the host-owned 0600 key is readable without a root entrypoint, additional capabilities, world-readable permissions or a writable image filesystem. Standalone images still default to UID/GID 10001.

Run bootstrap as a non-root developer. It creates only new private base files, exclusively, and preserves a valid existing configuration byte-for-byte. Legacy 0444 keys, symlinks, incorrect ownership, partial configurations or missing/mismatched runtime identity fields fail with an instruction to review the existing files. It never silently changes existing permissions or regenerates credentials. For an older private-file layout, the owner must review and restore key/environment mode 0600 and directory mode 0700, and add the current non-root `FUSE_RUNTIME_UID` / `FUSE_RUNTIME_GID` values to their private environment file. Do not publish these generated files. Rootless Docker with user-namespace remapping may use different effective ownership; that configuration requires separate runtime validation rather than relaxing the key permissions.

`python3 scripts/bootstrap-dev-test.py` exercises private-file creation, preservation, failure paths and setup guidance only in disposable synthetic directories. It neither provisions database authority nor certifies Docker startup.

## Durable demo bearer authority

Demo/test bearer authority is stored in PostgreSQL. `V6__durable_demo_tokens.sql` creates `demo_auth_registry` and `demo_token`; it does not initialize a registry or issue credentials. The web application's token store is read-only. Startup, health checks, seed data and authentication never import environment values, create missing records or refresh a token.

Each generated token is identified by the SHA-256 fingerprint of its exact UTF-8 bytes. Database records contain that fingerprint, identity, original configured scope, current scope, issuance/expiry, revocation state and revision. Raw bearer bytes are not stored in those tables. The original identity, configured scope and timestamps cannot be rewritten; expired and revoked records remain. A token admits requests only while ACTIVE and `issued_at <= database_time < expires_at`, with a 7,200-second lifetime. Signing-key rotation does not change this fingerprint or lifetime.

Environment token declarations check the original binding; they do not supply the current scope. A narrower stored scope remains effective after a restart even when the original broad scope is still configured. Explicit scope replacement can widen or narrow the current scope without renewing a credential or undoing revocation. A committed change is visible to a subsequent admission lookup; this does not cancel a request already admitted before that change.

An expired or revoked credential returns 401 `UNAUTHENTICATED`; a service identity retains the public-route 403 restriction. Missing or unavailable authority, incompatible records and mismatched configured bindings make readiness DOWN and reject admission with sanitized 503 `DEPENDENCY_UNAVAILABLE` / `decision: ERROR`. These failures do not run controller work or repair the ledger. An expired historical binding alone does not make the whole ledger unready.

The migration removes mutation privileges from the standard `fuse_runtime` role on these tables and retains SELECT access. Installations with a differently named runtime role need an explicit privilege review. The standalone administrator uses existing approved owner connectivity; it does not add a management endpoint, web component or persistent access credential.

### First installation

This is a manual operational sequence. Applying migrations, using owner connectivity, issuing credentials and replacing private configuration each require the operator's applicable approval. The bootstrap and Compose commands do not perform token administration.

1. As a non-root developer, run `./scripts/bootstrap-dev.sh` to prepare private base configuration and the signing key. Its generated bearer values have no durable authority. An existing valid `.env` and key are preserved byte-for-byte.
2. Prepare the database connection and apply the repository migrations through `V6__durable_demo_tokens.sql` with separately approved migration tooling. This repository does not provide an offline migrate-only command. Do this before normal backend startup; the token provisioner requires the migrated tables and does not run Flyway or application services.
3. Provide `FUSE_DB_URL`, `FUSE_MIGRATION_USERNAME` and `FUSE_MIGRATION_PASSWORD` to the short-lived provisioner through an approved private environment. It does not load `.env`. Keep Gradle debug/environment tracing disabled and use `--no-daemon` so this administrative invocation does not reuse a persistent build daemon. Never put passwords or bearer values in command arguments, shell history, logs or reports. Use a reachable database address for this process; the default Compose database has no published host port.
4. Run the provisioner as a non-root owner. Choose an absolute normalized path for a new output file under an existing owner-owned directory with mode 0700. The output must not already exist. Symlinks and unsafe permissions are rejected; the new credential file is mode 0600. The following example assumes that `/private/fuse-auth` has already been prepared by the operator:

```sh
./gradlew --no-daemon demoTokenProvision --args='init-fresh --new-install --output /private/fuse-auth/initial-tokens.env'
```

`init-fresh` requires empty migrated auth tables. It creates fresh credentials for customers 101–104, the reviewer, security operator, developer and KYC service. Reviewer/security initial scopes use `FUSE_REVIEWER_CUSTOMERS` / `FUSE_SECURITY_CUSTOMERS`, defaulting to customers 101–104; keep those declarations consistent with the backend configuration. Existing bearer environment values are never imported.

5. Confirm the process reports success and the private output's final status marker is COMMITTED. The earlier PREPARED marker remains in the file. The output contains the operation ID, fingerprints and generated environment assignments. Do not display or paste the whole file to inspect its status. Separately review and approve copying the required assignments into the intended private runtime configuration. The provisioner never edits an existing `.env` or secret file. The `FUSE_SERVICE_TOKEN` handoff must remain consistent between the backend and the KYC adapter.
6. Start the normal services with `docker compose up --build` and check `/actuator/health/readiness`. There is no Compose provisioning service or startup retry that creates authority. Issuance time starts when the database issues the token, before this configuration handoff and startup.

### Replacement, revocation and scope

All commands below use the same standalone `DemoTokenProvisioner` and approved owner environment. They do not start Spring, a web server, schedulers or demo seed. Their nonsecret selectors are actor IDs or lowercase 64-character SHA-256 fingerprints, never bearer tokens. Do not publish private output files.

To issue an additional credential:

```sh
./gradlew --no-daemon demoTokenProvision --args='issue-fresh --actor staff-01 --role LOAN_REVIEWER --scope customer-101,customer-102 --output /private/fuse-auth/additional-reviewer.env'
```

This leaves previous credentials active. For replacement, add `--replace` followed by a comma-separated list of previous fingerprints to the same `issue-fresh` operation. It issues the new credential and revokes the selected old credentials in one transaction. Removing or changing an environment token does not revoke its durable record. Review the selectors before approval, and account for the interval between database replacement and the separate configuration handoff.

`issue-fresh` writes a generic `FUSE_FRESH_TOKEN` assignment with identity and fingerprint receipt metadata. The operator must choose the intended runtime role slot or authorized client handoff; merely adding that generic name to `.env` does not configure a predefined role slot. Use a new output path for every issuance. A failed or uncertain operation is not permission to retry with a new lifetime.

To revoke all credentials for an actor, or replace their current customer scope:

```sh
./gradlew --no-daemon demoTokenProvision --args='revoke --actor staff-01'
./gradlew --no-daemon demoTokenProvision --args='update-scope --actor staff-01 --scope customer-101'
```

For one credential, use `revoke --fingerprint` with its recorded fingerprint instead of `--actor`. Repeated revocation is idempotent. Scope replacement applies to existing actor credentials, never creates a missing row and does not change original issuance, expiry or revocation. The empty scope is supported as an explicitly empty argument. Backend environment scope declarations continue to describe the original configured binding, not later scope changes.

### Upgrade compatibility

The earlier in-memory registry has no authoritative issuance, expiry or revocation history to migrate. Old environment tokens cannot be safely assigned a new issuance history, so upgrade does not import them as active credentials. Choose explicit fresh issuance and a reviewed configuration handoff. Reusing file timestamps or process uptime as issuance evidence is not supported. A different historical migration source would need separate review.

After the tables exist but before explicit initialization, the backend remains unready. Restarting it, rerunning bootstrap or replacing its signing key cannot initialize bearer authority. Preserve old lifecycle records when the durable ledger already exists; do not reset it to refresh access.

### Recovery and uncertain results

An issuance output is first marked PREPARED; a final COMMITTED marker is appended only after the database commit is acknowledged. Output or commit failure must not be reported as successful issuance. An uncertain result can leave only a PREPARED marker even when the database transaction committed. Retain that private file and use its nonsecret operation ID and fingerprints with an approved owner-side review to reconcile the result. Do not retry issuance automatically, overwrite the file, delete tombstones or reuse an old bearer with a new expiry.

If a table, registry marker or configured token row disappears, admission remains closed. Restore a consistent authoritative backup, or explicitly choose a new installation with fresh credentials and a separate configuration handoff. Never treat missing state as a request to initialize it. `init-fresh --new-install` expresses that deliberate choice; a completely lost database cannot identify its own prior existence. This feature does not detect stale backup rollback or correct a materially wrong database clock.

These sections describe implementation and operator prerequisites. They are not evidence that a database migration, credential handoff, Docker startup, PostgreSQL persistence test or true process-restart test has been executed for this change.
