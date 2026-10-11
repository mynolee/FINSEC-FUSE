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

This is an explicit operator sequence for a NEW standard local database, not an upgrade/reset procedure. Database access, migration, issuance and private configuration handoff each need their applicable approval. These documented commands do not authorize the assistant to operate an existing database.

Prerequisites are a non-root Linux/POSIX user, Bash, Python 3, Docker Engine and Compose. Host Java is not required for the container recipe. The supported UID/GID range for the token-admin image is 1–2147483646. Existing base files remain private and unchanged; the bootstrap bearer values do not carry authority.

```sh
./scripts/bootstrap-dev.sh
docker compose -f compose.yaml -f compose.admin.yaml build migration token-admin
docker compose up --detach --wait postgres
docker compose -f compose.yaml -f compose.admin.yaml run --rm --no-deps migration migrate-fresh --new-install
```

Keep applications and other administrators stopped during migration. The standalone Java main accepts only `migrate-fresh --new-install`. It uses existing explicit owner connectivity, fixed `classpath:db/migration`, the public schema and the seven packaged SQL migrations. It requires the standard `fuse` database owned by `fuse_owner`, with the bootstrap runtime role and exact per-schema default grants already present. Before any migration it rejects runtime superuser/elevated role membership, database/schema CREATE authority or ownership. It refuses unrelated user objects, previous history and nonempty/partial installations. No clean, repair, baseline, arbitrary migration locations, schema creation, upgrade or automatic retry is available. All connections have bounded connection/socket/lock/statement timeouts. A cooperative advisory lock coordinates this command, not arbitrary database administrators.

The command applies V1–V7 and exits without Spring, HTTP, schedulers, workers, provider/model clients, application startup recovery, demo seed or token issuance. V1's `execution_gate` row is a structural sentinel, not a seeded customer/workflow. A fixed `Migration COMPLETE` receipt requires confirmed migration and post-validation; it contains no connection details. A failure must not be treated as a rollback or successful setup.

After confirmed migration, separately approve issuance to a new private output:

```sh
mkdir -m 700 .secrets/auth-output
docker compose -f compose.yaml -f compose.admin.yaml run --rm --no-deps token-admin init-fresh --new-install --output /private-output/initial-tokens.env
python3 -c 'from pathlib import Path; import sys; ok=Path(".secrets/auth-output/initial-tokens.env").read_bytes().splitlines()[-1:]==[b"# status=COMMITTED"]; print("COMMITTED" if ok else "NOT_CONFIRMED"); sys.exit(0 if ok else 1)'
```

The output directory must be new, owner-owned and mode 0700. Compose must not create a missing bind directory. The token-admin image creates a real non-root passwd identity with the bootstrap UID/GID at build time, including when an image already contains that numeric identity. It mounts only the output directory. Its unchanged provisioner rejects symlinks, unsafe ownership and existing files; outputs are 0600 and exclusive. Do not run it as root, override its image user, relax permissions, display the credential file or pass credentials in arguments. Rebuild the image after an explicitly reviewed identity change.

`init-fresh` still requires empty migrated auth tables and generates fresh credentials for customers 101–104, reviewer, security operator, developer and KYC service. Scope declarations default to customers 101–104 and must match the backend. It never imports bootstrap/environment bearer values. Migration and issuance are separate invocations; neither command starts the other.

After success and a final COMMITTED marker, separately review and approve copying the required assignments into the intended private `.env` using a private editor. The PREPARED marker remains earlier in the file. Do not print the whole file to inspect its status. Preserve consistency of `FUSE_SERVICE_TOKEN` between backend and adapter. No operator command automatically edits an existing `.env`.

```sh
docker compose up --build --detach --wait
```

Check `/actuator/health/readiness` and the documented adapter readiness. The standard backend receives no main/auth migration-owner password. Its separate experiment-owner connection remains restricted to the distinct experiment database and existing owned sandbox code. Merely selecting the admin profile or starting either admin image without explicit operation arguments cannot initialize a database or issue authority.

### Runtime schema admission

The shipped `FuseApplication.main` installs a mandatory initializer after Spring prepares effective configuration and before context refresh, bean construction, server startup, seed or startup recovery. It cannot be disabled by profile, CLI or environment flags. It rejects effective Flyway migration, SQL initialization, main/auth owner credentials and alternative datasource URL/credential/schema/JNDI mechanisms. The actual runtime database, login/session identity and default schema must match the checked configuration. The first identity probe uses catalog-qualified functions and requires the effective schema search order to be exactly `pg_catalog,public`; a public-first explicit catalog path or other schema is rejected before contract queries.

Every validator connection is nonpooled and server-enforced read-only, including autocommit, with fixed timeouts. Validation requires the exact V1–V7 successful SQL history and packaged checksums, with no baseline, future, pending or unknown migration. It checks the enumerated public tables, validated primary-key presence, named enabled integrity triggers, function signatures, critical column names and runtime/auth/history privileges. It does not compare arbitrary DBA function bodies, column types or every unique/check/foreign-key definition. There is no fallback to migration, repair or a read/write validator.

V7 preserves V1–V6 and historical rows, revokes PUBLIC/runtime table and column mutation privileges on Flyway history and retains runtime SELECT. It operates in Flyway's current schema so owned custom-schema fixtures remain valid. The standard runtime has no role memberships or main-database/schema/object ownership. Custom roles require explicit privilege review and must meet this same contract.

The supported boundary is the shipped web main and its container. Trusted internal `ExperimentSandbox` and test builders deliberately do not invoke that main and retain their own owned disposable-database/schema setup. Their tests do not prove this product-main gate; shipped-jar and Compose process tests are required. Arbitrary external Java bootstrap code is outside this boundary.

### Fresh migration failures

Nonzero exit, process loss, lock-session loss or missing success receipt means NOT_CONFIRMED. No cleanup, repair, baseline, credential issuance or automatic retry follows. Preserve private diagnostics and inspect the approved database's history and state. Grouping transactional migrations does not prove that a failed attempt leaves no Flyway housekeeping objects. The fresh command refuses retained history/partial objects; a completely rolled-back or lost database cannot prove its earlier existence. A deliberate retry therefore requires prior reconciliation and renewed operator judgment even when the database appears empty.

Existing V6-or-earlier installations need a separately approved upgrade/backup procedure and migration tool before starting this web artifact. The fresh-only command intentionally cannot upgrade them. Do not remove history, delete tombstones or destroy a volume to make a migration or token operation succeed. For ordinary stop/restart, use `docker compose stop postgres agent backend frontend ingress`, then `docker compose start postgres agent backend frontend ingress`, followed by the README's bounded readiness check. This preserves existing containers and the named database volume. Compose 2.38.2 stops in reverse dependency order and starts in dependency order, observing the configured database/adapter health dependencies; its `start` command does not support `--wait` or `--wait-timeout`. The disposable CI oracle compares all five container IDs and the database volume name, creation metadata and mount binding across the stop and restart. Token issuance/expiry/revocation must survive unchanged.

### Replacement, revocation and scope

All commands below use the same standalone `DemoTokenProvisioner` and approved owner environment. The examples are an optional host-Java 21 route and require independently approved reachable database connectivity; the default Compose database is not published to the host. For the container route, use the token-admin service with the same operation arguments and a new `/private-output/` filename for every issuance. They do not start Spring, a web server, schedulers or demo seed. Their nonsecret selectors are actor IDs or lowercase 64-character SHA-256 fingerprints, never bearer tokens. Do not publish private output files.

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
