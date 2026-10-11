# Private runtime assets

Public source contains file-loading code, opaque fixture IDs, schemas, and
setup instructions only. Service instruction bodies, reference instruction
bodies, and personal agent settings must remain outside Git. The ignored
`private-prompts/` directory is available for local storage; storing files
outside the checkout is also supported. No private contents belong in tests,
README examples, container image layers, CI variables printed to logs, or
published evaluation artifacts.

## REPLAY and OFFLINE

The default modes work without private files. Reference documents contain
opaque `FUSE_DOCUMENT_ID:` markers and candidates are synthetic. These modes
check contracts and policy behavior; they do not measure private instructions
or live-model robustness. Public tests use opaque, non-instruction markers.

## Explicit LIVE setup

Provide these files yourself and configure their paths in an untracked `.env`:

- `FUSE_KYC_PROMPT_PATH`: a nonempty UTF-8 system instruction file for Python.
  No default body is bundled. Invalid configuration fails LIVE readiness.
  Python snapshots the file at startup; restart it after editing the file.
- `FUSE_PRIVATE_DOCUMENTS_PATH`: a UTF-8 JSON object mapping opaque IDs to
  nonempty text values (maximum 65,536 characters each and 1 MiB per file). Required IDs for the
  complete built-in set are `seed-v1`, `seed-v2`, `reference-default`, and
  `rag-01` through `rag-05`. No body examples are included. Java uses the seed
  and RAG IDs; the Python audit also uses `reference-default`.

Existing LIVE provider configuration and explicit cost authorization are still
required. Neither file path enables LIVE by itself. Java LIVE references are
resolved before input/content hashing. Missing or invalid reference data is an
unavailable dependency, never a successful security block. Python refuses
unresolved reference markers before making a provider request. Do not relabel
existing replay documents or historical replay reports as LIVE evidence.
Seeded source versions are immutable: changing environment variables does not
replace reference content in an existing database. Use a separately initialized
LIVE demo database with the private files present; do not erase an existing
database merely to switch modes. The paired experiment harness creates its own
private-resolved source versions in disposable schemas.

For direct local processes, use paths readable by their runtime users. No
private file needs to be copied into the source tree. For containers, set the
two variables to absolute host file paths. First provision and independently
verify the restricted-egress network described in
[Compose security](compose-security.md#explicit-live-egress-prerequisite), and
set `FUSE_LIVE_EGRESS_NETWORK` to that already-existing network. Merely naming
an external Docker network does not enforce approved destinations.

After that prerequisite and separate approval for external transmission/cost,
explicitly combine the LIVE overlay with the read-only private mounts:

```sh
docker compose -f compose.yaml -f compose.live.yaml -f compose.private.yaml up --build
```

The private override mounts only the system file into Python and only the
reference map into Java. Missing host files fail instead of creating empty
directories. That override by itself never enables LIVE or external routing.
The default `compose.yaml` has no private mounts and is fixed to REPLAY;
setting mode or provider keys in `.env` alone does not enable LIVE. Private
directories are excluded from the Docker build context. Ensure each file is
readable by the container service user without granting broader access.
The default stack publishes only loopback UI/backend ports; Python readiness
is checked inside its container, as shown in the Compose security document.

## Verification and provenance

```sh
python -m pytest -q agent/tests evaluation/tests
python -m evaluation.scenario_runner validate-fixtures
```

These checks use no provider and require no real private bodies. Generated
fixture hashes changed when inline text was replaced by IDs; old execution
reports do not verify the current fixture set. Regenerate measurements against
the current tree rather than copying old successes. Reports and logs remain
local because model explanations may reproduce private input text.
