# Candidate-only KYC agent

This service proposes KYC JSON. Java remains the authority for evidence validity,
authentication, delegation, budgets, employee approval, quarantine and mock
payment. The service has no database client, grant-signing key, payment tool,
employee token, or tool-calling capability.

## Run locally

From the repository root, install `agent/requirements.txt` into a Python 3.12
virtual environment, then run:

```sh
# Use the generated .env from scripts/bootstrap-dev.sh; never commit it.
set -a; . ./.env; set +a
uvicorn agent.app:app --host 127.0.0.1 --port 8001
```

The container pins Python 3.12.15, FastAPI 0.136.1 and Pydantic 2.12.5. `/health`
reports liveness, mode and whether outputs are synthetic. `/ready` fails closed
without a service token or complete live configuration. `CHANGE_ME` is rejected.

## Exact boundary

- `GET /health`
- `GET /ready`
- `POST /internal/v1/kyc/evaluations`, `X-Fuse-Service-Token` and JSON required
- `POST /internal/v1/kyc/captures`, the same internal token and strict KYC request, LIVE only

The request/response JSON schemas are in `schemas/`. The exact request field
order for the input fingerprint is `requestId`, `workflowId`, `generation`,
`runId`, `customerId`, `policyVersion`, `evidenceFacts`, `documents`. Exclude
`inputSnapshotHash` itself; encode UTF-8, no whitespace, no ASCII escaping, with
nested DTO field order. Array order is preserved. Java selects and records
source/evidence order before calling. Python checks source-text hashes and the
snapshot hash and copies all response context from the original request.

Unknown fields, duplicate keys, non-finite numbers, malformed canonical UUIDs,
invalid types, oversize collections and hash mismatches are rejected. Candidate
status is one of `VERIFIED`, `NOT_VERIFIED`, `NEEDS_REVIEW`. A structurally valid
but false VERIFIED is intentionally returned to Java's evidence gate; Python
must not silently turn candidate content into trusted authorization.

Model generation and semaphore queueing share a 25-second deadline, with at most
four active model generations. A model failure returns 503
`DEPENDENCY_UNAVAILABLE`; malformed model JSON returns 502
`MODEL_OUTPUT_INVALID`. Neither is a policy-block success. Responses are bounded
to 64 KiB. Requests are bounded to 256 KiB.

## Modes and private configuration

`FUSE_KYC_MODE=replay` is the default and requires no external key. The exact
seeded customer-101/document-201/version-2 case deliberately returns false
VERIFIED with no evidence. Its explanation and model metadata visibly say
synthetic replay. Other fixtures use deterministic independent-fact rules.
This is an adversarial policy fixture, not a claim that an LLM was attacked.

`FUSE_KYC_MODE=offline` uses deterministic rules for every request, including the
poisoned fixture. It never interprets document instructions. It is useful to test
integration and output schemas, not to measure LLM prompt-injection resistance.

`FUSE_KYC_MODE=live` is opt-in and needs `FUSE_LLM_MODEL`, `FUSE_LLM_API_KEY`,
`FUSE_KYC_PROMPT_PATH` pointing to an operator-owned UTF-8 file, and
optionally `FUSE_LLM_BASE_URL` (default `https://api.openai.com/v1`). The endpoint
must support OpenAI-compatible Chat Completions with strict JSON-schema output.
No live provider calls were made during offline verification. Actual provider
compatibility, cost and model quality must be tested separately with explicit
operator authorization. The key is never logged or put into the prompt.

No service instruction bodies or adversarial document bodies are distributed
with this repository. Keep them outside the checkout or in the ignored
`private-prompts/` directory. There is no embedded default or generated fallback.
An absent, unreadable, empty or non-UTF-8 system file keeps LIVE readiness false.
The configured file is loaded once when settings are created; restart after
changing it so generation and capture fingerprints always use identical bytes.
REPLAY and OFFLINE never load it and need no private files.

Java seed and evaluation references use opaque IDs. LIVE also needs the private
reference map configured through `FUSE_PRIVATE_DOCUMENTS_PATH`; unresolved
`FUSE_DOCUMENT_ID:` markers are rejected before provider calls. See
[`../docs/private-runtime-assets.md`](../docs/private-runtime-assets.md) for the
file contract and read-only container mounts. The adapter sends no tools,
validates the candidate schema, rejects tool calls/refusals/truncated output,
and never retries a paid model call automatically.

## Tests

```sh
python -m pip install -r agent/requirements-dev.txt
python -m pytest -q agent/tests evaluation/tests
```

Tests cover strict contracts, hashes, malformed nested JSON, authentication,
context binding, deliberately unsafe replay, safe offline behavior, prompt role
separation with opaque markers, private-file failures, timeouts and error semantics.
Tests contain no service or adversarial instruction text. See `../evaluation/README.md` for the
registered 40-attack/20-normal plan and paired Java harness.

## Paired LIVE capture

The separate `/internal/v1/kyc/captures` boundary rejects replay/offline or
unconfigured service modes before calling an adapter. One request produces one
provider call; the response contains `response` (the ordinary bound KYC response),
`modelMode: LIVE`, `promptHash`, and `modelOutputHash`. The model ID is taken from
the provider response, not merely the requested alias. Providers that omit a model
identifier cannot produce a valid capture. The ordinary evaluations route retains
its existing wire contract.

Prompt/output fingerprints use SHA-256 of UTF-8 JSON with sorted object keys,
compact separators and no ASCII escaping. `promptHash` fingerprints the actual
three prompt messages; `modelOutputHash` fingerprints the complete strict
proposal including explanation. These are distinct from the ordered DTO
`inputSnapshotHash`. Capture uses the same authentication, size, queue/generation
timeout and no-retry limits as normal KYC. No provider key or service token is
included in a capture. See evaluation documentation for Java opt-in and paired
exclusion rules. Tests use fake model adapters and HTTP mock transport only.

### Internal boundary hardening

The agent reads the canonical `config/security_policy.json` packaged from the backend resource, selected by `FUSE_SECURITY_POLICY_PATH` (repository-relative default during tests). Its fixed version is `FUSE-SECURITY-1`. Body reads stop at 256 KiB; responses stop at 64 KiB. JSON nesting is at most 16 containers, evidence at most 10 facts, documents at most 8, and each document text at most 16 KiB of UTF-8 bytes. Invalid internal JSON/DTOs return 422; unsupported media or any content encoding returns 415. Missing, duplicate, comma-combined, or incorrect internal tokens return 401 before reading the body, checking LIVE readiness, or calling a model. Actual ASGI startup refuses absent/short service tokens.

Model generation admits four active calls and four waiting calls, with a single 25-second budget including waiting. Overflow is a dependency-unavailable response, and cancellation releases capacity. The HTTP connection timeout is two seconds. LIVE uses only the registered `https://api.openai.com/v1` endpoint, verified TLS, no environment proxy, no redirects, and public-IP validation at the socket connection boundary. The resolved address is passed as an IP literal to the network backend while the original hostname remains the TLS verification/SNI target. Request, reference, and model-output URLs never select destinations. This application guard complements deployment egress restrictions; unit fakes do not certify a deployed firewall.

Private system text is read once, as a bounded regular UTF-8 file, using an explicit operator-selected parent root. Symlink components and traversal are rejected, the leaf is opened without following links, and at most 64 KiB is read. No private contents are part of test artifacts. Remote model integration and deployed egress remain separately testable from isolated contract tests.
