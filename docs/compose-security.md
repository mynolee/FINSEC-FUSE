# Compose isolation and verification

This is the local mock-finance demo topology. The configuration is not a
production deployment certification or evidence that Docker networking was
executed successfully. The commands below must be tested on the target Engine
and Compose versions before relying on their runtime behavior.

## Default REPLAY boundary

`docker compose up --build` uses three explicit internal bridge networks:

- `web`: frontend and backend only
- `data`: backend and PostgreSQL only
- `kyc`: backend and Python adapter only

The frontend can resolve `backend:8080`; the backend can resolve
`postgres:5432` and `agent:8001`. The adapter and frontend do not join the
database bridge or each other's bridge. The backend is the shared trust
boundary. Networks are bidirectional, so this is service segmentation, not a
directional HTTP firewall. Python still needs service authentication, and the
public API must still reject its service identity.

Only `127.0.0.1:5173` and `127.0.0.1:8080` are published. Python and PostgreSQL
have no host port in the default stack. Check Python readiness inside its
container:

```sh
docker compose exec -T agent python -c \
  'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8001/ready", timeout=2).status)'
```

For explicitly requested local debugging, add `compose.dev.yaml`. It exposes
only the loopback adapter and database ports and does not add external routing:

```sh
docker compose -f compose.yaml -f compose.dev.yaml up --build
```

Do not use that debugging override on a shared deployment. Browser clients use
the frontend `/api/` route and never need direct Python access. The standalone
non-Docker development workflow is unaffected by these Compose files.

REPLAY is literal in the base file, as is disabled LIVE experimentation.
Ambient `.env` model keys and mode changes do not turn it into LIVE. Each
service receives an explicit configuration allowlist; `.env` is not wholesale
injected into any container. The provider key is absent from Java, PostgreSQL,
and the frontend. Python receives neither DB/staff credentials nor signing
material. Java still receives the migration credential because this demo
runs Flyway at startup; the runtime DB identity remains `fuse_runtime`.
Separating migration into a one-shot identity is outside this Compose change.

## Process and filesystem limits

All four services declare a non-root identity, drop all Linux capabilities,
enable `no-new-privileges`, and use a read-only root filesystem. Explicit,
size-bounded `/tmp` tmpfs mounts support runtime temporary files. PostgreSQL
also has a temporary socket directory and its existing named data volume.
The DB initialization script is a read-only single-file mount. Container
process counts and local log rotation are bounded in the configuration.

Source compatibility review: the official
[PostgreSQL 16 image](https://github.com/docker-library/postgres/blob/master/16/trixie/Dockerfile)
creates a `postgres`-owned data directory and supports starting as that user.
A fresh named volume normally inherits the image directory ownership; existing
or externally provisioned volumes must already have appropriate ownership.
The socket tmpfs remains writable by the non-root process. The upstream
[unprivileged nginx image template](https://github.com/nginx/docker-nginx-unprivileged/blob/main/Dockerfile-alpine-slim.template)
uses UID/GID 101, a `/tmp` PID file, and `/tmp` request/proxy temporary paths.
The project adds only a server block. Runtime Java dependencies currently use
PostgreSQL JDBC without application native-library extraction; embedded
PostgreSQL is test-only. Recheck the `/tmp` `noexec` assumption when adding
JNI/native dependencies. These source observations do not prove image startup.

The backend uses the nonzero host UID/GID recorded by bootstrap so a local
Compose file-backed secret can remain owner-readable only (0600). Compose
bind-backed secrets do not provide ownership remapping. Do not relax the key
mode to make startup succeed. If using user-namespace remapping, rootless
Docker, or a different volume implementation, verify the actual container
ownership/readability; fail closed when the key is unreadable. Keep existing
database volumes: a permission/startup problem never authorizes deleting
stored data or enabling a privileged container.

Docker administrators and the host are trusted. Internal bridge networks do
not isolate a service from a malicious host, remove all host reachability,
or create DNS/domain/path allowlists. Published loopback isolation also depends
on the target Engine, host firewall, and routing configuration. See the Docker
[network declaration](https://docs.docker.com/reference/compose-file/networks/),
[bridge isolation](https://docs.docker.com/engine/network/drivers/bridge/), and
[service configuration](https://docs.docker.com/reference/compose-file/services/) documentation.

## Explicit LIVE egress prerequisite

`compose.live.yaml` attaches only the adapter to an already-existing network
named by `FUSE_LIVE_EGRESS_NETWORK`. Missing configuration or a nonexistent
network fails rather than automatically creating a general Internet bridge.
The name is an operator reference, not proof of filtering. Do not point it at
an unrestricted bridge and call that approved egress.

Before enabling LIVE, the operator must provision and independently verify a
default-deny egress boundary for that network. Permit the approved resolver
and TLS connections only to the approved model endpoint, currently
`https://api.openai.com:443/v1/chat/completions`. Block metadata, link-local,
arbitrary private/loopback destinations, unrelated public destinations, and
IPv6 bypasses. DNS changes must update a validated address policy without
opening a broad destination range. The existing internal `kyc` exception is
separate from that provider egress rule. The model transport ignores ambient
HTTP proxy variables; setting `HTTPS_PROXY` does not establish this boundary.
Use an enforcement method compatible with direct, certificate-verified TLS,
such as a managed egress gateway or host/network firewall. Network-layer
filters cannot enforce an HTTPS path: the fixed application endpoint and
verified TLS provide that part of the boundary.

No firewall, resolver, gateway, or destination allowlist is provisioned by
these files. Do not enable LIVE until that infrastructure and the negative
connection tests below have evidence. Setting a network name is insufficient
for the SSRF/egress acceptance claim. The adapter's application-layer exact
origin, DNS address validation, redirect rejection, and TLS verification
remain necessary even with network enforcement.

After that verification and separate approval for provider transmission/cost,
set the provider configuration and private file paths in the untracked local
environment. Use a separately initialized LIVE demo database as described in
[private runtime assets](private-runtime-assets.md), then explicitly combine:

```sh
docker compose -f compose.yaml -f compose.live.yaml -f compose.private.yaml up --build
```

`compose.private.yaml` by itself adds read-only files and never enables LIVE
or Internet access. LIVE adds no host ports and leaves Java, PostgreSQL, and
the frontend on internal networks. Do not include `compose.dev.yaml` in the
LIVE command.

## Verification and evidence limits

Run the source-level regression suite with PyYAML from the security lockfile:

```sh
python3 scripts/compose-security-test.py
```

It checks topology declarations, forbidden host/network privilege shortcuts,
exact internal routes, port exposure, configuration/secret boundaries,
bounded writable mounts, LIVE prerequisites, and negative configuration
mutations. It does not emulate Compose interpolation or merge behavior and
does not open any network connection, read private files, or call a provider.

On a Docker-enabled isolated test host, separately collect:

1. `docker compose config --quiet` for base, developer, and approved LIVE
   combinations. Do not publish rendered environment/secret configuration.
2. Fresh-volume startup, existing-volume restart, container nonzero UIDs,
   root filesystem write denial, capabilities, and signing-key 0600 ownership.
3. Actual frontend-to-backend and backend-to-agent/DB health plus a normal
   authenticated replay workflow. Confirm no model call and no hidden host
   Python or DB listener in the base stack.
4. Connection denials from adapter to DB and frontend; frontend to DB and
   adapter; and every base service to unapproved external destinations.
   Include host-gateway, metadata, link-local and IPv4/IPv6 paths where
   applicable. Record host/platform behavior rather than assuming isolation.
5. For LIVE, endpoint success under an explicitly authorized call, unrelated
   destinations denied by the network independently of the application, DNS
   rebinding/redirect rejection, and no credential forwarding. Record exact
   enforcement rules and the source revision without secrets or private text.

Without those observations, actual network isolation, LIVE egress filtering,
and container startup remain **NOT_RUN**, even when all static checks pass.
