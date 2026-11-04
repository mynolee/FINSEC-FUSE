# Explicit virtual HTTP registration

`VirtualHttpApplication` registers the supplied virtual product graph in a dedicated, unstarted servlet context. It does not implement the missing production `FuseApplication`, start a listener, connect a database, run migrations, seed data, issue credentials or schedule workers.

Construction requires explicit local transport configuration, `VirtualProductAssembly.Inputs`, readiness authorization and a current dependency-availability callback. There are no default identities, catalog, policy values or permissive authorities. The only accepted listener address for this adapter is literal `127.0.0.1`; its port, internal readiness path, HTTP limits, read timeout and concurrent-request limit are supplied by the caller. Graph HTTP limits must match the host configuration.

Construction delegates to the existing product graph and may call the supplied evaluator's `mode()` contract; it does not invoke `evaluate()` or open a listener. Injected callbacks remain trusted application dependencies and are not an OS sandbox.

Call `register(context, containerBinding)` only for a new, empty servlet context. The mandatory container binding must verify the actual address/port, header/body bounds, read timeout and concurrent-request admission on the caller-owned container before registration. This adapter cannot enforce transport properties through the standard ServletContext API. The binding must throw if the container does not satisfy them and must not start the listener. A caller must separately integrate and start a real container; no listener integration is supplied here. Registration failure requires discarding that context, and the adapter permits only one registration attempt.

A successful callback return is a caller-supplied contract assertion, not independent socket or transport-enforcement proof. The authored registration tests exercise registration calls with a mock ServletContext; they do not initialize the DispatcherServlet or verify a running MVC/container graph.

Registration explicitly installs both graph controllers, fixed public exception advice, MVC configuration without component scanning, the exact readiness servlet and the graph's mode/request filters in that order for synchronous requests. It enables no broad Boot, JDBC, Flyway or actuator configuration. The caller owns container shutdown and disposal of initialized servlet contexts.

Readiness authenticates with the supplied callback before checking availability. Missing identity yields 401, denied access 403, unavailable dependencies or callback failure 503. Authorized GET without query/body returns `{"ready":true,"executionMode":"VIRTUAL_SIMULATION","productionReady":false}` only when the explicit availability callback succeeds. This callback must reflect current required synthetic dependencies; it must not claim real auth, database or model readiness. Responses use fixed errors and `Cache-Control: no-store`. Availability is a contract supplied by the application owner, not an OS isolation measurement.

The existing virtual services continue to reject LIVE operation without a fallback. Real provider or database adapters require separate implementations; do not label them synthetic to use these ports.

## Virtual experiment cancellation

The virtual controller exposes `POST /experiments/{experimentId}/cancel` with an empty JSON object and the existing canonical UUID `Idempotency-Key`. The current EXPERIMENT authorization and exact stored experiment owner are checked before mutation or replay disclosure; no new role or default identity is introduced. Matching completed actions replay their bound receipt. Conflicting action identities retain the existing invalid-request behavior, while a pending or competing experiment advance returns fixed 503 rather than evaluating twice.

Cancellation terminalizes nonterminal experiment work as `CANCELLED` and fences late evaluation results. Already committed pairs, exclusions and completed-pair counts remain intact; a final `COMPLETED` experiment remains completed. Evaluator calls occur outside the store transaction. Cancellation does not interrupt or terminate the provider, enforce a timeout or reclaim an abandoned claim automatically. Pending claims require an explicit authorized owner cancellation; no worker or HTTP advance endpoint is added.

GET experiment responses omit the stored owner (`actorId`), active claim and fence. Cancel receipts report the current terminal status and committed-pair count; discarded evaluation does not become a successful observation. This is a virtual source contract, not evidence of a running listener, cancellation responsiveness or successful integration tests.
