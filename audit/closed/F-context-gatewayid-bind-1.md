# F-context-gatewayid-bind-1: decision context binds session_id but not gateway_id
- Severity: info
- Status: Accepted-Risk
- Area: decisionctx

## Observation (T3: redteam + security)
The verifier binds `context.session_id == self.session_id` (anti-replay / anti-misroute)
but does not additionally compare the signed `context.gateway_id` to the Gateway's own id.

## Disposition — Accepted-Risk (sufficient; cheap belt-and-suspenders noted)
The `session_id` is a fresh 128-bit random value the Gateway allocated and the CP echoes
back inside the SIGNED context, delivered over the pinned mTLS channel — a context minted
for a different session/gateway carries a different session_id and is rejected. Adding the
`gateway_id` comparison is cheap defense-in-depth (per the S5 model) but not required; the
session_id binding is sufficient anti-replay. Noted for a future hardening pass.
