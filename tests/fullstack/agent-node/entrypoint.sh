#!/bin/sh
# Full-stack agent-node entrypoint: start the REAL Agent binary (non-root, real enrollment via a
# join token against the real CP) then hand off to the sshd entrypoint. The agent binary + the
# bootstrap CA are docker-cp'd into /agent by run.sh; the join token + endpoints come from env.
#
# The agent runs as `deploy` (non-root, FR-CONN-6 / Design §9.3): it therefore CANNOT read the
# node host key, so host identity is anchored out-of-band (run.sh ssh-keyscans the node's own key
# and registers it as the pinned host anchor). It dials OUT to the Gateway's agent transport and
# splices each dial-back to THIS container's own 127.0.0.1:22 (an address it reads from its own
# config, never from the wire).
set -eu

if [ -n "${AGENT_JOIN_TOKEN:-}" ] && [ -x /agent/sessionlayer-agent ]; then
	chown -R deploy /agent 2>/dev/null || true
	# Retries with backoff, so starting before sshd is listening is fine.
	su deploy -s /bin/sh -c "RUST_LOG=${AGENT_LOG:-info} exec /agent/sessionlayer-agent run \
		--node-name '${AGENT_NODE_NAME}' \
		--join-method token --join-token '${AGENT_JOIN_TOKEN}' \
		--cp-endpoint '${AGENT_CP_ENDPOINT}' \
		--cp-server-name '${AGENT_CP_SERVER_NAME:-controlplane}' \
		--bootstrap-ca-file /agent/ca.pem \
		--gateway-endpoint '${AGENT_GATEWAY_ENDPOINT}' \
		--gateway-server-name '${AGENT_GATEWAY_SERVER_NAME}' \
		--splice-addr 127.0.0.1:22 \
		--data-dir /agent/data" >/agent/agent.log 2>&1 &
fi

exec /usr/local/bin/entrypoint.sh "$@"
