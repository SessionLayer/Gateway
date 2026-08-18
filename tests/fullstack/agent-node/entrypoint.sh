#!/bin/sh
# The agent binary + bootstrap CA are docker-cp'd into /agent by run.sh; the join token
# and endpoints come from env.
#
# The agent runs as `deploy` (non-root): it therefore CANNOT read the node host key, so
# host identity is anchored out-of-band (run.sh generates the key, places it in the
# container before start, and registers it as the pinned host anchor). It dials OUT and
# splices each dial-back to AGENT_SPLICE_ADDR - an address it reads from its OWN config,
# never from the wire. The default is this container's own :22; run.sh overrides it with
# the port it started this node's sshd on, so the splice target is one the harness
# created rather than whatever happens to answer on 22.
set -eu

if [ -n "${AGENT_JOIN_TOKEN:-}" ] && [ -x /agent/sessionlayer-agent ]; then
	# The data-dir must exist BEFORE the agent starts: Tier-0 hardening opens it to build
	# the Landlock ruleset, and a missing directory aborts the agent at startup rather
	# than being created on demand.
	mkdir -p /agent/data
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
		--splice-addr "${AGENT_SPLICE_ADDR:-127.0.0.1:22}" \
		--data-dir /agent/data" >/agent/agent.log 2>&1 &
fi

exec /usr/local/bin/entrypoint.sh "$@"
