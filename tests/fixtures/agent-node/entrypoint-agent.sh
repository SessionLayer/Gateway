#!/bin/sh
# Start the node's Agent (non-root, FR-CONN-6) then hand off to the sshd entrypoint.
#
# The Agent runs as `deploy`, so it cannot read /etc/ssh/ssh_host_*_key: spoofing this
# node's host identity requires node-ROOT compromise, which is exactly why the agent
# model raises rather than lowers the host-verification bar (Design §9.3). It dials OUT
# and splices to 127.0.0.1:22 — an address it reads from its own configuration, never
# from the wire.
set -eu

if [ -n "${AGENT_ENDPOINT:-}" ] && [ -f /agent/test-agent ]; then
	chmod 0755 /agent/test-agent
	chown -R deploy /agent
	# It retries with backoff, so starting before sshd is listening is fine.
	su deploy -s /bin/sh -c "RUST_LOG=${AGENT_LOG:-info} exec /agent/test-agent \
		--endpoint '${AGENT_ENDPOINT}' \
		--server-name '${AGENT_SERVER_NAME}' \
		--ca /agent/ca.pem \
		--cert /agent/agent.pem \
		--key /agent/agent.key \
		--node-name '${AGENT_NODE_NAME}' \
		--splice-addr 127.0.0.1:22" >/agent/agent.log 2>&1 &
fi

exec /usr/local/bin/entrypoint.sh "$@"
