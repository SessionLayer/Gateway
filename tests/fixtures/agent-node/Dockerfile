# The ordinary test node (real Debian 13 sshd) plus a **non-root Agent** that dials OUT
# to the Gateway and splices each dial-back to this container's own 127.0.0.1:22, so the
# node needs ZERO inbound reachability.
#
# The Agent binary and its mTLS identity are injected at run time; this image only knows
# how to start it. Base: the shared sshd fixture (tests/fixtures/sshd), built first by
# the test.
ARG NODE_IMAGE=sessionlayer-gw-testnode:test
FROM ${NODE_IMAGE}

COPY entrypoint-agent.sh /usr/local/bin/entrypoint-agent.sh
RUN chmod +x /usr/local/bin/entrypoint-agent.sh \
 && mkdir -p /agent \
 && chown deploy /agent

ENTRYPOINT ["/usr/local/bin/entrypoint-agent.sh"]
