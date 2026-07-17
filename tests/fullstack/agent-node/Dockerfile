# Full-stack agent-node: the shared sshd node fixture + the REAL Agent binary running the real
# enrollment flow (distinct from the per-repo tests/fixtures/agent-node, which injects a
# pre-issued identity). The Agent binary + bootstrap CA + join token are supplied at run time.
ARG NODE_IMAGE=sessionlayer-gw-fullstack-node:s20
FROM ${NODE_IMAGE}

COPY entrypoint.sh /usr/local/bin/fs-agent-entrypoint.sh
RUN chmod +x /usr/local/bin/fs-agent-entrypoint.sh \
 && mkdir -p /agent \
 && chown deploy /agent

ENTRYPOINT ["/usr/local/bin/fs-agent-entrypoint.sh"]
