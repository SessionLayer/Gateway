# SessionLayer test node — a real OpenSSH server on slim Debian 13 (trixie).
#
# Purpose: a controllable, port-mappable sshd for accurate E2E/integration tests
# (cert-based auth against a session CA, SFTP/SCP, command exec, node-local sshd
# logs) — NEVER rely on the host's ssh for testing. Used by Testcontainers in
# every repo (canonical source lives in testing/docker/sshd/; repos vendor it)
# and by the local docker-compose dev stack.
#
# Cert auth model (Design §3): node sshd trusts ONLY the session CA via
# TrustedUserCAKeys. Inject the CA public key at runtime with -e TRUSTED_USER_CA=
# "<openssh public key line>" (or bind-mount /etc/ssh/trusted_user_ca.pub). The
# presented user cert must carry a principal matching the login user (deploy|dba).
FROM debian:13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server \
      openssh-client \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 # Dedicated non-root login accounts = the RBAC-resolved Linux principals.
 # -p '*' => no password login, but the account is NOT locked ('!'), so OpenSSH
 # (UsePAM no) still permits certificate/pubkey auth. A locked '!' account is
 # refused with "account is locked" even for valid certs.
 && useradd --create-home --shell /bin/bash -p '*' deploy \
 && useradd --create-home --shell /bin/bash -p '*' dba \
 && passwd --lock root \
 # Placeholder trusted-CA file (populated at runtime by the entrypoint).
 && touch /etc/ssh/trusted_user_ca.pub \
 && chmod 644 /etc/ssh/trusted_user_ca.pub

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
 && /usr/sbin/sshd -t -f /etc/ssh/sshd_config || true

EXPOSE 22
# sshd -D -e keeps it foreground and logs to stderr (VERBOSE → cert key-id shows,
# giving the node-local audit trail the design relies on).
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
