# SessionLayer test node — a real OpenSSH server on slim Debian 13, so tests never rely
# on the host's ssh.
#
# The node trusts ONLY the session CA via TrustedUserCAKeys: inject the CA public key at
# runtime with -e TRUSTED_USER_CA="<openssh public key line>" (or bind-mount
# /etc/ssh/trusted_user_ca.pub), and the presented user certificate must carry a
# principal matching the login user (deploy|dba).
FROM debian:13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server \
      openssh-client \
      ca-certificates \
      xauth \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 # Dedicated non-root login accounts = the RBAC-resolved Linux principals.
 # -p '*' => no password login, but the account is NOT locked ('!'), so OpenSSH
 # (UsePAM no) still permits certificate/pubkey auth. A locked '!' account is
 # refused with "account is locked" even for valid certs.
 && useradd --create-home --shell /bin/bash -p '*' deploy \
 && useradd --create-home --shell /bin/bash -p '*' dba \
 && passwd --lock root \
 && touch /etc/ssh/trusted_user_ca.pub \
 && chmod 644 /etc/ssh/trusted_user_ca.pub

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
 && /usr/sbin/sshd -t -f /etc/ssh/sshd_config || true

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
