# Debian 13 (trixie) openssh-**client** for Session Seven outer-leg E2E tests.
#
# Purpose: drive the stock OpenSSH `ssh`/`ssh-keygen` client at the Gateway's
# outer SSH leg (never the host's ssh). Run with `--network host` so the
# container's 127.0.0.1 is the host loopback where the in-process Gateway binds;
# the client then connects to the Gateway on an ephemeral host port. The
# container stays alive (sleep) so tests `exec` ssh commands into it.
FROM debian:13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-client \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Idle forever; tests exec `ssh`/`ssh-keygen` into this container.
ENTRYPOINT ["sleep", "infinity"]
