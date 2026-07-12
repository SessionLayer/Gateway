# Debian 13 (trixie) openssh-**client** for the outer-leg E2E tests.
#
# Purpose: drive the stock OpenSSH `ssh`/`ssh-keygen` client at the Gateway's
# outer SSH leg (never the host's ssh). Run with `--network host` so the
# container's 127.0.0.1 is the host loopback where the in-process Gateway binds;
# the client then connects to the Gateway on an ephemeral host port. The
# container stays alive (sleep) so tests `exec` ssh commands into it.
#
# Stage 1 builds the OpenSSH **software SK provider** (`sk-dummy.so`) — a virtual
# FIDO2 authenticator — from the matching openssh-portable source, so the Session
# Thirteen break-glass `sk-ecdsa` path can be driven end-to-end with a REAL FIDO
# signature and no hardware token (Design §7, FR-ACC-6). The stock Debian
# openssh-client ships no middleware, so `ssh-keygen -t ecdsa-sk` fails "device
# not found" without this. Only `config.h` (./configure) + the openbsd-compat
# shims are needed to link it — the full openssh build is not.
ARG OPENSSH_VERSION=10.0p1
# Pinned tarball digest (reproducible; no floating fetch). Verified against the
# OpenBSD OpenSSH portable release for OPENSSH_VERSION above.
ARG OPENSSH_SHA256=021a2e709a0edf4250b1256bd5a9e500411a90dddabea830ed59cef90eb9d85c
# Digest-pinned base (reproducible; not a floating tag). Debian trixie slim.
ARG DEBIAN_BASE=debian:13-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2
# Expected OpenSSH major line of the packaged client, asserted so a future Debian
# bump past 10.x (which could shift the sk-api ABI vs. the built sk-dummy.so) fails
# the build loudly instead of silently mismatching.
ARG OPENSSH_CLIENT_MAJOR=OpenSSH_10.

FROM ${DEBIAN_BASE} AS skprovider
ARG OPENSSH_VERSION
ARG OPENSSH_SHA256

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential libssl-dev zlib1g-dev curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# sk-dummy.so = sk-dummy.c + fatal.c + ed25519.c + hash.c, linked against
# libcrypto (per regress/misc/sk-dummy/Makefile). Pinned to the same OpenSSH
# release as the client's openssh-client, so the SK middleware ABI matches. The
# fetched tarball is checksum-verified before use (reproducible build).
RUN cd /tmp \
 && curl -fsSL -o openssh.tar.gz \
      "https://cloudflare.cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz" \
 && echo "${OPENSSH_SHA256}  openssh.tar.gz" | sha256sum -c - \
 && tar xzf openssh.tar.gz \
 && cd "openssh-${OPENSSH_VERSION}" \
 && ./configure --with-ssl-dir=/usr > /tmp/configure.log 2>&1 \
 && make -C openbsd-compat -j"$(nproc)" > /tmp/compat.log 2>&1 \
 && gcc -fPIC -DWITH_OPENSSL -I. -Iopenbsd-compat -shared \
      -o /sk-dummy.so \
      regress/misc/sk-dummy/sk-dummy.c \
      regress/misc/sk-dummy/fatal.c \
      ed25519.c hash.c \
      openbsd-compat/libopenbsd-compat.a \
      -lcrypto \
 && test -s /sk-dummy.so

FROM ${DEBIAN_BASE}
ARG OPENSSH_CLIENT_MAJOR

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-client \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 # Assert the packaged client's OpenSSH major line matches the sk-dummy source, so
 # the SK middleware ABI cannot silently drift (reproducible, verified).
 && ssh -V 2>&1 | grep -q "${OPENSSH_CLIENT_MAJOR}" \
      || (echo "openssh-client is not ${OPENSSH_CLIENT_MAJOR}x — update OPENSSH_VERSION/DEBIAN_BASE"; ssh -V; exit 1)

# The virtual FIDO2 authenticator, used as:
#   ssh-keygen -t ecdsa-sk -w /usr/local/lib/sk-dummy.so ...   (touch-required in prod)
#   ssh -o SecurityKeyProvider=/usr/local/lib/sk-dummy.so ...
COPY --from=skprovider /sk-dummy.so /usr/local/lib/sk-dummy.so

# Idle forever; tests exec `ssh`/`ssh-keygen` into this container.
ENTRYPOINT ["sleep", "infinity"]
