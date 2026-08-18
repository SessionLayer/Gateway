# Debian 13 openssh-**client** for the outer-leg E2E tests. Run with `--network host` so
# the container's 127.0.0.1 is the host loopback where the in-process Gateway binds.
#
# Stage 1 builds the OpenSSH **software SK provider** (`sk-dummy.so`) - a virtual FIDO2
# authenticator - from the matching openssh-portable source: the stock Debian
# openssh-client ships no middleware, so `ssh-keygen -t ecdsa-sk` fails "device not
# found" without it. Only `config.h` (./configure) + the openbsd-compat shims are needed
# to link it - the full openssh build is not.
ARG OPENSSH_VERSION=10.0p1
ARG OPENSSH_SHA256=021a2e709a0edf4250b1256bd5a9e500411a90dddabea830ed59cef90eb9d85c
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
      xauth \
      netcat-openbsd \
 && rm -rf /var/lib/apt/lists/* \
 && ssh -V 2>&1 | grep -q "${OPENSSH_CLIENT_MAJOR}" \
      || (echo "openssh-client is not ${OPENSSH_CLIENT_MAJOR}x - update OPENSSH_VERSION/DEBIAN_BASE"; ssh -V; exit 1)

COPY --from=skprovider /sk-dummy.so /usr/local/lib/sk-dummy.so

ENTRYPOINT ["sleep", "infinity"]
