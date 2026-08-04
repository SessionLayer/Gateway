# SessionLayer Gateway — hardened production image (NFR-5).
#
# Both base images are pinned to their multi-arch INDEX digest. A per-platform
# manifest digest would resolve on one architecture and fail the build on the
# other; the human tag is kept alongside for legibility. Keep the rust tag equal
# to rust-toolchain.toml's channel — when they diverge the build still succeeds,
# because rustup honours the toml and fetches the pinned toolchain over the
# network, so the drift is invisible while defeating the pinned builder.

# ---- build stage ----
# Pinned to $BUILDPLATFORM and cross-compiled: a QEMU-emulated release build of
# this workspace costs hours per architecture, and aarch64 is a target CI already
# compiles on every push.
FROM --platform=$BUILDPLATFORM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS build

# protoc: build.rs generates the CP<->GW gRPC stubs via tonic-prost-build.
# The aarch64 cross toolchain is installed unconditionally so both target builds
# share one layer; libc6-dev-arm64-cross supplies the target sysroot headers,
# without which ring's C falls back to the host /usr/include and fails to compile.
RUN apt-get update \
 && apt-get install --no-install-recommends -y \
      protobuf-compiler gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
 && rm -rf /var/lib/apt/lists/*

# Target-scoped, so they are inert on the native build.
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar

WORKDIR /src
# The whole workspace, including the vendored [patch.crates-io] russh under
# third_party/ and the vendored proto/ (CI checks out this repo alone).
COPY . .

ARG TARGETARCH
# rustc strips rather than binutils: one command covers both targets, with no
# per-architecture strip binary to keep in step.
ENV CARGO_INCREMENTAL=0 \
    RUSTFLAGS="-C strip=symbols"
# The cache ids are per-architecture because buildx runs the two platform builds
# concurrently and cargo takes a whole-directory lock.
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=gateway-registry-$TARGETARCH \
    --mount=type=cache,target=/src/target,id=gateway-target-$TARGETARCH \
    set -eu; \
    case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu ;; \
      arm64) triple=aarch64-unknown-linux-gnu ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    rustup target add "$triple"; \
    cargo build --release --locked --target "$triple" --bin gateway; \
    install -D "target/$triple/release/gateway" /out/gateway; \
    install -d -o 65532 -g 65532 /out/rootfs/var/lib/sessionlayer-gateway

# ---- runtime stage ----
# distroless/cc = glibc + libgcc + CA certificates, no shell and no package
# manager. The :nonroot variant ships uid/gid 65532 and owns nothing writable.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e

ARG VERSION=0.0.0-dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="SessionLayer Gateway" \
      org.opencontainers.image.description="Policy-enforced SSH proxy with session recording for the SessionLayer Zero-Trust platform." \
      org.opencontainers.image.source="https://github.com/SessionLayer/Gateway" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"

COPY --from=build /out/gateway /usr/local/bin/gateway
# Carries the 65532 ownership, so an anonymous volume or a PVC without an fsGroup
# still lands writable for the runtime user.
COPY --from=build /out/rootfs/ /

# The credential data-dir is the only location the daemon writes; mount a tmpfs or
# PVC there and keep the root filesystem read-only. Declared so an operator who
# forgets the mount fails loudly rather than writing into an overlay that vanishes.
VOLUME ["/var/lib/sessionlayer-gateway"]

# uid 65532 cannot bind :22; listen high and front it with a Service/LB that maps
# 22 -> this port (see deploy/kubernetes/gateway.yaml). For a bind-:22 deployment
# use the systemd unit (deploy/systemd/), which drops privileges in-process after
# the bind — a path this image deliberately does not take, since a container that
# starts as root to drop later is a worse posture than one that is never root.
EXPOSE 2222 9444

# Numeric, so Kubernetes runAsNonRoot can enforce it with no /etc/passwd lookup.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/gateway"]
CMD ["--config", "/etc/sessionlayer/gateway.json"]
