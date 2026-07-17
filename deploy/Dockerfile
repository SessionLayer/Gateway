# SessionLayer Gateway — hardened production image (Session Twenty-One, NFR-5).
#
# Two-stage build: a full toolchain compiles the release binary, and a distroless
# runtime carries only glibc + CA roots + the binary — no shell, no package
# manager, no busybox, nothing an attacker who lands code execution could pivot
# through. It runs as a non-root user with a read-only root filesystem; the outer
# container/orchestrator security-context (see deploy/kubernetes/) drops all
# capabilities and confines egress, and the binary ITSELF then applies the
# in-process seccomp + Landlock + privilege-drop hardening at startup.
#
# Pin the base images by digest in your registry mirror for production (the tags
# below are for readability); the project pins GitHub Actions by SHA for the same
# supply-chain reason.

# ---- build stage ----
FROM rust:1.95-bookworm AS build

# build.rs generates the CP<->GW gRPC stubs via tonic-prost-build, which shells
# out to protoc. Nothing else is needed (ring/rustls are pure-Rust + asm).
RUN apt-get update \
 && apt-get install --no-install-recommends -y protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# The whole workspace, including the vendored [patch.crates-io] russh under
# third_party/ and the vendored proto/ (CI checks out this repo alone).
COPY . .

# Reproducible, offline-friendly release build of just the daemon.
ENV CARGO_INCREMENTAL=0
RUN cargo build --release --locked --bin gateway \
 && strip target/release/gateway

# ---- runtime stage ----
# distroless/cc = glibc + libgcc + CA certificates, no shell/package manager.
# The :nonroot tag runs as uid/gid 65532 and owns nothing writable in the image.
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=build /src/target/release/gateway /usr/local/bin/gateway

# The only writable location the daemon needs is its credential data-dir; mount a
# tmpfs / PVC there (read-only rootfs everywhere else). Declared so an operator who
# forgets a mount fails loudly rather than writing into an overlay that vanishes.
VOLUME ["/var/lib/sessionlayer-gateway"]

# distroless/nonroot cannot bind :22; listen high and front it with a Service/LB
# that maps 22 -> this port (see deploy/kubernetes/gateway.yaml). For a bind-:22
# deployment use the systemd unit (deploy/systemd/) with the in-process privilege
# drop instead.
EXPOSE 2222 9444

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/gateway"]
CMD ["--config", "/etc/sessionlayer/gateway.json"]
