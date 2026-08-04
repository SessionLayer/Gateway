# Gateway deployment assets

Container image, Kubernetes manifests, and systemd unit for the hardened
Gateway. See `docs/installation/gateway.md` in the
[Documentation](https://github.com/SessionLayer/Documentation) repo for the
deployment models, the `hardening` config block, and the fail-closed contract
these assets implement.

## Container image

`Dockerfile` compiles the release binary with a digest-pinned Rust toolchain and
copies it into `gcr.io/distroless/cc-debian12:nonroot`, which carries glibc,
libgcc and the CA roots and nothing else. The aarch64 binary is cross-compiled
from the build platform, so neither architecture is built under emulation.

| Property | Value |
|---|---|
| Image | `ghcr.io/sessionlayer/gateway:v0.0.2` |
| Platforms | `linux/amd64`, `linux/arm64` |
| User | `65532:65532`, numeric so `runAsNonRoot` needs no `/etc/passwd` lookup |
| Writable path | `/var/lib/sessionlayer-gateway`, declared as a `VOLUME` and owned by 65532 |
| Shell | none in the final layer |
| Ports | 2222 (SSH), 9444 (Agent transport) |
| Healthcheck | none; the probes in `kubernetes/gateway.yaml` are the real ones |

The image never binds port 22, because uid 65532 cannot. The Service maps 22 to
2222 instead. For a bind-:22 host deployment use the systemd unit in `systemd/`,
which starts as root, binds, then drops privileges in-process. Setting
`hardening.run_as_user` in a container config is a startup error: the process is
already unprivileged, so it has no root to drop.

Build from the repository root, not from `deploy/`:

```console
$ docker build -f deploy/Dockerfile -t sessionlayer/gateway:dev .
$ docker run --rm sessionlayer/gateway:dev --version
gateway 0.0.1 (SessionLayer Gateway; CP<->GW protocol 1.0-1.1)
```

The release workflow publishes both platforms on a `v*` tag, signs the index and
every platform manifest with keyless cosign, and attaches an SPDX SBOM and SLSA
provenance. Verify an image before you run it, substituting the tag you intend
to deploy:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/SessionLayer/Gateway/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/sessionlayer/gateway:v0.0.2
```
