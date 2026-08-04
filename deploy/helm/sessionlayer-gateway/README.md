# sessionlayer-gateway

Deploys the SessionLayer Gateway as a Deployment, Service, Secret,
ServiceAccount, PodDisruptionBudget and NetworkPolicy. The chart is a
translation of `deploy/kubernetes/gateway.yaml` and
`deploy/kubernetes/networkpolicy.yaml`; those manifests remain the reference
for a deployment that does not use Helm.

The Gateway reads one JSON file, and that file carries the single-use
enrollment token. The chart therefore renders it into a Secret rather than a
ConfigMap, and offers a second path where you supply the whole file yourself.

## The two configuration paths

**You supply the file.** Set `config.existingSecret` to a Secret whose
`gateway.json` key holds the complete configuration. The chart renders no
configuration of its own, so the token never passes through a values file or
through Helm's release storage. The chart still cannot read that file, so
`ssh.listenPort`, `ssh.agent.listenPort` and `ha.drain.readyzPort` must match
what it says, or the probes and the Service point at ports nothing listens on.

**The chart renders the file.** Leave `config.existingSecret` empty and set
`bootstrap.enrollmentToken`, `bootstrap.gatewayName`, `trustAnchor` and
`ssh.sourceIpAllowlist`. `config.overrides` merges any other key from the
Gateway's own configuration schema over the result. The Gateway rejects unknown
keys, so a typo there stops the process at start with the offending key named,
rather than being ignored:

```text
Error: parsing gateway config /etc/sessionlayer/gateway.json: unknown field
`source_ip_alowlist`, expected one of `listen_addr`, `host_key_path`, ...
```

## Install

```bash
kubectl -n sessionlayer create configmap sessionlayer-bootstrap-ca --from-file=ca.pem=cp-ca.pem

helm install gw deploy/helm/sessionlayer-gateway \
  --namespace sessionlayer \
  --set trustAnchor.existingConfigMap=sessionlayer-bootstrap-ca \
  --set bootstrap.gatewayName=gw-a \
  --set bootstrap.enrollmentToken="$TOKEN" \
  --set 'ssh.sourceIpAllowlist={10.0.0.0/8}' \
  --set image.digest=sha256:<the digest you verified>
```

`$TOKEN` is one token from `POST /v1/gateway-enrollment-tokens`, minted for the
name in `bootstrap.gatewayName`. Replace `<the digest you verified>` with the
digest `cosign verify` reported for `ghcr.io/sessionlayer/gateway`.

`ci/production-values.yaml` and `ci/rendered-config-values.yaml` are the two
paths above as complete values files, kept as what the chart is linted and
schema-checked against.

## Rendering refuses these

| Condition | Why |
|---|---|
| `ssh.sourceIpAllowlist` empty | An empty allowlist is not "no opinion". The Gateway logs a warning and then accepts SSH from every source address. Checked after `config.overrides` merges, so it cannot be walked around by accident. |
| `bootstrap.enabled` with no `enrollmentToken` | A Gateway with neither an identity nor a bootstrap block can never obtain one and never says why. |
| `bootstrap.enabled` with no `gatewayName` | Identity in HA follows the Gateway's name. |
| `bootstrap.enabled` with no `trustAnchor.existingConfigMap` | The Gateway pins the Control Plane's CA and performs no trust-on-first-use. |
| `terminationGracePeriodSeconds` at or below the drain budget | The kubelet would SIGKILL mid-drain, and live sessions would lose their finalized recordings. |
| `persistence.enabled` with more than one replica | The replicas would share one data dir. Each Gateway holds its own identity and generation counter, and a shared one reads to the Control Plane as a clone, which auto-locks it. |
| `podDisruptionBudget.minAvailable` not below `replicaCount` | Such a budget refuses every voluntary eviction and hangs a node drain. |

## Values

### Image

| Key | Default | Notes |
|---|---|---|
| `image.repository` | `ghcr.io/sessionlayer/gateway` | |
| `image.tag` | `""` | Empty resolves to the chart's `appVersion`. |
| `image.digest` | `""` | Wins over `tag`. Pin this in production. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |

### Configuration and identity

| Key | Default | Notes |
|---|---|---|
| `config.existingSecret` | `""` | Secret holding the complete `gateway.json`. |
| `config.existingSecretKey` | `gateway.json` | |
| `config.overrides` | `{}` | Merged over the generated configuration, in the Gateway's own key names. |
| `trustAnchor.existingConfigMap` | `""` | ConfigMap holding the Control Plane's CA certificate. |
| `trustAnchor.key` | `ca.pem` | |
| `controlPlane.mtlsEndpoint` | `""` | Empty derives `https://controlplane.<namespace>.svc:9443`, the Service the Control Plane chart creates. |
| `controlPlane.serverName` | `""` | The name the Control Plane's certificate carries, which is not always the address dialled. Empty derives `controlplane.<namespace>.svc`. |
| `bootstrap.enabled` | `true` | Off means this Gateway already holds an identity in a persistent data dir. |
| `bootstrap.enrollmentToken` | `""` | Single-use. |
| `bootstrap.gatewayName` | `""` | |
| `dataDir` | `/var/lib/sessionlayer-gateway` | The only path the process writes. |

### Listeners

| Key | Default | Notes |
|---|---|---|
| `ssh.listenPort` | `2222` | uid 65532 cannot bind 22, so the container listens high and the Service maps 22 onto it. Nothing in the pod ever needs a privileged bind. For a bind-22 host deployment use `deploy/systemd/`, which drops privileges in-process after the bind. |
| `ssh.hostKeyPath` | `/var/lib/sessionlayer-gateway/host_ed25519` | |
| `ssh.sourceIpAllowlist` | `[]` | Required non-empty. |
| `ssh.agent.listenPort` | `9444` | Where Agents dial in and peer Gateways relay bytes. |
| `ssh.agent.advertiseUrl` | `""` | Empty derives the in-cluster Service address, which is right only when your nodes are in this cluster. A fleet outside it needs the load balancer's address. |
| `service.type` | `LoadBalancer` | |
| `service.sshPort` | `22` | |
| `service.agentPort` | `9444` | |
| `service.loadBalancerSourceRanges` | `[]` | Narrows the front door at the load balancer as well as at the in-process source-IP gate. |
| `service.externalTrafficPolicy` | `""` | |

### High availability

| Key | Default | Notes |
|---|---|---|
| `ha.mode` | `single_instance` | |
| `ha.coordination` | `{backend: in_process}` | The Gateway's own schema. `in_process` cannot reach another pod, so a session landing on a Gateway that does not own the node's agent channel has no way to signal the owner. A multi-replica deployment serving agent-based nodes needs `{backend: nats, url: ..., subject_prefix: sl}`. The install notes say so when the combination appears. |
| `ha.drain.preDrainGraceSecs` | `5` | |
| `ha.drain.deadlineSecs` | `30` | |
| `ha.drain.readyzPort` | `8081` | |
| `terminationGracePeriodSeconds` | `45` | Above the 35s drain budget, with room for a slow object-store PUT. During the drain the Gateway stops advertising ready, lets live sessions finish and finalizes their recordings. Kubernetes' 30s default would SIGKILL five seconds before the deadline and break the promise that recordings are finalized on a clean drain. |
| `podDisruptionBudget.enabled` | `true` | Without it, draining two nodes can evict both replicas at once and take every live session with it. Voluntary disruption only. |
| `podDisruptionBudget.minAvailable` | `1` | |

### Hardening

| Key | Default | Notes |
|---|---|---|
| `hardening.landlock.enabled` | `true` | |
| `hardening.landlock.required` | `false` | On means the process refuses to start where the kernel cannot fully enforce Landlock, rather than degrading to the container's read-only root filesystem and dropped capabilities alone. Turn it on where you control the kernel version. |
| `hardening.landlock.readOnlyPaths` | see `values.yaml` | The systemd-resolved path the host unit lists is absent from the container image and is not repeated here. A listed path that does not exist is skipped with a startup warning and confines nothing. |
| `hardening.landlock.readWritePaths` | `[/var/lib/sessionlayer-gateway]` | |
| `hardening.seccomp.mode` | `enforce` | The binary's own filter. The pod's `seccompProfile: RuntimeDefault` is the kernel floor beneath it. |
| `podSecurityContext` | `runAsNonRoot`, uid/gid/fsGroup `65532`, `RuntimeDefault` | |
| `containerSecurityContext` | `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]` | |
| `serviceAccount.automountServiceAccountToken` | `false` | The Gateway never calls the Kubernetes API. |

The security context is the outer layer; the binary applies its own seccomp and
Landlock at startup and fails closed. Together: a non-root, read-only-rootfs,
all-capabilities-dropped, no-privilege-escalation, seccomp-confined process
whose egress the NetworkPolicy restricts.

### Storage

| Key | Default | Notes |
|---|---|---|
| `persistence.enabled` | `false` | Off re-enrolls on every restart, which needs a fresh single-use token each time. |
| `persistence.existingClaim` | `""` | |
| `persistence.storageClass` | `""` | |
| `persistence.accessModes` | `[ReadWriteOnce]` | |
| `persistence.size` | `1Gi` | |
| `tmpVolume.enabled` | `true` | |

A claim the chart creates carries `helm.sh/resource-policy: keep`, because the
enrolled identity outlives the release.

### Probes

| Key | Default | Notes |
|---|---|---|
| `probes.readiness` | `/readyz`, every 5s | Reports the drain state, so a draining Gateway leaves the load balancer's rotation before its sessions end. |
| `probes.liveness` | TCP on the SSH port, every 15s | Restarts a Gateway that has wedged and accepts nothing. |
| `probes.startup` | TCP on the SSH port, 30 failures | Slack for enrollment, where the mTLS bootstrap round trip can be slow. |

### NetworkPolicy

| Key | Default | Notes |
|---|---|---|
| `networkPolicy.enabled` | `true` | Default-deny both directions. Needs a CNI that enforces NetworkPolicy. |
| `networkPolicy.controlPlanePodSelector` | `app.kubernetes.io/name: sessionlayer-controlplane` | |
| `networkPolicy.controlPlaneGrpcPort` | `9443` | Match the port inside `controlPlane.mtlsEndpoint`. |
| `networkPolicy.nodeCidrs` | `[]` | The SSH nodes this Gateway bridges to. |
| `networkPolicy.wormCidrs` | `[]` | The object store recordings upload to. |

The binary's seccomp filter cannot scope a destination, so egress confinement
is the network layer's job: this policy permits only the Control Plane's gRPC
plane, the nodes, cluster DNS and the object store. Everything else, including
the cloud metadata service, is dropped.

The CIDR lists start empty. A placeholder range permits egress to hosts that
are not your fleet or your object store, which is worse than no rule at all,
so those rules are absent until you name the range. The install notes print
what is currently denied.

### Scheduling and extension

`podAnnotations`, `podLabels`, `nodeSelector`, `tolerations`, `affinity`,
`topologySpreadConstraints`, `priorityClassName`, `extraEnv`, `extraEnvFrom`,
`extraVolumes` and `extraVolumeMounts` pass through unchanged.

## What this chart is not

It is validated statically: `helm lint`, `helm template`, `values.schema.json`,
`kubeconform -strict` against the Kubernetes schemas, and the rendered
`gateway.json` loaded by the Gateway binary itself. It has not been installed
into a live cluster as part of this repository's testing.

## See also

- `deploy/kubernetes/` for the plain manifests this chart translates
- `deploy/systemd/` for the bind-22 host deployment
- [Gateway configuration](https://github.com/SessionLayer/Documentation/blob/main/docs/reference/config-gateway.md)
