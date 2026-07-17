# Deploying the SessionLayer Gateway (Tier-0 hardened)

The Gateway is the platform's only plaintext-SSH MITM — the largest blast radius
in the system (Design §15). It defends itself in **two composed layers**:

1. **In-process self-hardening** (Session Twenty-One, NFR-5) — applied by the
   binary at startup, *after* it binds its listeners:
   - **privilege drop** to an unprivileged user (bind `:22` as root, then drop);
   - **Landlock** filesystem confinement (only the declared paths are reachable);
   - a **seccomp** syscall allow-list (unlisted → `EPERM`; the exploitation set —
     `execve`/`ptrace`/module-load/namespace-escape/`kexec`/… → `KILL_PROCESS`).
2. **The container / OS security-context** in this directory — read-only rootfs,
   dropped capabilities, `no_new_privs`, and a restricted-egress NetworkPolicy.

Neither layer trusts the other; a bypass of one is still caught by the second.

## Which deployment model

| | Container (Kubernetes) | Bare-metal / VM (systemd) |
|---|---|---|
| Port | high port (`:2222`), Service maps `:22` → `:2222` | binds `:22` directly |
| Privilege | starts **non-root** (uid 65532) — no in-process drop | starts root, **drops after bind** |
| Files | `deploy/Dockerfile` + `deploy/kubernetes/` | `deploy/systemd/` |
| FS confinement | `readOnlyRootFilesystem` + Landlock | `ProtectSystem=strict` + Landlock |
| Egress | `networkpolicy.yaml` (CP + nodes + DNS) | host firewall (nftables/iptables) |

The container model is the recommended default. The bare-metal model exists for
environments that must bind `:22` on the host, and is the one that exercises the
in-process privilege-drop-after-bind.

## The `hardening` config block

```jsonc
"hardening": {
  // Privilege drop (bare-metal only): bind :22 as root, then run as this user.
  // Empty = no drop. Requested-but-not-root, or an unknown user, fails closed.
  "run_as_user": "sessionlayer",
  "run_as_group": "",                     // blank = the user's primary group

  "landlock": {
    "enabled": true,
    // Everything the daemon reads: config, TLS/CA bundle, host key, resolver +
    // NSS files, and — for a dynamically-linked binary — the library dirs
    // (getaddrinfo/getpwnam load libnss_*.so at runtime). Missing paths are
    // skipped with a warning.
    "read_only_paths": [
      "/etc/sessionlayer", "/etc/ssl/certs", "/etc/resolv.conf",
      "/etc/hosts", "/etc/nsswitch.conf",
      "/lib", "/lib64", "/usr/lib", "/usr/local/bin/gateway"
    ],
    "read_write_paths": ["/var/lib/sessionlayer-gateway"]
  },

  // off | log | enforce.  Roll out as: enforce=off → log (run a full session,
  // confirm dmesg/auditd shows no unexpected syscall) → enforce.
  "seccomp": { "mode": "enforce" }
}
```

## Fail-closed contract

A step that is **requested** but cannot be applied for a reason under operator
control aborts startup with a diagnostic:

- `run_as_user` set but the process is not root, or the user is unknown;
- a Landlock/seccomp rule the kernel supports but rejects.

The **single exception** is a *kernel-capability gap* — the running kernel does
not implement Landlock or seccomp at all — which **degrades** with a loud warning
(a documented Accepted-Risk), so the Gateway still starts on an older kernel
rather than wedging. On such a host, lean on the container read-only rootfs +
dropped capabilities. seccomp `enforce` on a kernel without seccomp is the one
case that will surface as a startup error from the syscall itself.

## Validation

The in-process hardening is exercised against the real binary by the full-stack
E2E (`tests/hardening_e2e.rs` + the cross-repo full-stack harness): the Gateway
runs under `seccomp=enforce` + Landlock while a real `ssh` client drives
shell/exec/sftp through it to a real node — proving the profile does not break the
SSH data path. The container/OS manifests here are validated by review + a
`kubeconform`/`kube-linter` pass in CI (non-gating).
