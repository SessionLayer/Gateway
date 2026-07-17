//! Tier-0 runtime self-hardening (Session Twenty-One; Design NFR-5,
//! [[audit/closed/F-dos-accept-1.md]]).
//!
//! The Gateway is the platform's only plaintext-SSH MITM — the largest blast
//! radius in the system (Design §15). This module is its in-process last line of
//! defence: after the listeners are bound it drops privileges, confines the
//! filesystem with Landlock, and installs a seccomp syscall filter, so that a
//! hypothetical code-execution bug in the SSH/TLS stack is boxed into a process
//! that cannot exec a shell, escape its namespace, read `/etc/shadow`, or reach
//! the network beyond the sockets it already holds.
//!
//! **It lives in the binary, never in `gateway-core`.** The library's integration
//! tests drive the SSH server in-process; applying a sandbox from library code
//! would restrict the test runner itself. The real hardened profile is therefore
//! exercised only by the real `gateway` binary (the cross-repo full-stack E2E).
//!
//! **Fail-closed contract.** A requested step that fails for a reason under
//! operator control (privilege drop while not root, an unknown user, a Landlock or
//! seccomp rule the kernel supports but rejects) returns `Err`, aborting startup.
//! A *kernel-capability gap* — the running kernel does not implement the mechanism
//! at all — degrades with a loud warning (a documented Accepted-Risk), so the
//! Gateway still starts on an older kernel rather than wedging.

use gateway_core::config::HardeningConfig;

#[cfg(target_os = "linux")]
mod landlock_fs;
#[cfg(target_os = "linux")]
mod privdrop;
#[cfg(target_os = "linux")]
mod seccomp;

/// Apply the configured hardening steps, in order, once every listener is bound.
///
/// Order is load-bearing:
///   1. **privilege drop** — first, while the process still has the privilege to
///      change user and while NSS libraries can still be loaded (a later Landlock
///      confinement or seccomp filter could block the `getpwnam`/`setuid` path).
///   2. **Landlock** — filesystem confinement, before seccomp (Landlock's own
///      syscalls must not be blocked by the filter).
///   3. **seccomp** — last, because it is the most restrictive; once installed it
///      would deny the very syscalls steps 1–2 depend on.
pub fn apply(cfg: &HardeningConfig) -> anyhow::Result<()> {
    apply_inner(cfg)
}

#[cfg(target_os = "linux")]
fn apply_inner(cfg: &HardeningConfig) -> anyhow::Result<()> {
    if !cfg.run_as_user.is_empty() {
        let report = privdrop::drop_to(&cfg.run_as_user, &cfg.run_as_group)?;
        tracing::info!(
            uid = report.uid,
            gid = report.gid,
            "privilege dropped after bind (irreversible)"
        );
    }

    if cfg.landlock.enabled {
        landlock_fs::confine(&cfg.landlock)?;
    }

    // seccomp LAST — it would otherwise block the setuid/landlock syscalls above.
    seccomp::install(cfg.seccomp.mode)?;

    Ok(())
}

/// Non-Linux fallback: none of the mechanisms exist, so a *requested* hardening
/// step fails closed (we cannot provide the posture the operator asked for); an
/// all-default (nothing requested) config is a silent no-op.
#[cfg(not(target_os = "linux"))]
fn apply_inner(cfg: &HardeningConfig) -> anyhow::Result<()> {
    use gateway_core::config::SeccompMode;
    let requested = !cfg.run_as_user.is_empty()
        || cfg.landlock.enabled
        || cfg.seccomp.mode != SeccompMode::Off;
    if requested {
        anyhow::bail!(
            "hardening (privilege drop / Landlock / seccomp) is configured but is only \
             implemented on Linux; refusing to start without the requested posture (fail closed)"
        );
    }
    Ok(())
}
