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

mod coredump;
#[cfg(target_os = "linux")]
mod landlock_fs;
#[cfg(target_os = "linux")]
mod privdrop;
#[cfg(target_os = "linux")]
mod seccomp;

/// Disable coredumps for the process when configured (Part B). Applied EARLY —
/// before any listener binds or any secret is handled — so it covers the whole
/// process lifetime and is inherited by every thread the runtime later spawns.
pub fn disable_coredumps(cfg: &HardeningConfig) -> anyhow::Result<()> {
    if cfg.disable_coredumps {
        coredump::disable()?;
    }
    Ok(())
}

/// Apply the configured hardening steps, in order, once every listener is bound.
///
/// Order is load-bearing:
///   1. **privilege drop** — first, while the process still has the privilege to
///      change user and while NSS libraries can still be loaded (a later Landlock
///      confinement or seccomp filter could block the `getpwnam`/`setuid` path).
///   2. **Landlock** (this thread) — filesystem confinement, before seccomp
///      (Landlock's own syscalls must not be blocked by the filter). The tokio
///      *worker* threads are confined separately at spawn via
///      [`confine_thread_for_landlock`] wired into `Builder::on_thread_start`,
///      because Landlock's `restrict_self` has no TSYNC — it covers only the
///      calling thread + its future children, unlike seccomp/setuid which reach
///      every thread from here.
///   3. **seccomp** — last, because it is the most restrictive; once installed it
///      would deny the very syscalls steps 1–2 depend on. Installed with TSYNC so
///      it covers every tokio worker. `io_uring_active` gates the `io_uring_*`
///      syscalls (hard-denied unless the reactor is actually selected).
pub fn apply(cfg: &HardeningConfig, io_uring_active: bool) -> anyhow::Result<()> {
    apply_inner(cfg, io_uring_active)
}

/// Confine the *calling* thread with Landlock (used from the tokio runtime's
/// `on_thread_start`, so each worker/blocking thread self-confines as it spawns).
/// Fail-closed: a worker that cannot apply a *required* confinement must not run,
/// and it cannot return an error to the runtime, so it aborts the process.
#[cfg(target_os = "linux")]
pub fn confine_thread_for_landlock(cfg: &gateway_core::config::LandlockConfig) {
    if !cfg.enabled {
        return;
    }
    if let Err(e) = landlock_fs::confine(cfg, false) {
        eprintln!("FATAL: Landlock confinement failed on a runtime thread: {e:#}");
        std::process::abort();
    }
}

#[cfg(not(target_os = "linux"))]
pub fn confine_thread_for_landlock(_cfg: &gateway_core::config::LandlockConfig) {}

#[cfg(target_os = "linux")]
fn apply_inner(cfg: &HardeningConfig, io_uring_active: bool) -> anyhow::Result<()> {
    if !cfg.run_as_user.is_empty() {
        let report = privdrop::drop_to(&cfg.run_as_user, &cfg.run_as_group)?;
        tracing::info!(
            uid = report.uid,
            gid = report.gid,
            "privilege dropped after bind (irreversible)"
        );
    }

    // Confine THIS (main) thread; the workers were confined at spawn.
    if cfg.landlock.enabled {
        landlock_fs::confine(&cfg.landlock, true)?;
    }

    // seccomp LAST — it would otherwise block the setuid/landlock syscalls above.
    seccomp::install(cfg.seccomp.mode, io_uring_active)?;

    Ok(())
}

/// Non-Linux fallback: none of the mechanisms exist, so a *requested* hardening
/// step fails closed (we cannot provide the posture the operator asked for); an
/// all-default (nothing requested) config is a silent no-op.
#[cfg(not(target_os = "linux"))]
fn apply_inner(cfg: &HardeningConfig, _io_uring_active: bool) -> anyhow::Result<()> {
    use gateway_core::config::SeccompMode;
    let requested =
        !cfg.run_as_user.is_empty() || cfg.landlock.enabled || cfg.seccomp.mode != SeccompMode::Off;
    if requested {
        anyhow::bail!(
            "hardening (privilege drop / Landlock / seccomp) is configured but is only \
             implemented on Linux; refusing to start without the requested posture (fail closed)"
        );
    }
    Ok(())
}
