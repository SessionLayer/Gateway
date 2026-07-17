//! Coredump hygiene for secret buffers (Session Twenty-One, Part B; NFR-5,
//! F-innerkey-zeroize / F-recorder-plaintext-zeroize residual).
//!
//! The Gateway holds SSH session plaintext and, transiently, the inner private
//! key. Those are scrubbed on drop (`Zeroizing`, aes-gcm key zeroize), but a
//! crash could still snapshot live secrets into a core file. This disables
//! coredumps entirely for the process, with two independent controls:
//!   * `PR_SET_DUMPABLE = 0` — the kernel produces no core dump for the process
//!     (and, as a bonus, a non-root `ptrace`/`/proc/pid/mem` attach is refused);
//!   * `RLIMIT_CORE = 0` — belt-and-suspenders: even if something re-enabled
//!     dumpability, the maximum core size is zero.
//!
//! Applied EARLY (before any secret is handled) so it covers the whole lifetime,
//! and inherited by every thread the runtime later spawns.
//!
//! Swap is a separate exposure the coredump controls do not cover; it is bounded
//! by the prompt `Zeroizing` scrub of plaintext, and operators handling the most
//! sensitive fleets should disable swap or use encrypted swap (see RUNBOOK).

/// Disable coredumps for this process. No-op on non-Linux (the deploy target is
/// Linux; `PR_SET_DUMPABLE` is Linux-only).
pub fn disable() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use anyhow::Context;
        use nix::sys::resource::{setrlimit, Resource};
        nix::sys::prctl::set_dumpable(false).context("prctl(PR_SET_DUMPABLE, 0)")?;
        setrlimit(Resource::RLIMIT_CORE, 0, 0).context("setrlimit(RLIMIT_CORE, 0)")?;
        tracing::debug!("coredumps disabled (PR_SET_DUMPABLE=0 + RLIMIT_CORE=0)");
    }
    Ok(())
}
