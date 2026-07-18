//! Landlock filesystem confinement (Session Twenty-One, NFR-5).
//!
//! Landlock (Linux LSM, ≥ 5.13) is an *unprivileged, additive-only* sandbox: once
//! `restrict_self` runs, the process (and every child/thread) may touch ONLY the
//! paths listed here, regardless of DAC permissions, and can never re-grant
//! access. So a code-exec bug in the SSH/TLS stack cannot read `/etc/shadow`,
//! write outside the data dir, or open arbitrary files — the filesystem reachable
//! to the attacker is exactly the Gateway's declared working set.
//!
//! Degrade vs fail-closed: we run in Landlock's BestEffort compatibility mode, so
//! a kernel with **no** Landlock returns `NotEnforced` — that is the documented
//! Accepted-Risk kernel-capability gap (warn + continue). An older-but-present
//! ABI returns `PartiallyEnforced` (still confining, just fewer access-right
//! distinctions) — fine. Any hard error (a path that exists but cannot be opened,
//! a failing `restrict_self`) fails closed.

use anyhow::Context;
use gateway_core::config::LandlockConfig;
use landlock::{
    Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, PathFdError, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::path::Path;

/// Baseline ABI. V1 (kernel 5.13) already delivers the whole read/write
/// filesystem confinement; newer ABIs only refine it (refer, truncate) and, in
/// BestEffort mode, degrade cleanly on older kernels.
const LANDLOCK_ABI: ABI = ABI::V1;

/// Confine the calling thread. `log_status` is set only for the one main-thread
/// call; the per-worker `on_thread_start` calls pass `false` to avoid N identical
/// status lines (one per runtime thread).
pub fn confine(cfg: &LandlockConfig, log_status: bool) -> anyhow::Result<()> {
    let read_access = AccessFs::from_read(LANDLOCK_ABI);
    let all_access = AccessFs::from_all(LANDLOCK_ABI);

    let mut created = Ruleset::default()
        // Explicit (not relying on the implicit default): a kernel without this
        // ABI degrades to NotEnforced rather than erroring, which is what maps to
        // our documented Accepted-Risk kernel-gap degrade below.
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(all_access)
        .context("landlock: handle_access")?
        .create()
        .context("landlock: create ruleset")?;

    // Read-only rules, then read-write rules. A path that does not exist is
    // skipped with a warning (a rule over a missing optional path — e.g.
    // /etc/pki on a Debian host — is not fatal); any other open failure is.
    for path in &cfg.read_only_paths {
        if let Some(fd) = open_rule_path(path)? {
            created = created
                .add_rule(PathBeneath::new(fd, read_access))
                .with_context(|| format!("landlock: add read rule for {}", path.display()))?;
        }
    }
    for path in &cfg.read_write_paths {
        if let Some(fd) = open_rule_path(path)? {
            created = created
                .add_rule(PathBeneath::new(fd, all_access))
                .with_context(|| format!("landlock: add read-write rule for {}", path.display()))?;
        }
    }

    let status = created.restrict_self().context("landlock: restrict_self")?;
    if log_status {
        match status.ruleset {
            RulesetStatus::FullyEnforced => {
                tracing::info!(
                    read_only = cfg.read_only_paths.len(),
                    read_write = cfg.read_write_paths.len(),
                    "Landlock filesystem confinement fully enforced"
                );
            }
            RulesetStatus::PartiallyEnforced => {
                tracing::warn!(
                    "Landlock partially enforced (older kernel ABI subset); filesystem confinement is active"
                );
            }
            RulesetStatus::NotEnforced => {
                // Kernel-capability gap — documented Accepted-Risk degrade (unless
                // landlock.required is set, in which case we fail closed below).
                tracing::warn!(
                    "Landlock is unavailable on this kernel (no LSM support); filesystem confinement DISABLED (Accepted-Risk) — rely on the container read-only rootfs + dropped capabilities"
                );
            }
        }
    }
    // F-landlock-require-1: on the Tier-0 Gateway an operator can demand FULL
    // confinement — refuse to start on a kernel that can't provide it (mirrors the
    // Agent's --require-full-landlock). Default off (best-effort degrade above).
    enforce_required(cfg.required, status.ruleset)
}

/// Fail closed when `required` is set but Landlock is not fully enforced. Factored
/// out so the decision is unit-testable without a Landlock-less kernel.
fn enforce_required(required: bool, ruleset: RulesetStatus) -> anyhow::Result<()> {
    if required && !matches!(ruleset, RulesetStatus::FullyEnforced) {
        anyhow::bail!(
            "landlock.required is set but Landlock is only {ruleset:?} on this kernel — refusing \
             to start a Tier-0 Gateway without full filesystem confinement (fail closed)"
        );
    }
    Ok(())
}

/// Open a path for a Landlock rule (`O_PATH`). Returns `Ok(None)` — skip with a
/// warning — when the path simply does not exist; propagates any other error to
/// fail closed.
fn open_rule_path(path: &Path) -> anyhow::Result<Option<PathFd>> {
    match PathFd::new(path) {
        Ok(fd) => Ok(Some(fd)),
        Err(e) => {
            // `PathFdError` is #[non_exhaustive]; its only variant wraps the
            // `open()` io error. A missing optional path is skip-with-warning;
            // anything else fails closed.
            if let PathFdError::OpenCall { source, .. } = &e {
                if source.kind() == std::io::ErrorKind::NotFound {
                    tracing::warn!(path = %path.display(), "Landlock allow-path does not exist; skipping");
                    return Ok(None);
                }
            }
            Err(anyhow::Error::new(e).context(format!("landlock: opening {}", path.display())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // F-landlock-require-1: with landlock.required set, anything short of full
    // enforcement must abort startup; unset, the best-effort degrade never blocks.
    #[test]
    fn required_fails_closed_unless_fully_enforced() {
        assert!(enforce_required(true, RulesetStatus::NotEnforced).is_err());
        assert!(enforce_required(true, RulesetStatus::PartiallyEnforced).is_err());
        assert!(enforce_required(true, RulesetStatus::FullyEnforced).is_ok());
        assert!(enforce_required(false, RulesetStatus::NotEnforced).is_ok());
        assert!(enforce_required(false, RulesetStatus::PartiallyEnforced).is_ok());
    }
}
