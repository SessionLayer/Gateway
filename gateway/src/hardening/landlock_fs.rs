use anyhow::Context;
use gateway_core::config::LandlockConfig;
use landlock::{
    Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, PathFdError, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::path::Path;

const LANDLOCK_ABI: ABI = ABI::V1;

pub fn confine(cfg: &LandlockConfig, log_status: bool) -> anyhow::Result<()> {
    let read_access = AccessFs::from_read(LANDLOCK_ABI);
    let all_access = AccessFs::from_all(LANDLOCK_ABI);

    let mut created = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(all_access)
        .context("landlock: handle_access")?
        .create()
        .context("landlock: create ruleset")?;

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
            // Deliberately does not name a cause. Best-effort compatibility
            // downgrades for more than an old kernel: the same kernel reports
            // partial or full depending only on the shape of the configured
            // paths, because a directory-only access right applied to a regular
            // file is downgraded too. Blaming the kernel sends the reader to
            // check a kernel version and stop, which is worse than saying less.
            RulesetStatus::PartiallyEnforced => {
                tracing::warn!(
                    read_only = cfg.read_only_paths.len(),
                    read_write = cfg.read_write_paths.len(),
                    abi_target = ?LANDLOCK_ABI,
                    "Landlock partially enforced: some requested access rights were downgraded. \
                     Filesystem confinement is active but narrower than configured - check both \
                     the kernel's Landlock ABI and whether any configured path is a regular file \
                     rather than a directory"
                );
            }
            RulesetStatus::NotEnforced => {
                tracing::warn!(
                    "Landlock is unavailable on this kernel (no LSM support); filesystem confinement DISABLED (Accepted-Risk) - rely on the container read-only rootfs + dropped capabilities"
                );
            }
        }
    }
    enforce_required(cfg.required, status.ruleset)
}

fn enforce_required(required: bool, ruleset: RulesetStatus) -> anyhow::Result<()> {
    if required && !matches!(ruleset, RulesetStatus::FullyEnforced) {
        anyhow::bail!(
            "landlock.required is set but Landlock is only {ruleset:?} on this kernel - refusing \
             to start a Tier-0 Gateway without full filesystem confinement (fail closed)"
        );
    }
    Ok(())
}

fn open_rule_path(path: &Path) -> anyhow::Result<Option<PathFd>> {
    match PathFd::new(path) {
        Ok(fd) => Ok(Some(fd)),
        Err(e) => {
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

    #[test]
    fn required_fails_closed_unless_fully_enforced() {
        assert!(enforce_required(true, RulesetStatus::NotEnforced).is_err());
        assert!(enforce_required(true, RulesetStatus::PartiallyEnforced).is_err());
        assert!(enforce_required(true, RulesetStatus::FullyEnforced).is_ok());
        assert!(enforce_required(false, RulesetStatus::NotEnforced).is_ok());
        assert!(enforce_required(false, RulesetStatus::PartiallyEnforced).is_ok());
    }
}
