use gateway_core::config::HardeningConfig;

mod coredump;
#[cfg(target_os = "linux")]
mod landlock_fs;
#[cfg(target_os = "linux")]
mod privdrop;
#[cfg(target_os = "linux")]
mod seccomp;

/// Must run before any listener binds or any secret is in memory.
pub fn disable_coredumps(cfg: &HardeningConfig) -> anyhow::Result<()> {
    if cfg.disable_coredumps {
        coredump::disable()?;
    }
    Ok(())
}

pub fn apply(cfg: &HardeningConfig, io_uring_active: bool) -> anyhow::Result<()> {
    apply_inner(cfg, io_uring_active)
}

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

    if cfg.landlock.enabled {
        landlock_fs::confine(&cfg.landlock, true)?;
    }

    seccomp::install(cfg.seccomp.mode, io_uring_active)?;

    Ok(())
}

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
