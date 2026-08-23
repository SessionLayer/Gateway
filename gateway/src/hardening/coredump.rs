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
