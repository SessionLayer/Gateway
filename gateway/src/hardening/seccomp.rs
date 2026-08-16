use anyhow::Context;
use gateway_core::config::SeccompMode;
use seccompiler::{apply_filter_all_threads, BpfProgram, SeccompAction, SeccompFilter};
use std::collections::BTreeMap;

pub fn install(mode: SeccompMode, io_uring_active: bool) -> anyhow::Result<()> {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (mode, io_uring_active);
        anyhow::bail!("seccomp allow-list is only defined for x86_64 and aarch64 (fail closed)");
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    match mode {
        SeccompMode::Off => {
            tracing::debug!("seccomp filter disabled by config");
            Ok(())
        }
        SeccompMode::Log => {
            let filter = build_filter(SeccompAction::Log, io_uring_active)
                .context("building seccomp log filter")?;
            apply(filter).context("installing seccomp log filter")?;
            tracing::warn!(
                "seccomp installed in LOG mode: unlisted syscalls are recorded (dmesg/auditd) but NOT blocked — no protection; flip hardening.seccomp.mode to \"enforce\" once the log is clean"
            );
            Ok(())
        }
        SeccompMode::Enforce => {
            let kill =
                build_kill_filter(io_uring_active).context("building seccomp hard-deny filter")?;
            apply(kill).context("installing seccomp hard-deny filter")?;

            let allow = build_filter(SeccompAction::Errno(libc::EPERM as u32), io_uring_active)
                .context("building seccomp allow-list filter")?;
            apply(allow).context("installing seccomp allow-list filter")?;

            tracing::info!(
                allowed = allowed_syscalls(io_uring_active).len(),
                hard_denied = dangerous_syscalls(io_uring_active).len(),
                io_uring = io_uring_active,
                "seccomp allow-list enforced (unlisted → EPERM; exploitation set → KILL)"
            );
            Ok(())
        }
    }
}

/// Compile + install one filter across ALL threads (TSYNC) — essential under a
/// multi-thread tokio runtime, so the tokio worker threads are filtered too, not
/// just the caller. `apply_filter_all_threads` also sets `PR_SET_NO_NEW_PRIVS`.
fn apply(filter: SeccompFilter) -> anyhow::Result<()> {
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e| anyhow::anyhow!("compiling seccomp BPF: {e}"))?;
    apply_filter_all_threads(&program)
        .map_err(|e| anyhow::anyhow!("applying seccomp filter: {e}"))?;
    Ok(())
}

fn build_filter(mismatch: SeccompAction, io_uring_active: bool) -> anyhow::Result<SeccompFilter> {
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = allowed_syscalls(io_uring_active)
        .into_iter()
        .map(|nr| (nr, Vec::new()))
        .collect();
    SeccompFilter::new(rules, mismatch, SeccompAction::Allow, target_arch())
        .map_err(|e| anyhow::anyhow!("constructing seccomp allow-list: {e}"))
}

fn build_kill_filter(io_uring_active: bool) -> anyhow::Result<SeccompFilter> {
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = dangerous_syscalls(io_uring_active)
        .into_iter()
        .map(|nr| (nr, Vec::new()))
        .collect();
    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        target_arch(),
    )
    .map_err(|e| anyhow::anyhow!("constructing seccomp hard-deny list: {e}"))
}

#[cfg(target_arch = "x86_64")]
fn target_arch() -> seccompiler::TargetArch {
    seccompiler::TargetArch::x86_64
}
#[cfg(target_arch = "aarch64")]
fn target_arch() -> seccompiler::TargetArch {
    seccompiler::TargetArch::aarch64
}
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn target_arch() -> seccompiler::TargetArch {
    unreachable!("seccomp is only applied on x86_64/aarch64 — install() bails otherwise")
}

/// The steady-state syscall allow-list. Deliberately generous: the ERRNO default
/// makes an omission a degraded operation, not a crash, but a complete list keeps
/// the Gateway correct. Arch-specific legacy syscalls (present only on x86_64) are
/// cfg-gated; aarch64 reaches the same behaviour through the `*at`/`*2` variants,
/// which are in the common set.
fn allowed_syscalls(io_uring_active: bool) -> Vec<libc::c_long> {
    let mut v = vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_preadv,
        libc::SYS_pwritev,
        libc::SYS_preadv2,
        libc::SYS_pwritev2,
        libc::SYS_close,
        libc::SYS_close_range,
        libc::SYS_lseek,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_fcntl,
        libc::SYS_ioctl,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_ftruncate,
        libc::SYS_flock,
        libc::SYS_fallocate,
        libc::SYS_splice,
        libc::SYS_pipe2,
        libc::SYS_ppoll,
        libc::SYS_pselect6,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_eventfd2,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_signalfd4,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_statfs,
        libc::SYS_fstatfs,
        libc::SYS_getdents64,
        libc::SYS_getcwd,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_readlinkat,
        libc::SYS_renameat2,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_umask,
        libc::SYS_utimensat,
        libc::SYS_fchdir,
        // Landlock self-confinement: a blocking-pool thread spawned AFTER seccomp is
        // installed re-confines itself via `on_thread_start` — allow these so that
        // self-confine actually runs (not merely inherits the parent's domain).
        libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_add_rule,
        libc::SYS_landlock_restrict_self,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_mlock,
        libc::SYS_mlock2,
        libc::SYS_munlock,
        // mlockall/munlockall + madvise(MADV_DONTDUMP) below are the key-buffer
        // swap/coredump hygiene; kept allowed so this sandbox never blocks it.
        libc::SYS_mlockall,
        libc::SYS_munlockall,
        libc::SYS_msync,
        libc::SYS_membarrier,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_rseq,
        libc::SYS_set_tid_address,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_setaffinity,
        libc::SYS_getpriority,
        libc::SYS_gettid,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_rt_sigpending,
        libc::SYS_rt_sigsuspend,
        libc::SYS_sigaltstack,
        libc::SYS_tgkill,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_gettimeofday,
        libc::SYS_times,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_restart_syscall,
        libc::SYS_prctl,
        libc::SYS_prlimit64,
        libc::SYS_getrusage,
        libc::SYS_sysinfo,
        libc::SYS_uname,
        libc::SYS_getrandom,
        // Credential syscalls here are read-only: the privilege drop already happened.
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getgroups,
        libc::SYS_getresuid,
        libc::SYS_getresgid,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept4,
        libc::SYS_connect,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_shutdown,
    ];

    #[cfg(target_arch = "x86_64")]
    v.extend_from_slice(&[
        libc::SYS_open,
        libc::SYS_poll,
        libc::SYS_select,
        libc::SYS_dup2,
        libc::SYS_epoll_create,
        libc::SYS_epoll_wait,
        libc::SYS_access,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_readlink,
        libc::SYS_rename,
        libc::SYS_unlink,
        libc::SYS_mkdir,
        libc::SYS_rmdir,
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_pipe,
        libc::SYS_arch_prctl,
        libc::SYS_getrlimit,
        // Legacy setrlimit (glibc routes through prlimit64, but keep it for the
        // sibling coredump-disable path that may call setrlimit directly).
        libc::SYS_setrlimit,
        // libc names SYS_sendfile/SYS_fadvise64 only on
        // x86_64-gnu, not aarch64-gnu — keeping them in the common list breaks the
        // arm64 build (E0425). The Gateway uses `splice` for the byte bridge (never
        // sendfile) and issues no posix_fadvise, so on aarch64 they are simply
        // unlisted → EPERM under the EPERM-default, harmless.
        libc::SYS_sendfile,
        libc::SYS_fadvise64,
    ]);

    // io_uring is a known sandbox-escape primitive; only allow it when the reactor
    // is actually selected (otherwise it is in the hard-deny set).
    if io_uring_active {
        v.extend_from_slice(&[
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ]);
    }

    v
}

/// Namespace *creation* via `clone`/`clone3` flags is deliberately NOT argument-filtered
/// here — the runtime depends on that thread-spawn path; the capability drop plus
/// `no_new_privs` make it impossible without CAP_SYS_ADMIN.
fn dangerous_syscalls(io_uring_active: bool) -> Vec<libc::c_long> {
    let mut v = vec![
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_process_madvise,
        libc::SYS_move_pages,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_add_key,
        libc::SYS_keyctl,
        libc::SYS_request_key,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_quotactl,
        libc::SYS_personality,
    ];

    #[cfg(target_arch = "x86_64")]
    v.extend_from_slice(&[
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_modify_ldt,
        libc::SYS_ioperm,
        libc::SYS_iopl,
        libc::SYS_uselib,
    ]);

    if !io_uring_active {
        v.extend_from_slice(&[
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ]);
    }

    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_and_deny_sets_are_disjoint() {
        for io_uring in [false, true] {
            let allow = allowed_syscalls(io_uring);
            for d in dangerous_syscalls(io_uring) {
                assert!(
                    !allow.contains(&d),
                    "syscall {d} is in BOTH the allow-list and the hard-deny set (io_uring={io_uring})"
                );
            }
        }
    }

    #[test]
    fn io_uring_syscalls_are_gated_on_the_backend() {
        assert!(dangerous_syscalls(false).contains(&libc::SYS_io_uring_setup));
        assert!(!allowed_syscalls(false).contains(&libc::SYS_io_uring_enter));
        assert!(allowed_syscalls(true).contains(&libc::SYS_io_uring_enter));
        assert!(!dangerous_syscalls(true).contains(&libc::SYS_io_uring_setup));
    }

    #[test]
    fn filters_compile() {
        for io_uring in [false, true] {
            let allow = build_filter(SeccompAction::Errno(libc::EPERM as u32), io_uring).unwrap();
            let _: BpfProgram = allow.try_into().unwrap();
            let kill = build_kill_filter(io_uring).unwrap();
            let _: BpfProgram = kill.try_into().unwrap();
        }
    }

    #[test]
    fn essential_syscalls_present() {
        let allow = allowed_syscalls(false);
        for nr in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_futex,
            libc::SYS_mmap,
            libc::SYS_epoll_pwait,
            libc::SYS_accept4,
            libc::SYS_getrandom,
            libc::SYS_clone3,
        ] {
            assert!(allow.contains(&nr), "essential syscall {nr} missing");
        }
    }
}
