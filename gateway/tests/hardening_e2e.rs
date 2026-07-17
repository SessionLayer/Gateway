//! Per-PR proof that the Tier-0 hardening profile is CORRECT and does not break
//! the SSH data path (Session Twenty-One, NFR-5). It spawns the `hardening-canary`
//! binary — which applies the REAL `gateway::hardening` seccomp/Landlock/coredump
//! code to itself in a fresh process — and asserts on the outcome, so nothing
//! sandboxes the test runner. The authoritative full-session proof (real CP + node
//! + binary under the profile) is the full-stack harness under `FS_HARDENING=full`.
//!
//! Gated on the `hardening-canary` feature so `CARGO_BIN_EXE_hardening-canary`
//! exists; the gate runs `--all-features`, so it is live on every PR.
#![cfg(all(feature = "hardening-canary", target_os = "linux"))]

use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;

const CANARY: &str = env!("CARGO_BIN_EXE_hardening-canary");

struct Run {
    status: std::process::ExitStatus,
    stdout: String,
}

fn run(args: &[&str], cwd: &Path) -> Run {
    let out = Command::new(CANARY)
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn hardening-canary");
    Run {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

/// Under `seccomp=enforce` the SSH data-path syscalls (file I/O, socket bind,
/// thread spawn, kernel RNG) all still succeed — the allow-list is complete.
#[test]
fn data_path_survives_seccomp_enforce() {
    let r = run(&["io"], &std::env::temp_dir());
    assert!(
        r.status.success() && r.stdout.contains("IO_OK"),
        "data path broke under seccomp enforce: status={:?} stdout={:?}",
        r.status,
        r.stdout
    );
}

/// `execve` is in the hard-deny set, so a direct call KILLS the process with
/// SIGSYS — the shell-spawn chain a post-exploitation payload needs is cut.
#[test]
fn execve_is_killed_under_seccomp() {
    let r = run(&["execve"], &std::env::temp_dir());
    assert_eq!(
        r.status.signal(),
        Some(libc::SIGSYS),
        "execve was not SIGSYS-killed (stdout={:?}, status={:?})",
        r.stdout,
        r.status
    );
    assert!(
        !r.stdout.contains("EXECVE_RETURNED"),
        "execve returned instead of being killed"
    );
}

/// Landlock confines the process to the declared paths: the allowed dir is
/// writable, a path outside it (`/etc/hostname`) is not readable.
#[test]
fn landlock_confines_to_allowed_paths() {
    let dir = tempfile::tempdir().unwrap();
    let r = run(&["landlock", dir.path().to_str().unwrap()], dir.path());
    assert!(
        r.status.success() && r.stdout.contains("LANDLOCK_CONFINED"),
        "landlock did not confine (status={:?} stdout={:?})",
        r.status,
        r.stdout
    );
    assert!(
        !r.stdout.contains("LANDLOCK_LEAK"),
        "read a path outside the allow-set"
    );
}

/// Coredump-disable is verifiable directly: after it, `RLIMIT_CORE` is 0.
#[test]
fn coredumps_disabled_rlimit_zero() {
    let r = run(&["coredump-check"], &std::env::temp_dir());
    assert!(
        r.status.success() && r.stdout.contains("RLIMIT_CORE soft=0"),
        "RLIMIT_CORE not zeroed (stdout={:?})",
        r.stdout
    );
}

/// Forcing a crash after coredump-disable yields NO core file carrying the secret,
/// even though core dumps were explicitly re-enabled first. A negative control
/// (no disable) confirms the grep can actually catch a leak when the host's
/// `core_pattern` writes a local file (otherwise the check is skipped).
#[test]
fn forced_crash_produces_no_core_with_secret() {
    const SECRET: &str = "CANARY_PLAINTEXT_MARKER_9f3a";

    // Negative control: without disable, does a local core with the secret appear?
    let neg_dir = tempfile::tempdir().unwrap();
    let neg = run(&["coredump-nodisable", SECRET], neg_dir.path());
    assert_eq!(
        neg.status.signal(),
        Some(libc::SIGABRT),
        "canary should abort"
    );
    let leak_detectable = core_dir_contains(neg_dir.path(), SECRET);

    // The real proof: WITH disable, no core with the secret is written.
    let dir = tempfile::tempdir().unwrap();
    let r = run(&["coredump", SECRET], dir.path());
    assert_eq!(
        r.status.signal(),
        Some(libc::SIGABRT),
        "canary should abort"
    );
    assert!(
        !core_dir_contains(dir.path(), SECRET),
        "a core dump containing the plaintext secret was produced despite coredump-disable"
    );

    if !leak_detectable {
        eprintln!(
            "note: host core_pattern does not write a local core (likely a pipe); the \
             crash-grep is inconclusive, but RLIMIT_CORE=0 + PR_SET_DUMPABLE=0 are asserted \
             elsewhere. To exercise the grep, run where core_pattern='core'."
        );
    }
}

/// True if any `core*` file directly under `dir` contains `needle`.
fn core_dir_contains(dir: &Path, needle: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        if name.to_string_lossy().starts_with("core") {
            if let Ok(bytes) = std::fs::read(e.path()) {
                if bytes.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                    return true;
                }
            }
        }
    }
    false
}
