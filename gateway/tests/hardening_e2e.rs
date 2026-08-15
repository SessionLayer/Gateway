//! Per-PR proof that the Tier-0 hardening profile is CORRECT and does not break
//! the SSH data path. It spawns the `hardening-canary`
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

#[test]
fn coredumps_disabled_rlimit_zero_and_not_dumpable() {
    let r = run(&["coredump-check"], &std::env::temp_dir());
    assert!(
        r.status.success()
            && r.stdout.contains("RLIMIT_CORE soft=0")
            && r.stdout.contains("DUMPABLE=false"),
        "coredump controls not fully disabled (stdout={:?})",
        r.stdout
    );
}

#[test]
fn forced_crash_produces_no_core_with_secret() {
    const SECRET: &str = "CANARY_PLAINTEXT_MARKER_9f3a";

    let neg_dir = tempfile::tempdir().unwrap();
    let neg = run(&["coredump-nodisable", SECRET], neg_dir.path());
    assert_eq!(
        neg.status.signal(),
        Some(libc::SIGABRT),
        "canary should abort"
    );
    let leak_detectable = core_dir_contains(neg_dir.path(), SECRET);

    // The assertion below is a negative control: it only proves anything if a crash
    // WITHOUT the protection (just above) is known to leave a local, readable core
    // file here. On a host whose core_pattern pipes elsewhere (systemd-coredump,
    // apport, ...) that negative control never fires, and the "no core" assertion
    // would then pass identically whether RLIMIT_CORE=0/PR_SET_DUMPABLE=0 ran or
    // were deleted entirely -- a silently vacuous pass, not evidence. Refuse to
    // claim a proof this environment cannot produce instead of quietly passing.
    assert!(
        leak_detectable,
        "cannot exercise this guard on this host: core_pattern is {:?}, which does not \
         leave a local, readable core file, so a passing coredump-disable assertion here \
         would be indistinguishable from the protection being deleted. Re-run with \
         core_pattern set to a local-file pattern (e.g. `core`) to get real coverage. \
         RLIMIT_CORE=0 / PR_SET_DUMPABLE=0 are independently asserted by \
         `coredumps_disabled_rlimit_zero_and_not_dumpable`, which does not depend on \
         core_pattern.",
        core_pattern(),
    );

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
}

fn core_pattern() -> String {
    std::fs::read_to_string("/proc/sys/kernel/core_pattern")
        .unwrap_or_default()
        .trim()
        .to_string()
}

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
