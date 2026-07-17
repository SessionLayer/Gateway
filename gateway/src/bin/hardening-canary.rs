//! Test-only canary for the Tier-0 hardening profile (Session Twenty-One).
//!
//! `tests/hardening_e2e.rs` spawns this binary so the REAL seccomp/Landlock/
//! coredump code (`gateway::hardening`) can be applied in a subprocess — never in
//! the test runner, since those restrictions are irreversible and process-wide.
//! Each mode applies the profile to itself, then does one representative thing the
//! test asserts on. Kept out of release builds by `required-features`.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("hardening-canary is Linux-only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    use gateway::hardening;
    use gateway_core::config::{HardeningConfig, LandlockConfig};

    let mode = std::env::args().nth(1).unwrap_or_default();
    let arg = std::env::args().nth(2).unwrap_or_default();

    match mode.as_str() {
        // Apply seccomp=enforce, then exercise the data path. Every syscall the SSH
        // data plane needs must survive; a missing allow-list entry would EPERM here.
        "io" => {
            apply_seccomp();
            data_path_io().unwrap_or_else(|e| fail(&format!("IO_FAIL: {e}")));
            println!("IO_OK");
        }
        // Apply seccomp=enforce, then execve directly — it is in the hard-deny set,
        // so the kernel must KILL this process with SIGSYS before execv returns.
        "execve" => {
            apply_seccomp();
            let path = std::ffi::CString::new("/bin/true").unwrap();
            let _ = nix::unistd::execv(&path, std::slice::from_ref(&path));
            // Reached only if execve was NOT killed (it should have been) — the test
            // asserts on the SIGSYS death, so this line printing is a failure signal.
            println!("EXECVE_RETURNED");
        }
        // Confine to a temp dir, then prove a path OUTSIDE it is denied while the
        // allowed path works. `arg` = the allowed read-write dir.
        "landlock" => {
            let cfg = HardeningConfig {
                landlock: LandlockConfig {
                    enabled: true,
                    read_only_paths: vec![],
                    read_write_paths: vec![arg.clone().into()],
                },
                disable_coredumps: false,
                ..Default::default()
            };
            hardening::apply(&cfg, false).unwrap_or_else(|e| fail(&format!("APPLY_FAIL: {e}")));
            let inside = std::path::Path::new(&arg).join("probe");
            std::fs::write(&inside, b"ok")
                .unwrap_or_else(|e| fail(&format!("ALLOWED_DENIED: {e}")));
            match std::fs::read("/etc/hostname") {
                Ok(_) => println!("LANDLOCK_LEAK"), // read outside the allow-set — bug
                Err(_) => println!("LANDLOCK_CONFINED"),
            }
        }
        // Deterministic coredump proof: after disable, RLIMIT_CORE must read back 0.
        "coredump-check" => {
            hardening::disable_coredumps(&HardeningConfig::default())
                .unwrap_or_else(|e| fail(&format!("DISABLE_FAIL: {e}")));
            let (soft, hard) =
                nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_CORE)
                    .unwrap_or_else(|e| fail(&format!("GETRLIMIT_FAIL: {e}")));
            println!("RLIMIT_CORE soft={soft} hard={hard}");
        }
        // Coredump proof: enable core dumps, put a secret in memory, disable
        // coredumps via the REAL code, then crash. The parent greps for the secret.
        "coredump" | "coredump-nodisable" => {
            let _ = nix::sys::resource::setrlimit(
                nix::sys::resource::Resource::RLIMIT_CORE,
                u64::MAX,
                u64::MAX,
            );
            let unit = if arg.is_empty() {
                "SECRET"
            } else {
                arg.as_str()
            };
            // A heap buffer full of the secret marker, kept from being optimized out.
            let secret = unit.repeat(4096 / unit.len() + 1).into_bytes();
            std::hint::black_box(&secret);
            if mode == "coredump" {
                hardening::disable_coredumps(&HardeningConfig::default())
                    .unwrap_or_else(|e| fail(&format!("DISABLE_FAIL: {e}")));
            }
            std::hint::black_box(&secret);
            // Force a crash so the kernel would dump core (if it were allowed to).
            std::process::abort();
        }
        other => fail(&format!("unknown mode {other:?}")),
    }
}

#[cfg(target_os = "linux")]
fn apply_seccomp() {
    use gateway_core::config::{HardeningConfig, SeccompConfig, SeccompMode};
    let cfg = HardeningConfig {
        seccomp: SeccompConfig {
            mode: SeccompMode::Enforce,
        },
        disable_coredumps: false,
        ..Default::default()
    };
    gateway::hardening::apply(&cfg, false).unwrap_or_else(|e| fail(&format!("APPLY_FAIL: {e}")));
}

/// Representative data-path syscalls the hardened profile must still permit:
/// file create/write/read, a TCP socket bind, thread spawn/join, /dev/urandom.
#[cfg(target_os = "linux")]
fn data_path_io() -> std::io::Result<()> {
    use std::io::{Read, Write};
    // File I/O (openat/write/read/close).
    let dir = std::env::temp_dir();
    let path = dir.join(format!("gw-canary-{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&path)?;
        f.write_all(b"data-path")?;
        f.sync_all()?;
    }
    let mut buf = Vec::new();
    std::fs::File::open(&path)?.read_to_end(&mut buf)?;
    let _ = std::fs::remove_file(&path);
    // Socket create + bind (socket/bind/listen).
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let _ = listener.local_addr()?;
    // Thread spawn/join (clone3/futex).
    std::thread::spawn(|| std::hint::black_box(1 + 1))
        .join()
        .ok();
    // Kernel RNG (getrandom, or /dev/urandom fallback).
    let mut rnd = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut rnd)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1);
}
