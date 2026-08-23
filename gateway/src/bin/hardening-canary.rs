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
        "io" => {
            apply_seccomp();
            data_path_io().unwrap_or_else(|e| fail(&format!("IO_FAIL: {e}")));
            println!("IO_OK");
        }
        "execve" => {
            apply_seccomp();
            let path = std::ffi::CString::new("/bin/true").unwrap();
            let _ = nix::unistd::execv(&path, std::slice::from_ref(&path));
            println!("EXECVE_RETURNED");
        }
        "landlock" => {
            let cfg = HardeningConfig {
                landlock: LandlockConfig {
                    enabled: true,
                    required: false,
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
                Ok(_) => println!("LANDLOCK_LEAK"),
                Err(_) => println!("LANDLOCK_CONFINED"),
            }
        }
        "coredump-check" => {
            hardening::disable_coredumps(&HardeningConfig::default())
                .unwrap_or_else(|e| fail(&format!("DISABLE_FAIL: {e}")));
            let (soft, hard) =
                nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_CORE)
                    .unwrap_or_else(|e| fail(&format!("GETRLIMIT_FAIL: {e}")));
            let dumpable = nix::sys::prctl::get_dumpable()
                .unwrap_or_else(|e| fail(&format!("GETDUMPABLE_FAIL: {e}")));
            println!("RLIMIT_CORE soft={soft} hard={hard} DUMPABLE={dumpable}");
        }
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
            let secret = unit.repeat(4096 / unit.len() + 1).into_bytes();
            std::hint::black_box(&secret);
            if mode == "coredump" {
                hardening::disable_coredumps(&HardeningConfig::default())
                    .unwrap_or_else(|e| fail(&format!("DISABLE_FAIL: {e}")));
            }
            std::hint::black_box(&secret);
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

#[cfg(target_os = "linux")]
fn data_path_io() -> std::io::Result<()> {
    use std::io::{Read, Write};
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
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let _ = listener.local_addr()?;
    std::thread::spawn(|| std::hint::black_box(1 + 1))
        .join()
        .ok();
    let mut rnd = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut rnd)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1);
}
