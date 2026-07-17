# F-seccomp-posture-1: seccomp default-action posture for a long-lived Tier-0 daemon
- Severity: info
- Status: Verified-Fixed
- Area: hardening

## Decision (documented)
The seccomp filter (`hardening::seccomp`) uses a **hybrid** posture, deliberately
NOT a pure KILL-default allow-list:
- **Default (mismatch) action = `ERRNO(EPERM)`** for any unlisted syscall. A
  KILL-default is *fail-deadly* for a long-lived Tier-0 daemon that holds many live
  plaintext SSH sessions: one syscall introduced by a future tokio/ring/russh/tonic/
  glibc bump that was not harvested into the allow-list would `SIGSYS` the process
  and drop **every** live session — an availability incident plus fail-open pressure
  to disable seccomp. EPERM-default is fail-safe and robust to library drift (a
  missed rare-path syscall degrades that one operation, not the process). This is
  the Docker-default-profile posture.
- **Hard-deny (KILL_PROCESS) denylist** for the exploitation set that must never
  occur: `execve`/`execveat`/`fork`/`vfork`/`ptrace`/`process_vm_*`/`process_madvise`/
  `move_pages`/`kexec_*`/`*_module`/`mount`/`umount2`/`pivot_root`/`chroot`/`setns`/
  `unshare`/`add_key`/`keyctl`/`request_key`/`bpf`/`perf_event_open`/`userfaultfd`/
  `personality`/… — a `SIGSYS` here is the correct, observable response to a
  compromise. `clone`/`clone3` stay allowed (threads); a cloned thread still cannot
  `execve`, so the shell-spawn chain is cut.
- **`io_uring_{setup,enter,register}`** are KILL-denied **unless** the io_uring
  reactor is actually selected at runtime (gated on `cfg.io_backend`; epoll is the
  default) — io_uring is a favourite sandbox-escape primitive.
- Installed with `TSYNC` (`apply_filter_all_threads`) so it reaches every tokio
  worker. Modes `off | log | enforce`; `log` (SECCOMP_RET_LOG) is the discovery
  roll-out mode.

The Agent repo uses a `KillProcess`-default for its own (shorter-lived, fewer
concurrent sessions) threat model — an intentional per-threat-model divergence, not
an inconsistency.

## Proof
`gateway/tests/hardening_e2e.rs` (`data_path_survives_seccomp_enforce`,
`execve_is_killed_under_seccomp`, `io_uring_syscalls_are_gated_on_the_backend`) +
the allow/deny-disjoint + filter-assembly unit tests in `hardening::seccomp`.
Allow-list to be harvested against the widest binary-driven exercise (shell + exec +
sftp + scp + recorder finalize + agent path + a deny/error path) under `log` mode;
`deploy/README.md` documents the roll-out.
