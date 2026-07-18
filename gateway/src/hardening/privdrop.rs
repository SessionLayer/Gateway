//! Privilege drop after bind (Session Twenty-One, NFR-5).
//!
//! Lets the Gateway bind a privileged port (`:22`) as root and then run as an
//! unprivileged user for the rest of its life. The already-bound listening
//! sockets are plain file descriptors and survive the `setuid`, so `accept()`
//! keeps working while the process can no longer act as root.
//!
//! Correctness under multi-thread tokio: `nix::unistd::{setgroups,setgid,setuid}`
//! call the libc wrappers, which on both glibc and musl broadcast the credential
//! change to *every* thread (the POSIX `setxid` semantics) — not the per-thread
//! raw syscall. So dropping from within the running runtime affects all worker
//! threads, not just the caller.

use anyhow::{bail, Context};
use nix::unistd::{setgid, setgroups, setuid, Gid, Group, Uid, User};

/// What the drop landed on (for logging).
pub struct DropReport {
    pub uid: u32,
    pub gid: u32,
}

/// A resolved target: just the uid and its primary gid (we deliberately do not
/// carry nix's `User`, whose private `CString` fields make it awkward to build
/// for a numeric-uid-not-in-NSS case).
struct ResolvedUser {
    uid: Uid,
    primary_gid: Gid,
}

/// Drop to `user` (and `group`, or the user's primary group when blank).
///
/// Fail-closed: refuses (returns `Err`) if the process is not root, if the target
/// resolves to root (a no-op drop is almost certainly a misconfiguration), or if
/// the drop does not verifiably take and become irreversible.
pub fn drop_to(user: &str, group: &str) -> anyhow::Result<DropReport> {
    let target = resolve_user(user).with_context(|| format!("resolving run_as_user {user:?}"))?;
    let uid = target.uid;
    let gid = match group.trim() {
        "" => target.primary_gid,
        g => resolve_group(g).with_context(|| format!("resolving run_as_group {g:?}"))?,
    };

    // Must currently be root: a privileged-port bind would already have required
    // it, and setgroups/setuid to a *different* user need CAP_SETUID/CAP_SETGID.
    // Requested-but-not-root is a misconfiguration we refuse rather than limp past.
    if !Uid::current().is_root() {
        bail!(
            "run_as_user is set ({user}) but the process is not root (uid {}); \
             cannot drop privileges — either start as root to bind the privileged \
             port then drop, or clear run_as_user",
            Uid::current()
        );
    }
    if uid.is_root() {
        bail!("run_as_user {user:?} resolves to uid 0 (root); refusing a no-op privilege drop");
    }

    // Order is mandatory: shed supplementary groups and set the gid while we still
    // have the privilege to do so — AFTER setuid drops root we could no longer.
    setgroups(&[gid]).context("setgroups (dropping supplementary groups)")?;
    setgid(gid).context("setgid")?;
    setuid(uid).context("setuid")?;

    // CWE-528: `setuid` RESETS the process dumpable flag to
    // `/proc/sys/fs/suid_dumpable` (kernel `commit_creds` on any euid/egid change),
    // re-enabling the coredumps `hardening::coredump` disabled at startup. Pipe
    // `core_pattern` handlers (systemd-coredump / apport) ignore `RLIMIT_CORE`, so
    // `PR_SET_DUMPABLE=0` is the ONLY effective gate. Re-assert it IMMEDIATELY after
    // the cred change — before the verify/reversibility checks below — so the dumpable
    // window is a single instruction, not the ~4-syscall verify sequence a crash could
    // hit and spill SSH plaintext / the inner key (F-privdrop-dumpable-window-1).
    nix::sys::prctl::set_dumpable(false)
        .context("re-asserting PR_SET_DUMPABLE=0 after privilege drop")?;

    // Verify the drop took on real AND effective uid...
    if Uid::current() != uid || Uid::effective() != uid {
        bail!(
            "privilege drop did not take: real uid {}, effective uid {}",
            Uid::current(),
            Uid::effective()
        );
    }
    // ...and that it is irreversible (a full setuid from euid 0 also sets the
    // saved-set-uid, so regaining root must now be impossible). If this somehow
    // succeeds we are unexpectedly root again — abort rather than run on. (A failed
    // setuid(0) changes no creds, so the dumpable flag set above stays 0.)
    if setuid(Uid::from_raw(0)).is_ok() {
        bail!("privilege drop is reversible (regained root after setuid); aborting");
    }

    // Confirm the dumpable re-assert held (fail closed).
    if nix::sys::prctl::get_dumpable().context("reading PR_GET_DUMPABLE")? {
        bail!(
            "process still dumpable after privilege drop (setuid re-enabled coredumps); aborting"
        );
    }

    Ok(DropReport {
        uid: uid.as_raw(),
        gid: gid.as_raw(),
    })
}

/// Resolve a user by name (NSS) or, failing that, as a bare numeric uid.
fn resolve_user(spec: &str) -> anyhow::Result<ResolvedUser> {
    if let Some(u) = User::from_name(spec).context("looking up user by name")? {
        return Ok(ResolvedUser {
            uid: u.uid,
            primary_gid: u.gid,
        });
    }
    if let Ok(raw) = spec.trim().parse::<u32>() {
        if let Some(u) = User::from_uid(Uid::from_raw(raw)).context("looking up user by uid")? {
            return Ok(ResolvedUser {
                uid: u.uid,
                primary_gid: u.gid,
            });
        }
        // A numeric uid NSS does not know (common in distroless/scratch images):
        // still usable for the drop, with the uid doubling as its primary gid
        // unless the caller overrides `run_as_group`.
        return Ok(ResolvedUser {
            uid: Uid::from_raw(raw),
            primary_gid: Gid::from_raw(raw),
        });
    }
    bail!("no such user {spec:?}")
}

/// Resolve a group by name (NSS) or as a bare numeric gid.
fn resolve_group(spec: &str) -> anyhow::Result<Gid> {
    if let Some(g) = Group::from_name(spec).context("looking up group by name")? {
        return Ok(g.gid);
    }
    if let Ok(raw) = spec.trim().parse::<u32>() {
        return Ok(Gid::from_raw(raw));
    }
    bail!("no such group {spec:?}")
}
