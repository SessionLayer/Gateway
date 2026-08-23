//! Privilege drop: setgroups/setgid/setuid through the glibc/musl `setxid` wrappers,
//! which broadcast the drop to ALL threads.

use anyhow::{bail, Context};
use nix::unistd::{setgid, setgroups, setuid, Gid, Group, Uid, User};

pub struct DropReport {
    pub uid: u32,
    pub gid: u32,
}

struct ResolvedUser {
    uid: Uid,
    primary_gid: Gid,
}

pub fn drop_to(user: &str, group: &str) -> anyhow::Result<DropReport> {
    let target = resolve_user(user).with_context(|| format!("resolving run_as_user {user:?}"))?;
    let uid = target.uid;
    let gid = match group.trim() {
        "" => target.primary_gid,
        g => resolve_group(g).with_context(|| format!("resolving run_as_group {g:?}"))?,
    };

    if !Uid::current().is_root() {
        bail!(
            "run_as_user is set ({user}) but the process is not root (uid {}); \
             cannot drop privileges - either start as root to bind the privileged \
             port then drop, or clear run_as_user",
            Uid::current()
        );
    }
    if uid.is_root() {
        bail!("run_as_user {user:?} resolves to uid 0 (root); refusing a no-op privilege drop");
    }

    setgroups(&[gid]).context("setgroups (dropping supplementary groups)")?;
    setgid(gid).context("setgid")?;
    setuid(uid).context("setuid")?;

    nix::sys::prctl::set_dumpable(false)
        .context("re-asserting PR_SET_DUMPABLE=0 after privilege drop")?;

    if Uid::current() != uid || Uid::effective() != uid {
        bail!(
            "privilege drop did not take: real uid {}, effective uid {}",
            Uid::current(),
            Uid::effective()
        );
    }
    // ...and that it is irreversible (a full setuid from euid 0 also sets the
    // saved-set-uid, so regaining root must now be impossible). If this somehow
    // succeeds we are unexpectedly root again - abort rather than run on. (A failed
    // setuid(0) changes no creds, so the dumpable flag set above stays 0.)
    if setuid(Uid::from_raw(0)).is_ok() {
        bail!("privilege drop is reversible (regained root after setuid); aborting");
    }

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

fn resolve_group(spec: &str) -> anyhow::Result<Gid> {
    if let Some(g) = Group::from_name(spec).context("looking up group by name")? {
        return Ok(g.gid);
    }
    if let Ok(raw) = spec.trim().parse::<u32>() {
        return Ok(Gid::from_raw(raw));
    }
    bail!("no such group {spec:?}")
}
