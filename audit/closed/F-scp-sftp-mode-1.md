# F-scp-sftp-mode-1: SCP capability only gates legacy scp-as-exec; modern scp rides the SFTP subsystem
- Severity: info
- Status: Verified-Fixed
- Area: capability

## Observation (T3: protocol reviewer)
`required_capability` maps an `exec` whose first word is `scp` to `Capability::Scp`, and
the `sftp` subsystem to `Capability::Sftp` (`handler.rs:967-975`). `is_scp_command`
(`handler.rs:979`) takes the exec command, splits on whitespace, strips any path with
`rsplit('/')`, and compares the basename to `"scp"`. That detection is **reasonable and
false-positive-safe**: OpenSSH's legacy scp always invokes exactly `scp -t <path>` /
`scp -f <path>` as the remote exec, so first-word matching is accurate; a script named
`scp_backup.sh` does not match (basename `!=` "scp"); `/usr/bin/scp` does match. The node
re-enforces the principal regardless, per the comment.

The nuance operators must know: since OpenSSH 9.0 the **`scp` client uses the SFTP
protocol by default** — it opens the `sftp` **subsystem**, not an `scp -t/-f` exec. So a
modern `scp` transfer is gated by `Capability::Sftp`, and the `Capability::Scp` gate only
catches *legacy-mode* scp (`scp -O`, or old clients). Consequences:
- Granting **Scp but not Sftp** breaks modern `scp` clients (they open sftp → refused),
  while `scp -O` still works — surprising and hard to diagnose.
- Granting **Sftp** implicitly permits modern `scp` file transfer as well as interactive
  `sftp`, since both ride the same subsystem — the two are not separable at the SSH layer.

## Impact
No security gap (both paths are gated; nothing is silently allowed). It is a
capability-model / operator-expectation nuance that will produce confusing "scp works but
only sometimes" reports if undocumented.

## Fix
Documentation only for S8: note in DATA-MODEL / the capability docs that (1) `Scp` gates
legacy scp-as-exec, (2) modern scp is gated by `Sftp` and cannot be separated from
interactive sftp at the protocol layer, and (3) to fully block file transfer both `Scp`
and `Sftp` must be withheld. No code change required.

## Resolution (Verified-Fixed)
The capgate refactor (F-capgate-scp-1) makes SCP admit the sftp subsystem alongside SFTP, so granting SCP no longer breaks modern scp. The doc-comment on `required_capabilities` records the nuance: SCP gates legacy scp-as-exec, modern scp rides the sftp subsystem (gated by SFTP-or-SCP), and to block file transfer both must be withheld. Info → documented + improved.
