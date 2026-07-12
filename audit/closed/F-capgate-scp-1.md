# F-capgate-scp-1: SCP capability ≈ EXEC — first-token classification lets an scp-only grant run arbitrary commands on the node
- Severity: medium
- Status: Verified-Fixed
- Area: authz

## Summary (T3: redteam-auditor)
The channel-open capability gate classifies an `exec` request as the `SCP`
capability by matching only the **first whitespace token's basename** against
`"scp"` (`is_scp_command`, `handler.rs:979-985`; used by `required_capability`,
`handler.rs:967-975`). A decision context that grants `CAPABILITY_SCP` but
withholds `CAPABILITY_EXEC`/`CAPABILITY_SHELL` — the natural "file-transfer only"
least-privilege grant — therefore admits **arbitrary program execution** on the
node as the granted principal. This violates FR-AUTHZ-6, which requires each
capability (`shell`,`exec`,`sftp`,`scp`,…) to be *independently grantable* and
*enforced at the Gateway*.

## Root cause / data flow
Source (attacker-controlled): the outer `exec_request` payload
(`handler.rs:853-863`) → `ChannelKind::Exec(cmd)` → `required_capability`:

```rust
ChannelKind::Exec(cmd) if is_scp_command(cmd) => Capability::Scp,
```

`is_scp_command` inspects only `split_whitespace().next()` and its `/`-basename.
Any exec whose first token is `scp` (or `.../scp`) is gated by `SCP`, and the gate
(`handler.rs:462`) admits it whenever `SCP` is in the granted set. The **entire
command string is then forwarded verbatim** to the node
(`InnerClient::open_channel` → `channel.exec(false, cmd)`, `innerleg.rs:170`),
where the node's `sshd` runs it via the login shell (`$SHELL -c "<cmd>"`). The
missing control is any validation that the exec is actually a benign scp
source/sink invocation.

Two independent escape vectors, both admitted under an scp-only grant:
- **`scp -S <program> …`** — scp's documented `-S` flag runs `<program>` as the
  transport, i.e. arbitrary program execution (`scp -S /bin/sh a b`).
- **shell metacharacters** — `scp x y; <command>` / `scp $(<command>)` — the node
  shell executes the trailing command.

## Proof of concept (source-faithful, local)
`scratchpad/scp_poc.rs` copies `is_scp_command` + `required_capability` verbatim
and runs the gate against a `granted = [SCP, SFTP]` set (exec+shell withheld):

```
exec "scp -S /bin/sh x y"                      -> gate demands Scp  admitted=true
exec "scp x y; id > /tmp/pwn"                   -> gate demands Scp  admitted=true
exec "/usr/bin/scp -S /usr/bin/id a b"          -> gate demands Scp  admitted=true
exec "scp -F /dev/null -o ProxyCommand=id a b"  -> gate demands Scp  admitted=true
exec "id"                                       -> gate demands Exec admitted=false   (control)
```

Every `scp …` payload is classified `SCP` and admitted; the honest arbitrary exec
`id` is correctly gated by `EXEC` and denied. The node then runs the admitted
string under the principal's shell. (An end-to-end run against `testing/docker/sshd`
would drop `-S /bin/sh` and observe the spawned shell; the classification above is
the whole of the gateway-side control, so the unit PoC is dispositive.)

## Impact
A "file-transfer only" policy (grant `scp`+`sftp`, withhold `shell`+`exec`) does
**not** restrict the user to file transfer: they obtain arbitrary command
execution as the granted Linux principal. No privilege escalation *beyond* the
granted principal (the node re-enforces the Linux user), but a full escape from
the intended capability boundary — the least-privilege guarantee the product
sells. Also affects SFTP-subsystem callers only indirectly (that path is gated by
`SFTP`, correctly). The `SHELL`/`EXEC`/`SFTP` gates themselves are sound; only the
legacy-scp-over-exec path is confused.

## Remediation
Legacy scp is inherently `exec` of the `scp` binary with attacker-controlled argv,
so first-token matching can never make it a safe standalone capability. Options,
strongest first:

1. **Require `EXEC` for legacy-scp exec, and gate true SCP on the SFTP subsystem
   only.** Modern OpenSSH (9.0+) runs `scp` over the SFTP subsystem; gate `SCP`
   there (alongside `SFTP`) and treat a raw `exec scp …` as needing `EXEC`. This
   matches Design §12.1 ("both scp modes: legacy exec + modern SFTP-subsystem") and
   makes the capability boundary real.
2. If legacy-scp-over-exec must be supported as a standalone grant, **parse and
   allowlist the scp argv**: require the first token to be exactly `scp`/`/usr/bin/scp`,
   require an `-t`/`-f` (sink/source) mode flag, and **reject** `-S`, `-o`, `-F`,
   `-D`, and any shell metacharacter (`; | & $ \` ( ) < > \n`) in the command. Deny
   on any parse ambiguity (fail closed).
3. At minimum, **document** that a legacy-scp grant is equivalent to exec-of-scp
   and MUST NOT be marketed as a command-execution restriction.

Add a regression test asserting `required_capability(Exec("scp -S /bin/sh a b"))`
is **not** admitted by an scp-only grant (it should require `EXEC`, or be rejected
by argv validation).

## References
FR-AUTHZ-6 (independent capability grantability, Gateway-enforced); FR-SESS-1
(both SCP modes); Design §6.1 / §12.1; CWE-77 (command injection via argument
smuggling), CWE-863 (incorrect authorization).

## Resolution (Verified-Fixed)
Replaced the first-token scp classification with `required_capabilities` returning an acceptable-capability set. Legacy scp-over-exec now requires **EXEC** (never a standalone SCP), so `scp -S <prog>` / metacharacter smuggling is no longer admitted by an scp-only grant; modern scp (sftp subsystem) is admitted by SCP or SFTP. Regression test `capability_gate_never_admits_scp_exec_or_unknown_subsystem`.
