# F-landlock-tsync-1: Landlock applied after the tokio workers spawned would not confine them
- Severity: high
- Status: Verified-Fixed
- Area: hardening

## Risk
The first draft applied the Landlock filesystem confinement from
`hardening::apply`, which runs **inside** `runtime.block_on` — i.e. AFTER the
multi-threaded tokio runtime has already spawned its worker threads. Unlike
seccomp (`apply_filter_all_threads` uses `TSYNC`) and the privilege drop (glibc/musl
`setxid` broadcast), Landlock's `landlock_restrict_self` has **no TSYNC**: it
confines only the calling thread and its *future* children, never pre-existing
sibling threads. Since the tokio workers do the actual accept / inner-dial /
byte-bridge / recorder I/O, they would have run **un-confined** — the FS
restriction would have been silently defeated for the threads that matter, while
appearing enabled. (Cross-caught by the Agent teammate; same class they hit.)

## Resolution (Verified-Fixed)
Each runtime thread self-confines as it spawns: `main::run` wires
`hardening::confine_thread_for_landlock` into `tokio::runtime::Builder::on_thread_start`
(fires for every worker AND blocking-pool thread), and the main thread confines
itself in `hardening::apply`. So every thread that can touch the filesystem is in
the Landlock domain. Fail-closed: a thread that cannot apply a *required*
confinement cannot return an error to the runtime, so it aborts the process.

Ordering note (verified against the enroll/bind flow): `on_thread_start` runs at
runtime build, so the workers are confined **before** bind + mTLS enrollment.
The ruleset must therefore allow the enroll/bind working set — the data-dir
(read-write), the CA/config paths, the NSS/resolver + library dirs. Network egress
(CP / node / WORM / peer-relay) is unaffected: Landlock ABI ≤ V3 does not restrict
network, so a too-tight FS ruleset cannot masquerade as "CP unreachable" at the
socket layer (it surfaces as an EACCES on a file, not a connect failure).

## Proof
`gateway/tests/hardening_e2e.rs::landlock_confines_to_allowed_paths` (a path outside
the allow-set is denied; the allowed dir is writable). The load-bearing evidence
that per-worker confinement carries the data path — a real shell+exec+sftp session
whose worker-thread bridge I/O succeeds under Landlock — is the full-stack harness
under `FS_HARDENING=full`.
