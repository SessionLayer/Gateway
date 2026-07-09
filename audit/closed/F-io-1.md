# F-io-1: UringIo::block_on nested-runtime foot-gun (undocumented panic edge)
- Severity: info
- Status: Verified-Fixed
- Area: io

**Issue.** `UringIo::block_on` (`#[cfg(io-uring)]`) calls `tokio_uring::start`,
which spins up its own runtime and panics if called from within an existing
tokio runtime. Unreachable in Session One (no SSH I/O), but a live public API
with a panic edge for the next session's author.

**Fix.** Documented the precondition on the method: must be called on a
dedicated OS thread not already inside a tokio runtime; the SSH bridge will
drive it on its own thread.

**Verification.** Doc comment added; not exercised (correct — sandboxes may
lack io_uring syscalls).
