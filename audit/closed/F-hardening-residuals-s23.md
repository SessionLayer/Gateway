# F-hardening-residuals-s23: Tier-0 hardening residuals (OTLP-threads/Landlock, ioctl breadth, clone3)
- Severity: low
- Status: Accepted-Risk
- Area: hardening

Three S23 A7 hardening residuals, each accepted with justification (all fail SAFE,
each backstopped by an independent control).

## A7-F4 — OTLP export threads escape the Landlock domain (both binaries)
The OTLP batch-export OS thread (opentelemetry_sdk BatchSpanProcessor + the Agent's
dedicated export runtime) is created in `telemetry::init` BEFORE `hardening::apply`.
Landlock has no TSYNC, so `restrict_self` covers only the calling thread + threads
spawned AFTER it → these pre-existing threads are outside the Landlock fs domain (and,
on the Agent, the net-egress port allow-list). **Accepted:** OTLP is opt-in (off unless
`OTEL_EXPORTER_OTLP_ENDPOINT` set); the threads ARE still covered by seccomp (TSYNC),
privilege-drop (process-wide setxid) and DAC; and the load-bearing egress control is
the shipped k8s **NetworkPolicy** (kernel netfilter, all-thread) per S21, not the
in-process Landlock net backstop. Reordering telemetry-after-hardening would lose
startup traces; the docstring is the follow-up to tighten.

## A7-F6 — Gateway `ioctl` blanket-allowed (Agent arg-restricts it)
The Gateway seccomp allow-lists `SYS_ioctl` unconditionally; the Agent arg-restricts it
to FIONREAD/FIONBIO (killing TIOCSTI etc.). **Accepted:** the Gateway daemon holds no
tty fd, so the TIOCSTI input-injection primitive is unreachable; arg-restriction is
defense-in-depth over a non-reachable threat. Tightening to arg-restriction is a clean
future hardening.

## A7-F7 — clone3 unfiltered → unprivileged user-namespace creation not seccomp-blocked
Both binaries allow `clone3` unconditionally. Docker's default profile ENOSYS's clone3
to force the filterable `clone` path. **Accepted (inherent):** clone3's flags live in a
struct seccomp cannot dereference, so a flag-level filter is not expressible; and the
impact is bounded — `mount`/`pivot_root`/`setns`/`unshare` are KILL'd and the inherited
Landlock domain cannot be dropped inside a new userns, so escape utility is low. This is
the standard seccomp limitation, documented at the call site.
