# F-agentcfg-bounds-1: unbounded HELLO_ACK parameters — a misconfigured Gateway boots healthy and is then refused by the entire agent fleet
- Severity: low
- Status: Verified-Fixed
- Area: config

## Risk

`ssh::validate_agent_config` bounded the two values the Gateway proposes in `HELLO_ACK`
only from below:

- `heartbeat_interval_secs` — required `> 0`, **no upper bound**.
- `max_frame_bytes` — required `> inner.max_packet_bytes` (32 KiB), **no upper bound**.

The Agent (independently, per its own reading of the contract) *refuses* a `HELLO_ACK`
proposing `heartbeat_interval_secs` outside 1–300 s or `max_frame_bytes` outside
4 KiB–1 MiB.

So an operator setting e.g. `max_frame_bytes = 2MiB` or `heartbeat_interval_secs = 600`
produced a Gateway that:

1. passed startup validation and came up **healthy**;
2. was then **refused by every Agent in the fleet** at the preface;
3. left **every outbound-agent node reporting "offline"** (§7.1 / FR-SESS-5) — the correct
   fail-closed outcome for an unreachable node, and therefore an outage that looks exactly
   like a network problem rather than like the misconfiguration it is.

This is a **fail-open-to-outage** misconfiguration: no security bypass (the deny path is
intact and the user-visible outcome is correct), but the failure surfaces at the far end
of the fleet instead of at the boot that caused it.

## Root cause — a contract defect, not just a missing check

The Gateway and the Agent had each *invented* a range that the other did not share. The
missing upper bound was the symptom; the absence of a single normative range was the
cause. Found during S14 cross-repo interop review (ag-engineer2), not by either
implementation's own tests — neither could have caught it alone, since each was
self-consistent.

## Fix (Verified-Fixed)

- **Contract first** (CP `2843f42`): §3 now makes the bounds normative and shared —
  `heartbeat_interval_secs` **1–300**, `max_frame_bytes` **4096–1048576** — and states
  that a Gateway MUST reject an out-of-range value **at startup**, precisely so it cannot
  come up healthy and be silently refused by every Agent.
- `agent/mod.rs`: the ranges are named constants (`HEARTBEAT_INTERVAL_SECS_RANGE`,
  `MAX_FRAME_BYTES_RANGE`) living beside the wire protocol they belong to — not numbers
  re-chosen at the validation site.
- `ssh/mod.rs::validate_agent_config`: rejects an out-of-range value at startup, citing the
  contract §3 range in the error so an operator is told what is legal. `max_frame_bytes`
  must still additionally clear this Gateway's `inner.max_packet_bytes`.
- Tests: `ssh::tests::agent_transport_bounds_fail_closed` now asserts both the illegal
  values (2 MiB / 2 KiB frames; 600 s / 0 s heartbeat) are refused **and** that the legal
  edges (1 MiB, 1 s, 300 s) are accepted — a bound that rejected valid configuration would
  be its own outage. `config::tests::agent_transport_is_off_by_default_with_fail_closed_bounds`
  asserts the shipped defaults (64 KiB / 20 s) sit inside the contract range, so an
  out-of-the-box Gateway is one every Agent will accept.

## Verification

`flock /tmp/sl-build.lock ./scripts/gate.sh` — green end to end (fmt, clippy `-D warnings`,
`nextest --all-features` incl. the Docker agent-path E2E, `cargo audit`, `cargo deny`,
findings gate).
