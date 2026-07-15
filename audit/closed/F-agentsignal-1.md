# F-agentsignal-1: a burst of concurrent sessions to a healthy agent node reports "node offline" — the shed policy is invisible and indistinguishable from a dead agent
- Severity: medium
- Status: Verified-Fixed
- Area: agentsignal

## Summary

The control channel's outbound signal queue is bounded at 16. When it is full,
`try_send` fails and the failure is collapsed into the same error as "the agent is
gone" — so the 17th concurrent session start against a **healthy, registered,
responsive** agent node is told the node is offline (§7.1 / FR-SESS-5), with no distinct
log line and no metric to explain it.

Fail-closed, so not a security bug. But it is a capacity cliff with a misleading outcome
and zero diagnosability, which at 3am is a page that sends the operator to look at an
agent that is fine.

## Location

- `gateway-core/src/agent/server.rs:547` — `let (tx, mut rx) = mpsc::channel::<ControlOut>(16);`
- `gateway-core/src/agent/registry.rs:39-43` — both `TrySendError::Full` **and**
  `TrySendError::Closed` collapse into one error:

```rust
pub fn send_dial_back(&self, req: DialBackRequest) -> Result<(), RegistryError> {
    self.tx
        .try_send(ControlOut::DialBack(Box::new(req)))
        .map_err(|_| RegistryError::ChannelGone)     // <- Full and Closed are not the same thing
}
```

- `gateway-core/src/agent/dial.rs:121-124` — `ChannelGone` becomes
  `NodeConnectError::NoAgent` ("no agent is connected for this node"), which
  `handler.rs::establish_inner` renders as `outcome = "node_unreachable"`.

## Failure scenario

State: node `node-a` has a live, healthy control channel; its Agent is answering
heartbeats.

Input: 20 `ssh deploy%node-a@gw` connections arrive together (a CI fan-out, an Ansible
play, a `pssh`).

Each session task independently calls `AgentDial::connect` -> `send_dial_back` ->
`try_send`. The control task is a *separate* task: if it has not been scheduled between
the 16th and 17th `try_send`, the queue is full. Sessions 17-20 receive
`NodeConnectError::NoAgent` and their users see "target node is offline / unreachable".

The operator log shows one generic `"node connect failed"` warn with
`error = "no agent is connected for this node"`. The RUNBOOK
(`RUNBOOK.md:78-81`) then instructs them to check whether the Agent is registered — and
it is. There is nothing anywhere that says "we shed the signal".

## Fix

Make the shed policy explicit, visible, and distinguishable:

1. `RegistryError` gains a `Backlogged` variant; `send_dial_back` matches
   `TrySendError::Full` -> `Backlogged` (with a `warn!` naming the node) and
   `TrySendError::Closed` -> `ChannelGone`.
2. `NodeConnectError` gains `AgentBacklogged` so the operator log distinguishes it. The
   **user** still sees the same generic §7.1 outcome — non-disclosure holds.
3. Raise the queue bound to a defensible value (e.g. 128) and **document the policy**
   ("bounded queue, policy = shed to node-offline") in
   `contracts/wire/agent-gateway-v1.md` §7 and in `RUNBOOK.md`. A bounded queue whose
   overflow behaviour is undocumented is the finding; the bound itself is fine.

## Resolution — Verified-Fixed

`registry.rs`: `send_dial_back` is now an **async bounded `send`** (bounded by the dial-back
timeout via a shared deadline in `AgentDial::connect`), not `try_send` — a momentary burst
queues and drains instead of shedding the 17th session onto "node offline". `TrySendError::Full`
and `Closed` are now distinct: a saturated-but-alive channel sheds as the new
`RegistryError::Busy` -> `NodeConnectError::AgentBusy` with a distinct `reason=agent_signal_saturated`
log, never conflated with `ChannelGone` (the agent actually disconnected).

**Proving tests:** `registry::tests::a_burst_queues_up_to_the_channel_capacity`,
`a_saturated_channel_sheds_as_busy_not_channel_gone`,
`send_after_the_agent_is_gone_is_channel_gone_not_busy`.
