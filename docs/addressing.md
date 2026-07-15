# Node addressing (how `ssh` reaches a node through the Gateway)

The Gateway is a single SSH front door; the *target node* is carried in the connection so a stock
`ssh` client needs no plugin. Three addressing modes are supported (Design §11):

| Mode | What the user types | How the node is carried |
|---|---|---|
| Username-encoding | `ssh login%node@gw` | the `%`-separated username (`login` + node) |
| **Wildcard DNS** (Session Sixteen, Part B) | `ssh login@node.ssh.corp` | an ssh_config convenience rewrites it to the username-encoding form |
| ProxyJump + host-cert | `ssh -J gw node` (Session Sixteen, Part C) | — |

In every mode the Gateway ends up with a **login** and a **node name**; the node name is resolved
to a node id **server-side by the Control Plane** (`Authorize.node_name` → `findByName`, Session
Sixteen Part A) — authoritative, and an unknown name yields a *generic* no-disclosure denial (§7.1).
The Gateway never decides node existence or access.

## Username-encoding (baseline)

`ssh deploy%web-01@gw` → username `deploy%web-01` → login `deploy`, node `web-01`. The separator is
`ssh.target_separator` (`%` by default). Exactly one separator, non-empty halves.

## Wildcard DNS (Part B)

Lets a user type a natural `ssh user@node.<your-domain>` while a small **client-side ssh_config**
convenience folds it into the username-encoding form the Gateway already understands — no Gateway
DNS server, no client plugin.

### Client `~/.ssh/config`

```
Host *.ssh.corp
    HostName gw.example.com          # the Gateway's real address
    User %r%%%h                      # encode: <original-user> % <original-host>
    # (optional) pin the Gateway host key / set Port as needed
```

`ssh deploy@web-01.ssh.corp` then dials the **Gateway** with the username `deploy%web-01.ssh.corp`:
`%r` expands to the login the user asked for (`deploy`), `%%` is a literal `%` (the target
separator), and `%h` is the original host (`web-01.ssh.corp`).

### Gateway side

The Gateway does its normal `%` split → login `deploy`, node `web-01.ssh.corp` — then **strips a
configured wildcard-DNS suffix** to recover the bare node name:

```json
{ "ssh": { "node_dns_suffixes": ["ssh.corp"] } }
```

`web-01.ssh.corp` → `web-01`, which then goes to the CP name→id resolution (Part A). Rules:

- Multiple domains may be listed; a leading dot is optional (`"ssh.corp"` == `".ssh.corp"`).
- Matching is **case-insensitive** (DNS); the bare name keeps its original case.
- The **most-specific (longest)** matching suffix wins; at most one suffix is stripped.
- A target that matches **no** configured suffix is passed through unchanged — so the plain
  `login%node` encoding is unaffected, and an operator can run both modes at once.
- **Empty (default) disables wildcard DNS.**

The strip is a pure normalization — it makes no access decision. A stripped name that no node
matches is denied generically at the CP (no existence disclosure).

### End to end

```
user: ssh deploy@web-01.ssh.corp
  → ssh_config (Host *.ssh.corp): HostName gw, User %r%%%h
  → gateway receives username "deploy%web-01.ssh.corp"
  → % split: login=deploy, node="web-01.ssh.corp"
  → strip suffix "ssh.corp": node="web-01"
  → Authorize(node_name="web-01") → CP findByName → node id
  → session established on web-01
```
