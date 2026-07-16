# Node addressing (how `ssh` reaches a node through the Gateway)

The Gateway is a single SSH front door; the *target node* is carried in the connection so a stock
`ssh` client needs no plugin. Three addressing modes are supported (Design §11):

| Mode | What the user types | How the node is carried |
|---|---|---|
| Username-encoding | `ssh login%node@gw` | the `%`-separated username (`login` + node) |
| **Wildcard DNS** (Session Sixteen, Part B) | `ssh login%node.ssh.corp@<any *.ssh.corp>` (or a wrapper/alias) | the node is in the username; the Gateway strips the DNS suffix |
| **ProxyJump + host-cert** (Session Sixteen, Part C) | `ssh -J gw login@node` | the node is the ProxyJump forward target; the Gateway presents a host-CA host cert (no TOFU) |

In every mode the Gateway ends up with a **login** and a **node name**; the node name is resolved
to a node id **server-side by the Control Plane** (`Authorize.node_name` → `findByName`, Session
Sixteen Part A) — authoritative, and an unknown name yields a *generic* no-disclosure denial (§7.1).
The Gateway never decides node existence or access.

## Username-encoding (baseline)

`ssh deploy%web-01@gw` → username `deploy%web-01` → login `deploy`, node `web-01`. The separator is
`ssh.target_separator` (`%` by default). Exactly one separator, non-empty halves.

## Wildcard DNS (Part B)

Wildcard DNS points `*.ssh.corp` at the Gateway so a fleet's node hostnames resolve to the single
front door with no per-node config. The **node is still conveyed in the SSH username** — that is the
only channel a stock `ssh` sends to the server (SSH has no host header / SNI). Part B's server-side
feature is a **wildcard-suffix strip**: it lets the username's node half be a fully-qualified DNS
name, which the Gateway normalizes to the bare node before name→id resolution. So
`ssh deploy%web-01.ssh.corp@anything.ssh.corp` reaches `web-01`.

### Client convenience (choose one)

There is **no pure `~/.ssh/config` rewrite** that turns a natural `ssh user@node.ssh.corp` into the
username encoding: OpenSSH's `User` directive does not expand `%h`/`%r` (`vdollar_percent_expand:
unknown key`), and a command-line `user@` overrides any config `User`. The username is the only thing
`ssh` sends the server, so the node must be in it. Realistic ergonomics:

- **Type the encoding** (the DNS suffix is fine — it is stripped): `ssh deploy%web-01.ssh.corp@gw`.
- **A distributed wrapper/alias** — a one-line shell function or `sl-ssh` script config-mgmt ships:
  ```sh
  sl-ssh() { local u=${1%@*} h=${1#*@}; shift; ssh "${u}%${h}@gw.example.com" "$@"; }
  # sl-ssh deploy@web-01.ssh.corp  →  ssh deploy%web-01.ssh.corp@gw  (Gateway strips .ssh.corp)
  ```
- For a **fully natural `ssh user@node.ssh.corp`** with nothing typed or wrapped, use **ProxyJump
  (mode C, below)** — there the node travels as the SSH forward target, not the username.

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
user: sl-ssh deploy@web-01.ssh.corp        (or: ssh deploy%web-01.ssh.corp@gw)
  → gateway receives username "deploy%web-01.ssh.corp"   (*.ssh.corp resolves to the Gateway)
  → % split: login=deploy, node="web-01.ssh.corp"
  → strip suffix "ssh.corp": node="web-01"
  → Authorize(node_name="web-01") → CP findByName → node id
  → session established on web-01
```
