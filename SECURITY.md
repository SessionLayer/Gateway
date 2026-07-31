# Security policy

Report a vulnerability through GitHub's private vulnerability reporting: the
**Security** tab above, then **Report a vulnerability**. That opens a thread
only you and the maintainers can read. Do not open a public issue, pull
request, or discussion for a security finding.

[SessionLayer's vulnerability disclosure policy](https://github.com/SessionLayer/Documentation/blob/main/docs/security/vulnerability-disclosure.md)
is the single authority for every repository in this organization: what to
include in a report, full scope, embargo and credit, and how to verify that
the release you installed is the build the advisory named. Read it before
reporting.

## Scope in this repository

The SessionLayer Gateway is the platform's Tier-0 data plane and the only
component that ever holds SSH session plaintext. A memory-disclosure,
cross-session, or relay-misrouting defect here exposes live keystrokes and
transferred file contents, so it is rated a category above the same class of
defect in any other SessionLayer repository.

In scope: the SSH front door and inner leg, the byte bridge, the recorder and
its seal, signed-decision-context verification, the lock feed, the HA peer
relay, the agent transport, the in-process sandbox, and `release.yml`.

Not accepted here: the legacy plaintext `cp_endpoint`
(`http://127.0.0.1:9090`), which is loopback-only and reached solely by the
handshake smoke test. The production plane is `cp_mtls_endpoint` over mutual
TLS 1.3. The policy lists the rest of the out-of-scope set, including test
fixtures, volumetric denial-of-service testing, anything starting from a
credential the threat model already assumes lost, and accepted risks already
documented in the trust model.

## Response targets

The [disclosure policy](https://github.com/SessionLayer/Documentation/blob/main/docs/security/vulnerability-disclosure.md)
carries the one timeline this organization keeps, from acknowledgement through
triage, fix and embargo, and it covers every repository including this one.
Advisories credit you unless you ask to stay anonymous, and request a CVE for
findings rated moderate or above. There is no bug bounty.
