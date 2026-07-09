# F-version-1: resolve_common_version treated the version space as contiguous across MAJOR
- Severity: info
- Status: Verified-Fixed
- Area: version

**Issue.** `resolve_common_version` compares `(major,minor)` lexicographically,
so a (malformed) advertised range straddling a major — e.g. `[(1,5),(2,3)]` —
would resolve to a `2.x`, treating a MAJOR change as an additive step, which
contradicts the contract ("a change of MAJOR is a hard break"). Not reachable
in S1: our advertised range is `min==max==(1,0)` and the live path
(`interpret()`) never calls this function.

**Fix.** Documented the precondition (each peer's range lies within a single
major) and added `debug_assert_eq!` on `min.major == max.major` for both peers,
so a contract-invalid range trips in debug/test builds.

**Verification.** Full test suite (incl. the resolver and mock-CP tests) green
with the assertions active.
