# F-supplychain-ci-injection-1: GitHub Actions script injection via ${{ github.ref_name }}
- Severity: medium
- Status: Verified-Fixed
- Area: supplychain

## Summary
release.yml interpolated `${{ github.ref_name }}` directly into a `run:` shell in
a job holding id-token/attestations/contents:write (the keyless signing identity);
a crafted tag could run arbitrary commands as the release signer.

## Fix
Pass the ref via a step `env: TAG:` and reference `"$TAG"`. (T3 security MED-1 / redteam.)
