# F-recorder-frame-count-1: per-frame AEAD binds the frame index but not the total frame count (trailing-frame truncation decrypts cleanly)
- Severity: low
- Status: Accepted-Risk
- Area: recorder

## Context (S23 red-team panel A4)

`ssh/recorder/seal.rs::decrypt_frames` loops to `at_end`; each frame is an
independent AES-256-GCM ciphertext keyed by its frame index (counter nonce +
frame-index AAD). Removing or reordering a **middle** frame breaks decryption (good,
proven by `frame_tamper_breaks_decryption`), but **truncating trailing frames**
yields a valid, shorter recording at the cipher layer — the AEAD does not commit to
the total frame count / a terminator.

## Why Accepted-Risk (justified — redundant defense, disproportionate change)

Truncation-evidence is already provided by two independent, load-bearing layers, so
the cipher-layer count-binding would be redundant:
1. **WORM compliance object-lock** makes a finalized object truly un-deletable /
   un-truncatable for the retention window; governance-mode deletion is whole-object
   (all-or-nothing), never a partial truncation.
2. The **write-once `hash_chain_head`** (S9, `chain.rs`) commits to the full record
   sequence AND its order; the S23 fix `F-recording-worm-version-1` now **version-pins**
   replay/export to the exact finalized object, so the served bytes are the finalized
   ones whose chain head is committed. A truncated object would not match.

The only residual is a party who can defeat WORM compliance **and** the write-once
version pin (a DB superuser) — the SAME residual class as the deferred external
Merkle anchor (FR-AUD-10). Implementing a cipher-layer terminator/frame-count would
change the **SLREC1 wire format** and require a matching change to the client-side
WebCrypto decryptor in the Dashboard (S19) and the CP decrypt-proof, for marginal
gain over the existing layered controls. Deferred as the same residual class as the
Merkle anchor; the SLREC1 format seam accommodates it additively if a customer regime
requires cryptographic truncation-evidence beyond WORM + hash-chain + version-pin.
