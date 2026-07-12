# F-recorder-plaintext-zeroize-1: transient per-event plaintext copies in the recorder are not zeroized
- Severity: low
- Status: Accepted-Risk
- Area: crypto

## Summary (Session Nine — recorder Tier-0 plaintext hygiene, §3/§15)
The session recorder (`ssh/recorder/`) copies SSH session plaintext into a few
staging buffers on the tap hot path before it is sealed. The **load-bearing**
buffers are scrubbed on drop:

- the per-recording AES-256-GCM **data key** — `RecordingCipher` holds an
  `aes_gcm::Aes256Gcm` built with the `zeroize` feature (key schedule zeroized on
  drop); the plaintext key bytes live in a `Zeroizing<[u8;32]>` during setup;
- the ECIES **KEK** + wrapped-key scratch — `Zeroizing`;
- the asciicast **plaintext accumulator** `Capture.pending_pt` and each drained
  **frame** buffer — `Zeroizing<Vec<u8>>`;
- the **SFTP reassembly buffers** `SftpDecoder.in_buf/out_buf` (which transit
  WRITE/DATA file content before hashing) — `Zeroizing<Vec<u8>>`.

The residual is **imperfect** in the same class as
[F-innerkey-zeroize-1](F-innerkey-zeroize-1.md): a handful of short-lived
transient copies of already-in-flight plaintext are not individually scrubbed:

1. **asciicast event strings** — `Utf8Chunker::push` returns a `String` and
   `asciicast::event_line` serializes it into a `Vec<u8>` via `serde_json` (whose
   internal scratch is un-scrubbed) before the bytes are appended to the zeroized
   `pending_pt`. Same residual class as F-zeroize-1's accepted `serde_json` scratch.
2. **`Utf8Chunker.pending`** — the ≤3-byte incomplete-UTF-8 tail held between
   chunks (and, only on malformed input, a larger slice) is a plain `Vec<u8>`.
3. **SCP `line`** — legacy-scp control lines (`C<mode> <size> <name>`, metadata,
   not file content — content streams straight to the hasher without buffering).
4. **packet slices** — `SftpDecoder` copies each whole packet out of the (zeroized)
   reassembly buffer into a transient `Vec` to parse it.

The source bytes at the tap are a borrowed `&[u8]` into russh's `CryptoVec`, which
russh itself zeroizes; these are copies of bytes already in flight, dropped
immediately after the event/packet is processed.

Not remotely exploitable — process-local heap/stack bytes, reachable only via a
coredump / swap / a memory-disclosure primitive on the Tier-0 host. Even then, the
recorded object on disk/in-store is ciphertext under the customer key; only the
in-RAM transient window is at issue, and the recording data key itself IS zeroized.

## Recommended disposition: Accepted-Risk
Fully scrubbing these would require a custom serde serializer (to zeroize
`serde_json`'s intermediate allocations) and wrapping every transient parse buffer
— disproportionate for a coredump/swap-only residual, and the same call already
made for F-innerkey-zeroize-1 / F-zeroize-1. The load-bearing secrets (data key,
KEK, the plaintext accumulator, the SFTP content buffers) ARE zeroized.

**Compensating control:** S18 Tier-0 memory hardening (coredump suppression,
`mlock`/`madvise(MADV_DONTDUMP)` on plaintext arenas, guard pages) is the systemic
fix for this whole residual class across the data plane; it covers this finding.
Re-evaluate if S18 lands a zeroizing arena the recorder can stage into.
