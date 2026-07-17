//! asciicast v2 encoding (Design §12.1, Part A).
//!
//! A recording's terminal stream is the standard [asciicast v2] format:
//! a header line (`{"version":2,"width":…,"height":…,"timestamp":…}`) followed by
//! newline-delimited event arrays `[elapsed, code, data]`, where `code` is `o`
//! (output), `i` (input/keystrokes), `r` (resize) or `m` (marker). Concatenating
//! the `o` (resp. `i`) event payloads reproduces the exact node output (resp.
//! keystrokes) — the round-trip property the gate checks.
//!
//! SSH terminal streams are UTF-8, but a multi-byte character may be split across
//! two SSH packets. [`Utf8Chunker`] holds an incomplete trailing sequence back for
//! the next chunk so an event never straddles a code point; concatenation stays
//! byte-exact. (Genuinely malformed bytes — not merely incomplete — are lossily
//! replaced; terminal capture assumes UTF-8, binary file transfers take the SFTP/
//! SCP audit path instead.)
//!
//! [asciicast v2]: https://docs.asciinema.org/manual/asciicast/v2/
//!
//! Tier-0 zeroization (Session Twenty-One, F-recorder-plaintext-zeroize / NFR-5):
//! an event line and the chunker's carry buffer hold live session plaintext, so
//! both are returned/held in scrub-on-drop [`Zeroizing`] buffers — the transient
//! copy is overwritten the moment the recorder is done folding it into the sealed
//! frame stream, never lingering in freed heap for a coredump/swap to expose.

use zeroize::Zeroizing;

/// An asciicast v2 event code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventCode {
    /// `o` — output (node → user).
    Output,
    /// `i` — input (keystrokes / the exec command line, user → node).
    Input,
    /// `r` — terminal resize.
    Resize,
    /// `m` — marker.
    Marker,
}

impl EventCode {
    fn as_str(self) -> &'static str {
        match self {
            EventCode::Output => "o",
            EventCode::Input => "i",
            EventCode::Resize => "r",
            EventCode::Marker => "m",
        }
    }
}

/// The asciicast v2 header line (terminated with `\n`).
pub fn header_line(width: u16, height: u16, timestamp: u64) -> Vec<u8> {
    let mut line = serde_json::to_string(&serde_json::json!({
        "version": 2,
        "width": width,
        "height": height,
        "timestamp": timestamp,
    }))
    .expect("header serializes");
    line.push('\n');
    line.into_bytes()
}

/// An asciicast v2 event line `[elapsed, "code", "data"]` (terminated with `\n`).
/// `data` is UTF-8 text (JSON-escaped); `elapsed` is seconds since the header.
///
/// The returned line contains live plaintext (keystrokes/output), so it is a
/// [`Zeroizing`] buffer: the recorder folds it into the hash-chain + sealed frame
/// stream and drops it, scrubbing the transient copy (F-recorder-plaintext-zeroize).
pub fn event_line(elapsed_secs: f64, code: EventCode, data: &str) -> Zeroizing<Vec<u8>> {
    // serde_json renders the tuple as a JSON array with correct string escaping.
    let mut line =
        serde_json::to_string(&(elapsed_secs, code.as_str(), data)).expect("event serializes");
    line.push('\n');
    // `into_bytes` reuses the String's buffer (no copy); wrapping it scrubs that
    // buffer on drop. (serde_json's own growth scratch is a coredump/swap-only
    // residual, covered by the process coredump-disable + mlock hygiene, NFR-5.)
    Zeroizing::new(line.into_bytes())
}

/// Splits a byte stream into UTF-8-clean event payloads, buffering an incomplete
/// trailing multi-byte sequence across chunks so no event straddles a code point.
/// The carry buffer holds live plaintext, so it is scrub-on-drop.
#[derive(Debug, Default)]
pub struct Utf8Chunker {
    pending: Zeroizing<Vec<u8>>,
}

impl Utf8Chunker {
    /// Feed the next raw chunk; returns the emittable UTF-8 text (possibly empty
    /// when the whole chunk was an incomplete trailing sequence). Scrub-on-drop.
    pub fn push(&mut self, chunk: &[u8]) -> Zeroizing<String> {
        self.pending.extend_from_slice(chunk);
        match std::str::from_utf8(&self.pending) {
            Ok(_) => {
                // Whole buffer is valid UTF-8: emit it all (moving the plaintext out
                // of `pending`, which is left empty — no residual carry).
                let out = std::mem::take(&mut *self.pending);
                Zeroizing::new(String::from_utf8(out).expect("validated above"))
            }
            Err(e) => {
                let valid = e.valid_up_to();
                match e.error_len() {
                    // Incomplete trailing sequence: emit the valid prefix, hold the
                    // rest (≤3 bytes) for the next chunk (byte-exact concatenation).
                    None => {
                        let out = self.pending[..valid].to_vec();
                        self.pending.drain(..valid);
                        Zeroizing::new(String::from_utf8(out).expect("valid prefix"))
                    }
                    // Genuinely malformed: lossily replace (UTF-8 terminal assumption).
                    Some(_) => {
                        let out = String::from_utf8_lossy(&self.pending).into_owned();
                        self.pending.clear();
                        Zeroizing::new(out)
                    }
                }
            }
        }
    }

    /// Flush any buffered bytes at end-of-stream (lossy if still incomplete).
    /// Returns `None` when nothing is pending. Scrub-on-drop.
    pub fn flush(&mut self) -> Option<Zeroizing<String>> {
        if self.pending.is_empty() {
            return None;
        }
        let out = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending.clear();
        Some(Zeroizing::new(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_line_escapes_and_frames() {
        let line = event_line(1.5, EventCode::Output, "a\"b\n");
        let s = String::from_utf8(line.to_vec()).unwrap();
        assert_eq!(s, "[1.5,\"o\",\"a\\\"b\\n\"]\n");
    }

    #[test]
    fn chunker_preserves_split_multibyte_char() {
        // "é" is 0xC3 0xA9; split across two chunks must reassemble byte-exact.
        let mut c = Utf8Chunker::default();
        let a = c.push(&[b'x', 0xC3]);
        let b = c.push(&[0xA9, b'y']);
        assert_eq!(a.as_str(), "x");
        assert_eq!(b.as_str(), "\u{e9}y");
        assert!(c.flush().is_none());
        assert_eq!(format!("{}{}", a.as_str(), b.as_str()), "x\u{e9}y");
    }

    #[test]
    fn chunker_flushes_trailing_incomplete_lossily() {
        let mut c = Utf8Chunker::default();
        assert_eq!(c.push(&[0xC3]).as_str(), "");
        assert!(c.flush().is_some(), "an incomplete tail flushes (lossy)");
    }
}
