//! Small secret-handling helpers shared across the crate.
//!
//! The Gateway holds several secrets that must round-trip through serde (the
//! persisted mTLS private key; the operator-provided enrollment token). Storing
//! them as [`zeroize::Zeroizing`] `String` guarantees each is scrubbed from the
//! heap on drop, but `Zeroizing` has no serde impls of its own — this adapter
//! bridges that gap so a field can be `#[serde(with =
//! "crate::secret::serde_zeroizing_string")]`.

/// serde adapter for a `Zeroizing<String>` field: (de)serialises as a plain JSON
/// string while keeping the in-memory value in a scrub-on-drop buffer. On
/// deserialisation the parsed value is wrapped in `Zeroizing` immediately, so
/// the only owned heap copy of the secret is the zeroizing one.
pub(crate) mod serde_zeroizing_string {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub(crate) fn serialize<S: Serializer>(
        value: &Zeroizing<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.as_str())
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<String>, D::Error> {
        Ok(Zeroizing::new(String::deserialize(deserializer)?))
    }
}
