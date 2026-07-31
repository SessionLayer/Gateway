//! Small secret-handling helpers. `Zeroizing` has no serde impls of its own, so this
//! adapter lets a scrub-on-drop secret field round-trip through serde.

/// serde adapter for a `Zeroizing<String>` field: (de)serialises as a plain JSON string
/// while the in-memory value stays in a scrub-on-drop buffer (the only owned heap copy).
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
