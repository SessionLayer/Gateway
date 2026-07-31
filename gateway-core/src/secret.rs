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
