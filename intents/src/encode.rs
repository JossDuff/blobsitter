//! One hex wire convention for every byte field in a package: 0x-prefixed, exact
//! length enforced on read. A package is untrusted input; a length that doesn't
//! match its field is malformed, never coerced.

use serde::{Deserialize, Deserializer, Serializer};

fn to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn from_hex<E: serde::de::Error>(s: &str) -> Result<Vec<u8>, E> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(serde::de::Error::custom)
}

fn from_hex_exact<const N: usize, E: serde::de::Error>(s: &str) -> Result<[u8; N], E> {
    let bytes = from_hex::<E>(s)?;
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::custom(format!("expected {N} bytes")))
}

macro_rules! fixed {
    ($name:ident, $n:literal) => {
        pub mod $name {
            use super::*;

            pub fn serialize<S: Serializer>(v: &[u8; $n], s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&to_hex(v))
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; $n], D::Error> {
                from_hex_exact::<$n, D::Error>(&String::deserialize(d)?)
            }
        }
    };
}

fixed!(hex20, 20);
fixed!(hex_hash, 32);
fixed!(hex48, 48);

pub mod hex_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&to_hex(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        from_hex(&String::deserialize(d)?)
    }
}

pub mod hex_bytes_vec {
    use super::*;
    use serde::ser::SerializeSeq;

    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for item in v {
            seq.serialize_element(&to_hex(item))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(d)?.iter().map(|s| from_hex(s)).collect()
    }
}

pub mod hex_hashes {
    use super::*;
    use blobsitter_reference::Hash;
    use serde::ser::SerializeSeq;

    pub fn serialize<S: Serializer>(v: &[Hash], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for item in v {
            seq.serialize_element(&to_hex(item))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Hash>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| from_hex_exact::<32, D::Error>(s))
            .collect()
    }
}
