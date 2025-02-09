// SPDX-License-Identifier: Apache-2.0

use super::super::super::{deserialize_base64, serialize_base64, String, Vec};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use p384::PublicKey;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct IdKeyEcdh {
    #[serde(
        serialize_with = "serialize_ec_public_key_sec1_base64",
        deserialize_with = "deserialize_ec_public_key_sec1_base64"
    )]
    pub public_key: PublicKey,
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub iv: Vec<u8>,
}

fn serialize_ec_public_key_sec1_base64<S>(
    sub: &PublicKey,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(sub.to_sec1_bytes());
    serializer.serialize_str(&encoded)
}

fn deserialize_ec_public_key_sec1_base64<'de, D>(
    deserializer: D,
) -> core::result::Result<PublicKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let sec1 = BASE64_URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(serde::de::Error::custom)?;
    let public_key = PublicKey::from_sec1_bytes(&sec1).map_err(serde::de::Error::custom)?;

    Ok(public_key)
}
