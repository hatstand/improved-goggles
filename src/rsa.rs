use std::ops::{Deref, DerefMut};

use base64::Engine;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    RsaPrivateKey,
};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct StorableRsaPrivateKey(pub RsaPrivateKey);

impl Serialize for StorableRsaPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let der = self
            .0
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(serde::ser::Error::custom)?;
        let b64 = base64::prelude::BASE64_STANDARD.encode(der.as_bytes());
        serializer.serialize_str(&b64)
    }
}

impl<'de> Deserialize<'de> for StorableRsaPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let b64 = String::deserialize(deserializer)?;
        let der = base64::prelude::BASE64_STANDARD
            .decode(b64)
            .map_err(serde::de::Error::custom)?;
        let key = RsaPrivateKey::from_pkcs1_pem(&String::from_utf8_lossy(&der))
            .map_err(serde::de::Error::custom)?;
        Ok(StorableRsaPrivateKey(key))
    }
}

impl From<RsaPrivateKey> for StorableRsaPrivateKey {
    fn from(key: RsaPrivateKey) -> Self {
        StorableRsaPrivateKey(key)
    }
}

impl From<StorableRsaPrivateKey> for RsaPrivateKey {
    fn from(val: StorableRsaPrivateKey) -> Self {
        val.0
    }
}

impl Deref for StorableRsaPrivateKey {
    type Target = RsaPrivateKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for StorableRsaPrivateKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
