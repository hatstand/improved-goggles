use std::ops::{Deref, DerefMut};

use aes::cipher::{BlockDecryptMut, KeyIvInit};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use log::debug;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    RsaPrivateKey,
};
use serde::{Deserialize, Serialize};

use crate::Aes128CbcDec;

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

pub fn decrypt_private_key_with_iv(
    encrypted: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<RsaPrivateKey> {
    // Ensure key is 16 bytes (128-bit AES)
    let mut aes_key = [0u8; 16];
    let key_len = std::cmp::min(key.len(), 16);
    aes_key[..key_len].copy_from_slice(&key[..key_len]);

    // Create cipher
    let cipher = Aes128CbcDec::new(&aes_key.into(), iv.into());

    debug!(
        "Decrypting private key with AES-128-CBC. Encrypted data length: {} bytes",
        encrypted.len()
    );

    // Decrypt
    let mut decrypted = encrypted.to_vec();
    let decrypted_data = cipher
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut decrypted)
        .map_err(|e| anyhow!("AES decryption failed: {:?}", e))?;

    debug!(
        "Decrypted data (len={}): {}",
        decrypted_data.len(),
        hex::encode(decrypted_data)
    );

    let unpadded = unpad(decrypted_data)?;

    // Skip first 26 bytes as per the Python code
    if unpadded.len() < 26 {
        bail!("Decrypted data too short");
    }

    // Parse the DER-encoded RSA private key (this creates an owned RsaPrivateKey)
    let der_bytes = &unpadded[26..];

    debug!(
        "DER-encoded RSA private key (len={}): {}",
        der_bytes.len(),
        hex::encode(der_bytes)
    );

    RsaPrivateKey::from_pkcs1_der(der_bytes)
        .context("Failed to parse RSA private key from decrypted data")
}

/// Decrypt the private license key using AES-CBC
/// Returns the parsed RSA private key.
#[allow(dead_code)]
pub fn decrypt_private_license_key(encrypted_b64: &str, key: &[u8]) -> Result<RsaPrivateKey> {
    // Decode base64
    let encrypted = base64::prelude::BASE64_STANDARD
        .decode(encrypted_b64)
        .context("Failed to decode base64")?;
    let iv = [0u8; 16];

    decrypt_private_key_with_iv(&encrypted, key, &iv)
}

/// PKCS#7 unpadding
pub fn unpad(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        bail!("Empty data for unpadding");
    }

    let padding_len = data[data.len() - 1] as usize;

    if padding_len == 0 || padding_len > 16 || padding_len > data.len() {
        bail!("Invalid padding length: {}", padding_len);
    }

    // Verify all padding bytes are correct
    for i in 0..padding_len {
        if data[data.len() - 1 - i] != padding_len as u8 {
            bail!("Invalid padding bytes");
        }
    }

    Ok(data[..data.len() - padding_len].to_vec())
}
