#![cfg(windows)]

//! Adobe ADEPT DRM RSA key extraction from Windows Registry.
//!
//! This module handles extracting and decrypting Adobe ADEPT activation keys
//! from the Windows Registry. The key hierarchy is:
//! 1. Device entropy (from volume serial, CPU info, username)
//! 2. Device key (encrypted in registry, decrypted with DPAPI and entropy)
//! 3. RSA private key (encrypted in registry, decrypted with device key)

use std::arch::x86_64::__cpuid;

use aes::Aes128;
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use byteorder::{BigEndian, ByteOrder};
use cbc::{
    cipher::{BlockDecryptMut, KeyIvInit},
    Decryptor,
};
use log::debug;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, RsaPrivateKey};
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
use windows::Win32::Storage::FileSystem::GetVolumeInformationW;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_registry::CURRENT_USER;

use crate::safe_strings;

type Aes128CbcDec = Decryptor<Aes128>;

const DEVICE_KEY_PATH: &str = r"Software\Adobe\Adept\Device";
const ADEPT_PATH: &str = r"Software\Adobe\Adept\Activation";

#[derive(Debug)]
pub struct AdeptKey {
    pub device_key: Vec<u8>,
    pub key: RsaPrivateKey,
    pub name: String,
}

/// PKCS#7 unpadding
fn unpad(data: &[u8]) -> Result<Vec<u8>> {
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

fn system_directory() -> Result<String> {
    unsafe {
        let out = &mut [0u16; 260];
        let len = GetSystemDirectoryW(Some(out));
        match len {
            0 => bail!(
                "GetSystemDirectoryW failed with error code: {}",
                windows::core::Error::from_thread()
            ),
            l if l as usize >= out.len() => bail!("Buffer too small for system directory"),
            l => Ok(String::from_utf16_lossy(&out[..l as usize])),
        }
    }
}

pub(crate) fn volume_serial_number(path: &str) -> Result<u32> {
    unsafe {
        safe_strings::with_wide_str(path, |path_wide| {
            let mut serial_number = 0u32;
            GetVolumeInformationW(path_wide, None, Some(&mut serial_number), None, None, None)?;
            Ok(serial_number)
        })
    }
}

pub(crate) fn cpu_vendor() -> String {
    let cpuid_result = unsafe { __cpuid(0) };
    let mut vendor_bytes = Vec::new();
    vendor_bytes.extend_from_slice(&cpuid_result.ebx.to_le_bytes());
    vendor_bytes.extend_from_slice(&cpuid_result.edx.to_le_bytes());
    vendor_bytes.extend_from_slice(&cpuid_result.ecx.to_le_bytes());
    String::from_utf8_lossy(&vendor_bytes).to_string()
}

pub(crate) fn cpu_signature() -> u32 {
    let cpuid_result = unsafe { __cpuid(1) };
    cpuid_result.eax
}

pub(crate) fn adobe_username() -> Result<Vec<u8>> {
    let user = CURRENT_USER.open(DEVICE_KEY_PATH)?.get_string("username")?;
    let user_bytes = user.as_bytes();
    Ok(user_bytes.to_vec())
}

pub(crate) fn device_entropy() -> Result<[u8; 32]> {
    let sysdir_entropy = system_directory()?.split("\\").next().unwrap().to_string() + "\\";
    let serial_entropy = volume_serial_number(&sysdir_entropy)?;
    let vendor = cpu_vendor();
    let signature = cpu_signature();
    let username = adobe_username()?;

    let mut buf = [0u8; 32];
    // Write serial (4 bytes).
    BigEndian::write_u32(&mut buf, serial_entropy);
    // Write vendor (12 bytes).
    buf[4..16].copy_from_slice(vendor.as_bytes());
    // Write signature 3 bytes (skipping the first byte).
    let sig_bytes = signature.to_be_bytes();
    buf[16] = sig_bytes[1];
    buf[17] = sig_bytes[2];
    buf[18] = sig_bytes[3];
    // Write 13 bytes of username.
    let max = std::cmp::min(13, username.len());
    buf[19..19 + max].copy_from_slice(&username[..max]);
    Ok(buf)
}

fn device_key() -> Result<Vec<u8>> {
    debug!("CPU signature: {:x}", cpu_signature());
    let keykey_key: windows_registry::Value =
        CURRENT_USER.open(DEVICE_KEY_PATH)?.get_value("key")?;
    let entropy = device_entropy()?;
    unsafe {
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        debug!("Decrypting key with entropy: {}", hex::encode(entropy));
        debug!(
            "Encrypted key (len={}): {}",
            keykey_key.len(),
            hex::encode(&keykey_key)
        );
        CryptUnprotectData(
            &CRYPT_INTEGER_BLOB {
                cbData: keykey_key.len() as u32,
                pbData: keykey_key.as_ptr() as *mut u8,
            } as *const CRYPT_INTEGER_BLOB,
            None,
            Some(&CRYPT_INTEGER_BLOB {
                cbData: entropy.len() as u32,
                pbData: entropy.as_ptr() as *mut u8,
            }),
            None,
            None,
            0,
            &mut out as *mut _,
        )?;

        assert_ne!(out.cbData, 0, "Decrypted data should not be empty");
        let decrypted = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        debug!(
            "Decrypted key (len={}): {}",
            decrypted.len(),
            hex::encode(&decrypted)
        );
        Ok(decrypted)
    }
}

/// Main function to retrieve Adobe Adept keys from Windows registry
pub fn adeptkeys() -> Result<AdeptKey> {
    // Open main Adobe Adept registry key
    let adept_key = CURRENT_USER
        .open(ADEPT_PATH)
        .context("Adobe Adept registry key not found")?;

    // Enumerate all subkeys under Software\Adobe\Adept
    let subkey_names: Vec<String> = adept_key
        .keys()
        .context("Failed to enumerate registry keys")?
        .collect();

    let aes_key_bytes = device_key()?;
    println!(
        "Decrypted AES key (for debugging): {}",
        hex::encode(&aes_key_bytes)
    );

    for subkey_name in subkey_names {
        debug!("Processing subkey: {}", subkey_name);
        // Open each subkey
        let subkey = adept_key.open(&subkey_name)?;

        // Get the default value (type)
        let ktype = subkey.get_string("")?;

        debug!("Subkey: {}  Type: {}", subkey_name, ktype);

        // We're only interested in 'credentials' keys
        if ktype == "credentials" {
            // Enumerate sub-subkeys
            let sub_subkeys = subkey.keys()?.collect::<Vec<_>>();

            for sub_subkey_name in sub_subkeys {
                let sub_subkey = subkey.open(&sub_subkey_name)?;
                let ktype2 = sub_subkey.get_string("")?;

                debug!("  Sub-subkey: {}  Type: {}", sub_subkey_name, ktype2);

                // Collect information for each credential component
                if ktype2 == "privateLicenseKey" {
                    let value = sub_subkey.get_string("value")?;

                    debug!("    privateLicenseKey value: {}", value);

                    let decoded = decrypt_private_key_from_b64(&value, &aes_key_bytes)?;
                    return Ok(AdeptKey {
                        key: decoded,
                        name: ("placeholder").to_string(),
                        device_key: aes_key_bytes.clone(),
                    });
                } else if ktype2 == "pkcs12" {
                    let value = sub_subkey.get_string("value")?;
                    debug!("    pkcs12 value: {}", value);
                    // let key = RsaPrivateKey::from_pkcs8_der(
                    //     &base64::prelude::BASE64_STANDARD.decode(value)?,
                    // )
                    // .context("Failed to parse RSA private key from pkcs12 value")?;
                    // println!("pkcs12: {:?}", key);
                }
            }
        }
    }
    bail!("No credentials found in registry");
}

/// Extract the Adept user GUID from Windows registry
///
/// Retrieves the user GUID from the activation credentials stored at:
/// `HKEY_CURRENT_USER\Software\Adobe\Adept\Activation\<activation-id>\credentials\user`
///
/// # Returns
/// The user GUID string
///
/// # Errors
/// Returns an error if the registry key is not found or cannot be accessed
pub fn adept_user() -> Result<String> {
    // Open main Adobe Adept registry key
    let adept_key = CURRENT_USER
        .open(ADEPT_PATH)
        .context("Adobe Adept registry key not found")?;

    // Enumerate all subkeys under Software\Adobe\Adept\Activation
    let subkey_names: Vec<String> = adept_key
        .keys()
        .context("Failed to enumerate registry keys")?
        .collect();

    for subkey_name in subkey_names {
        debug!("Processing subkey for user: {}", subkey_name);
        // Open each subkey
        let subkey = adept_key.open(&subkey_name)?;

        // Get the default value (type)
        let ktype = subkey.get_string("")?;

        debug!("Subkey: {}  Type: {}", subkey_name, ktype);

        // We're only interested in 'credentials' keys
        if ktype == "credentials" {
            // Enumerate sub-subkeys
            let sub_subkeys = subkey.keys()?.collect::<Vec<_>>();

            for sub_subkey_name in sub_subkeys {
                let sub_subkey = subkey.open(&sub_subkey_name)?;
                let ktype2 = sub_subkey.get_string("")?;

                debug!("  Sub-subkey: {}  Type: {}", sub_subkey_name, ktype2);

                // Look for the user key
                if ktype2 == "user" {
                    let user_value = sub_subkey.get_string("value")?;
                    debug!("    user value: {}", user_value);
                    return Ok(user_value);
                }
            }
        }
    }
    bail!("No user found in registry");
}

/// Extract the Adept device identifier from Windows registry
///
/// Retrieves the device identifier from the activation credentials stored at:
/// `HKEY_CURRENT_USER\Software\Adobe\Adept\Activation\<activation-id>\activationToken\device`
///
/// # Returns
/// The device identifier string
///
/// # Errors
/// Returns an error if the registry key is not found or cannot be accessed
pub fn adept_device() -> Result<String> {
    // Open main Adobe Adept registry key
    let adept_key = CURRENT_USER
        .open(ADEPT_PATH)
        .context("Adobe Adept registry key not found")?;

    // Enumerate all subkeys under Software\Adobe\Adept\Activation
    let subkey_names: Vec<String> = adept_key
        .keys()
        .context("Failed to enumerate registry keys")?
        .collect();

    for subkey_name in subkey_names {
        debug!("Processing subkey for device: {}", subkey_name);
        // Open each subkey
        let subkey = adept_key.open(&subkey_name)?;

        // Get the default value (type)
        let ktype = subkey.get_string("")?;

        debug!("Subkey: {}  Type: {}", subkey_name, ktype);

        // We're only interested in 'activationToken' keys
        if ktype == "activationToken" {
            // Enumerate sub-subkeys
            let sub_subkeys = subkey.keys()?.collect::<Vec<_>>();

            for sub_subkey_name in sub_subkeys {
                let sub_subkey = subkey.open(&sub_subkey_name)?;
                let ktype2 = sub_subkey.get_string("")?;

                debug!("  Sub-subkey: {}  Type: {}", sub_subkey_name, ktype2);

                // Look for the device key
                if ktype2 == "device" {
                    let device_value = sub_subkey.get_string("value")?;
                    debug!("    device value: {}", device_value);
                    return Ok(device_value);
                }
            }
        }
    }
    bail!("No device found in registry");
}

/// Extract the Adept fingerprint from Windows registry
///
/// Retrieves the fingerprint from the activation token stored at:
/// `HKEY_CURRENT_USER\Software\Adobe\Adept\Activation\<activation-id>\activationToken\fingerprint`
///
/// # Returns
/// The fingerprint string
///
/// # Errors
/// Returns an error if the registry key is not found or cannot be accessed
pub fn adept_fingerprint() -> Result<String> {
    // Open main Adobe Adept registry key
    let adept_key = CURRENT_USER
        .open(ADEPT_PATH)
        .context("Adobe Adept registry key not found")?;

    // Enumerate all subkeys under Software\Adobe\Adept\Activation
    let subkey_names: Vec<String> = adept_key
        .keys()
        .context("Failed to enumerate registry keys")?
        .collect();

    for subkey_name in subkey_names {
        debug!("Processing subkey for fingerprint: {}", subkey_name);
        // Open each subkey
        let subkey = adept_key.open(&subkey_name)?;

        // Get the default value (type)
        let ktype = subkey.get_string("")?;

        debug!("Subkey: {}  Type: {}", subkey_name, ktype);

        // We're only interested in 'activationToken' keys
        if ktype == "activationToken" {
            // Enumerate sub-subkeys
            let sub_subkeys = subkey.keys()?.collect::<Vec<_>>();

            for sub_subkey_name in sub_subkeys {
                let sub_subkey = subkey.open(&sub_subkey_name)?;
                let ktype2 = sub_subkey.get_string("")?;

                debug!("  Sub-subkey: {}  Type: {}", sub_subkey_name, ktype2);

                // Look for the fingerprint key
                if ktype2 == "fingerprint" {
                    let fingerprint_value = sub_subkey.get_string("value")?;
                    debug!("    fingerprint value: {}", fingerprint_value);
                    return Ok(fingerprint_value);
                }
            }
        }
    }
    bail!("No fingerprint found in registry");
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

pub fn decrypt_private_key(encrypted: &[u8], key: &[u8]) -> Result<RsaPrivateKey> {
    // Use 16 bytes zero IV as per the Python code
    let iv = [0u8; 16];
    decrypt_private_key_with_iv(encrypted, key, &iv)
}

/// Decrypt the private license key using AES-CBC
/// Returns the parsed RSA private key.
pub fn decrypt_private_key_from_b64(encrypted_b64: &str, key: &[u8]) -> Result<RsaPrivateKey> {
    // Decode base64
    let encrypted = base64::prelude::BASE64_STANDARD
        .decode(encrypted_b64)
        .context("Failed to decode base64")?;

    decrypt_private_key(&encrypted, key)
}
