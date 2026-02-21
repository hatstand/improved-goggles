#![cfg(windows)]

//! Adobe ADEPT DRM RSA key extraction from Windows Registry.
//!
//! This module handles extracting and decrypting Adobe ADEPT activation keys
//! from the Windows Registry. The key hierarchy is:
//! 1. Device entropy (from volume serial, CPU info, username)
//! 2. Device key (encrypted in registry, decrypted with DPAPI and entropy)
//! 3. RSA private key (encrypted in registry, decrypted with device key)

use std::arch::x86_64::__cpuid;

use anyhow::{bail, Context, Result};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use byteorder::{BigEndian, ByteOrder};
use log::debug;
use p12_keystore::KeyStoreEntry;
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
use windows::Win32::Storage::FileSystem::GetVolumeInformationW;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_registry::CURRENT_USER;

use crate::AdeptKey;
use crate::{
    rsa::{decrypt_private_license_key, StorableRsaPrivateKey},
    safe_strings,
};

const DEVICE_KEY_PATH: &str = r"Software\Adobe\Adept\Device";
const ADEPT_PATH: &str = r"Software\Adobe\Adept\Activation";

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
        // Open each subkey
        let subkey = adept_key.open(&subkey_name)?;

        // Get the default value (type)
        let ktype = subkey.get_string("")?;

        // We're only interested in 'credentials' keys
        if ktype == "credentials" {
            let private_license_key =
                private_license_key_from_registry_key(&subkey, &aes_key_bytes)?;
            let (cert, pkcs) = pkcs12_from_registry_key(&subkey, &aes_key_bytes)?;

            return Ok(AdeptKey {
                private_license_key: StorableRsaPrivateKey(private_license_key),
                name: ("placeholder").to_string(),
                device_key: aes_key_bytes.clone(),
                private_auth_key: StorableRsaPrivateKey(pkcs),
                certificate: cert,
                fingerprint: adept_fingerprint()?,
                user: adept_user()?,
                device: adept_device()?,
                authentication_certificate: authentication_certificate()?,
                license_certificate: license_certificate()?,
            });
        }
    }
    bail!("No credentials found in registry");
}

fn pkcs12_from_registry_key(
    subkey: &windows_registry::Key,
    device_key: &[u8],
) -> Result<(String, RsaPrivateKey)> {
    let sub_subkeys = subkey.keys()?.collect::<Vec<_>>();
    for sub_subkey_name in sub_subkeys {
        let sub_subkey = subkey.open(&sub_subkey_name)?;
        let ktype2 = sub_subkey.get_string("")?;

        // Collect information for each credential component
        if ktype2 == "pkcs12" {
            // Value is a pkcs12 with the base64-encoded device key as the password.
            let value = sub_subkey.get_string("value")?;
            let data = base64::prelude::BASE64_STANDARD.decode(value)?;
            let password = base64::prelude::BASE64_STANDARD.encode(device_key);
            let keystore = p12_keystore::KeyStore::from_pkcs12(&data, &password)?;
            if let Some((name, entry)) = keystore.entries().next() {
                println!("name: {} entry: {:?}", name, entry);
                let (cert, key) = key_from_key_store_entry(entry)?;
                return Ok((cert, key));
            }
        }
    }
    bail!("No pkcs12 found in registry");
}

fn key_from_key_store_entry(entry: &KeyStoreEntry) -> Result<(String, RsaPrivateKey)> {
    match entry {
        KeyStoreEntry::PrivateKeyChain(keychain) => {
            let rsa_key = RsaPrivateKey::from_pkcs8_der(keychain.key())?;
            let cert = keychain
                .chain()
                .first()
                .map(|cert| {
                    println!("Certificate in chain: {:?}", cert);
                    BASE64_STANDARD.encode(cert.as_der())
                })
                .ok_or_else(|| anyhow::anyhow!("No certificate found in chain"))?;
            Ok((cert, rsa_key))
        }
        _ => bail!("Expected a private key entry in the keystore"),
    }
}

fn private_license_key_from_registry_key(
    subkey: &windows_registry::Key,
    device_key: &[u8],
) -> Result<RsaPrivateKey> {
    let sub_subkeys = subkey.keys()?.collect::<Vec<_>>();
    for sub_subkey_name in sub_subkeys {
        let sub_subkey = subkey.open(&sub_subkey_name)?;
        let ktype = sub_subkey.get_string("")?;

        // Collect information for each credential component
        if ktype == "privateLicenseKey" {
            // Value is an AES-CBC encrypted RSA private key, base64-encoded. Decrypt it with the device key and a zero IV.
            let value = sub_subkey.get_string("value")?;
            return decrypt_private_license_key(&value, device_key);
        }
    }
    bail!("No privateLicenseKey found in registry");
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

fn authentication_certificate() -> Result<String> {
    let adept_key = CURRENT_USER
        .open(ADEPT_PATH)
        .context("Adobe Adept registry key not found")?;
    // Enumerate all subkeys under Software\Adobe\Adept\Activation
    let subkey_names: Vec<String> = adept_key
        .keys()
        .context("Failed to enumerate registry keys")?
        .collect();

    for subkey_name in subkey_names {
        debug!("Processing subkey for auth cert: {}", subkey_name);
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

                // Look for the authentication certificate key
                if ktype2 == "authenticationCertificate" {
                    let auth_cert_value = sub_subkey.get_string("value")?;
                    debug!("    authentication certificate value: {}", auth_cert_value);
                    return Ok(auth_cert_value);
                }
            }
        }
    }
    bail!("No authentication certificate found in registry");
}

fn license_certificate() -> Result<String> {
    let adept_key = CURRENT_USER
        .open(ADEPT_PATH)
        .context("Adobe Adept registry key not found")?;
    // Enumerate all subkeys under Software\Adobe\Adept\Activation
    let subkey_names: Vec<String> = adept_key
        .keys()
        .context("Failed to enumerate registry keys")?
        .collect();

    for subkey_name in subkey_names {
        debug!("Processing subkey for auth cert: {}", subkey_name);
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

                // Look for the license certificate key
                if ktype2 == "licenseCertificate" {
                    let license_cert_value = sub_subkey.get_string("value")?;
                    debug!("    license certificate value: {}", license_cert_value);
                    return Ok(license_cert_value);
                }
            }
        }
    }
    bail!("No license certificate found in registry");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpuid_vendor() {
        let is_intel = cpu_vendor() == "GenuineIntel";
        let is_amd = cpu_vendor() == "AuthenticAMD";
        assert!(is_intel || is_amd, "Surprise CPU vendor: {}", cpu_vendor());
    }

    #[test]
    fn test_cpuid_signature() {
        let sig = cpu_signature();
        assert_ne!(sig, 0, "CPU signature should not be zero");
    }

    #[test]
    fn test_entropy_generation() {
        let serial = volume_serial_number("C:\\").expect("wut");
        assert_ne!(serial, 0, "Volume serial number should not be zero");

        let entropy = device_entropy().expect("Failed to generate device entropy");
        assert_eq!(entropy.len(), 32, "Device entropy should be 32 bytes");

        assert_eq!(
            &entropy[0..4],
            &serial.to_be_bytes(),
            "First 4 bytes of entropy should match volume serial number"
        );
        let vendor_bytes = &entropy[4..16];
        let vendor_str = String::from_utf8_lossy(vendor_bytes);
        assert_eq!(
            vendor_str,
            cpu_vendor(),
            "Vendor string in entropy should match CPU vendor"
        );

        let signature = cpu_signature();
        assert_eq!(0xb4_0f_40, signature);
        assert_ne!(signature, 0, "CPU signature should not be zero");
        // let signature_bytes = &entropy[16..19];
        // assert_eq!(
        //     signature_bytes,
        //     &signature.to_be_bytes()[0..3],
        //     "Signature bytes in entropy should match CPU signature"
        // );

        assert_eq!(entropy[16], 0xb4);
        assert_eq!(entropy[17], 0x0f);
        assert_eq!(entropy[18], 0x40);

        let username = adobe_username().expect("Failed to get Adobe username");
        assert_eq!(username.len(), 5);
    }
}
