#![cfg(windows)]

use std::arch::x86_64::__cpuid;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use aes::Aes128;
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use byteorder::{BigEndian, ByteOrder};
use cbc::{
    cipher::{BlockDecryptMut, KeyIvInit},
    Decryptor,
};
use flate2::read::DeflateDecoder;
use rsa::{pkcs1::DecodeRsaPrivateKey, Pkcs1v15Encrypt, RsaPrivateKey};
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
use windows::Win32::Storage::FileSystem::GetVolumeInformationW;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_registry::CURRENT_USER;
use zip::ZipArchive;

mod safe_strings;

type Aes128CbcDec = Decryptor<Aes128>;

const KEYKEY_PATH: &str = r"Software\Adobe\Adept\Device";
const ADEPT_PATH: &str = r"Software\Adobe\Adept\Activation";

#[derive(Debug)]
pub struct AdeptKey {
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

fn volume_serial_number(path: &str) -> Result<u32> {
    unsafe {
        safe_strings::with_wide_str(path, |path_wide| {
            let mut serial_number = 0u32;
            GetVolumeInformationW(path_wide, None, Some(&mut serial_number), None, None, None)?;
            Ok(serial_number)
        })
    }
}

fn cpu_vendor() -> String {
    let cpuid_result = unsafe { __cpuid(0) };
    let mut vendor_bytes = Vec::new();
    vendor_bytes.extend_from_slice(&cpuid_result.ebx.to_le_bytes());
    vendor_bytes.extend_from_slice(&cpuid_result.edx.to_le_bytes());
    vendor_bytes.extend_from_slice(&cpuid_result.ecx.to_le_bytes());
    String::from_utf8_lossy(&vendor_bytes).to_string()
}

fn cpu_signature() -> u32 {
    let cpuid_result = unsafe { __cpuid(1) };
    cpuid_result.eax
}

fn adobe_username() -> Result<Vec<u8>> {
    let user = CURRENT_USER.open(KEYKEY_PATH)?.get_string("username")?;
    let user_bytes = user.as_bytes();
    Ok(user_bytes.to_vec())
}

fn device_entropy() -> Result<[u8; 32]> {
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

/// Extracts the encrypted key from an EPUB file.
/// The key is located in META-INF/rights.xml inside the `encryptedKey` XML tag.
pub fn extract_content_key<P: AsRef<Path>>(epub_path: P) -> Result<String> {
    // Open the EPUB file (which is a ZIP archive)
    let file = File::open(epub_path.as_ref())
        .with_context(|| format!("Failed to open EPUB file: {:?}", epub_path.as_ref()))?;
    let reader = BufReader::new(file);
    let mut archive = ZipArchive::new(reader).context("Failed to read EPUB as ZIP archive")?;

    // Extract META-INF/rights.xml
    let mut rights_file = archive
        .by_name("META-INF/rights.xml")
        .context("META-INF/rights.xml not found in EPUB")?;

    // Read the XML content
    let mut xml_content = String::new();
    rights_file
        .read_to_string(&mut xml_content)
        .context("Failed to read rights.xml")?;

    // Parse XML and find the encryptedKey tag
    let doc = roxmltree::Document::parse(&xml_content).context("Failed to parse rights.xml")?;

    // Find the encryptedKey element and return its text content
    doc.descendants()
        .find(|n| n.has_tag_name("encryptedKey"))
        .and_then(|n| n.text())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("encryptedKey tag not found in rights.xml"))
}

/// Decrypts an encrypted key from an EPUB using an RSA private key.
/// The encrypted key is expected to be Base64 encoded and encrypted with PKCS#1 v1.5 padding.
///
/// # Arguments
/// * `encrypted_key_b64` - The Base64-encoded encrypted key from the EPUB
/// * `rsa_key` - The RSA private key to use for decryption
///
/// # Returns
/// The decrypted key as raw bytes
pub fn decrypt_content_key(encrypted_key_b64: &str, rsa_key: &RsaPrivateKey) -> Result<Vec<u8>> {
    // Decode the Base64 encrypted key
    let encrypted_key = base64::prelude::BASE64_STANDARD
        .decode(encrypted_key_b64.trim())
        .context("Failed to decode Base64 encrypted key")?;

    // Decrypt using RSA PKCS#1 v1.5
    let decrypted = rsa_key
        .decrypt(Pkcs1v15Encrypt, &encrypted_key)
        .context("Failed to decrypt key with RSA private key")?;

    Ok(decrypted)
}

/// Decrypts a single file from an EPUB using the decrypted AES key.
/// Adobe ADEPT DRM uses AES-128 CBC encryption with the IV stored as the first 16 bytes of each encrypted file.
///
/// # Arguments
/// * `epub_path` - Path to the EPUB file
/// * `file_path` - Path to the file within the EPUB (e.g., "OEBPS/chapter1.xhtml")
/// * `decrypted_key` - The decrypted AES key (obtained from decrypt_epub_key)
///
/// # Returns
/// The decrypted file contents as bytes
pub fn decrypt_epub_file<P: AsRef<Path>>(
    epub_path: P,
    file_path: &str,
    decrypted_key: &[u8],
) -> Result<Vec<u8>> {
    // Open the EPUB file
    let file = File::open(epub_path.as_ref())
        .with_context(|| format!("Failed to open EPUB file: {:?}", epub_path.as_ref()))?;
    let reader = BufReader::new(file);
    let mut archive = ZipArchive::new(reader).context("Failed to read EPUB as ZIP archive")?;

    // Extract the encrypted file
    let mut encrypted_file = archive
        .by_name(file_path)
        .with_context(|| format!("File '{}' not found in EPUB", file_path))?;

    // Read the encrypted content
    let mut encrypted_data = Vec::new();
    encrypted_file
        .read_to_end(&mut encrypted_data)
        .context("Failed to read encrypted file")?;

    // The first 16 bytes are the IV
    if encrypted_data.len() < 16 {
        bail!("Encrypted file too short (must be at least 16 bytes for IV)");
    }

    let iv = &encrypted_data[..16];
    // let iv = [0u8; 16]; // Adobe ADEPT uses a fixed IV of 16 zero bytes
    // let ciphertext = &encrypted_data[16..];
    let ciphertext = &encrypted_data[16..]; // The Python code seems to use the entire file as ciphertext, including the IV

    // Ensure key is 16 bytes (AES-128)
    if decrypted_key.len() != 16 {
        bail!(
            "Decrypted key must be 16 bytes for AES-128, got {}",
            decrypted_key.len()
        );
    }

    // Create AES-128-CBC cipher
    let cipher = Aes128CbcDec::new(decrypted_key.into(), iv.into());

    // Decrypt the content
    let mut decrypted = ciphertext.to_vec();
    let decrypted_data = cipher
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut decrypted)
        .map_err(|e| anyhow!("Failed to decrypt file content: {:?}", e))?;

    // Decompress using raw deflate (equivalent to zlib.decompressobj(-15) in Python)
    // If decompression fails, return the raw decrypted bytes (they might not be compressed)
    let decompressed = decompress_deflate(decrypted_data)?;

    Ok(decompressed)
}

/// Decompresses data using raw deflate (no zlib/gzip headers).
/// This matches Python's zlib.decompressobj(-15) behavior.
fn decompress_deflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .context("Deflate decompression failed")?;
    Ok(decompressed)
}

fn keykey() -> Result<Vec<u8>> {
    println!("{:x}", cpu_signature());
    let keykey_key: windows_registry::Value = CURRENT_USER.open(KEYKEY_PATH)?.get_value("key")?;
    let entropy = device_entropy()?;
    unsafe {
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        println!("Decrypting key with entropy: {}", hex::encode(&entropy));
        println!(
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
        println!(
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

    let aes_key_bytes = keykey()?;

    for subkey_name in subkey_names {
        println!("Processing subkey: {}", subkey_name);
        // Open each subkey
        let subkey = adept_key.open(&subkey_name)?;

        // Get the default value (type)
        let ktype = subkey.get_string("")?;

        println!("Subkey: {}  Type: {}", subkey_name, ktype);

        // We're only interested in 'credentials' keys
        if ktype == "credentials" {
            // Enumerate sub-subkeys
            let sub_subkeys = subkey.keys()?.collect::<Vec<_>>();

            for sub_subkey_name in sub_subkeys {
                let sub_subkey = subkey.open(&sub_subkey_name)?;
                let ktype2 = sub_subkey.get_string("")?;

                println!("  Sub-subkey: {}  Type: {}", sub_subkey_name, ktype2);

                // Collect information for each credential component
                if ktype2 == "privateLicenseKey" {
                    let value = sub_subkey.get_string("value")?;

                    println!("    privateLicenseKey  value: {}", value);

                    let decoded = decrypt_private_key(&value, &aes_key_bytes)?;
                    return Ok(AdeptKey {
                        key: decoded,
                        name: ("placeholder").to_string(),
                    });
                }
            }
        }
    }
    bail!("No credentials found in registry");
}

/// Decrypt the private license key using AES-CBC
/// Returns the parsed RSA private key.
fn decrypt_private_key(encrypted_b64: &str, key: &[u8]) -> Result<RsaPrivateKey> {
    // Decode base64
    let encrypted = base64::prelude::BASE64_STANDARD
        .decode(encrypted_b64)
        .context("Failed to decode base64")?;

    // Use 16 bytes zero IV as per the Python code
    let iv = [0u8; 16];

    // Ensure key is 16 bytes (128-bit AES)
    let mut aes_key = [0u8; 16];
    let key_len = std::cmp::min(key.len(), 16);
    aes_key[..key_len].copy_from_slice(&key[..key_len]);

    // Create cipher
    let cipher = Aes128CbcDec::new(&aes_key.into(), &iv.into());

    println!(
        "Decrypting private key with AES-128-CBC. Encrypted data length: {} bytes",
        encrypted.len()
    );

    // Decrypt
    let mut decrypted = encrypted.clone();
    let decrypted_data = cipher
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut decrypted)
        .map_err(|e| anyhow!("AES decryption failed: {:?}", e))?;

    println!(
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

    println!(
        "DER-encoded RSA private key (len={}): {}",
        der_bytes.len(),
        hex::encode(der_bytes)
    );

    RsaPrivateKey::from_pkcs1_der(der_bytes)
        .context("Failed to parse RSA private key from decrypted data")
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
