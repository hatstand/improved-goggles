#![cfg(windows)]

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use aes::Aes128;
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use cbc::{
    cipher::{BlockDecryptMut, KeyIvInit},
    Decryptor,
};
use flate2::read::DeflateDecoder;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use zip::ZipArchive;

mod adept_keys;
mod safe_strings;

// Re-export public API
pub use adept_keys::{adeptkeys, AdeptKey};

type Aes128CbcDec = Decryptor<Aes128>;

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
    let ciphertext = &encrypted_data[16..];

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adept_keys::*;

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
        let serial = adept_keys::volume_serial_number("C:\\").expect("wut");
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
