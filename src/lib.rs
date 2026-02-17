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

#[cfg(windows)]
mod adept_keys;
#[cfg(windows)]
mod safe_strings;

mod acsm;

// Re-export public API
pub use acsm::{parse_acsm, AcsmInfo};
#[cfg(windows)]
pub use adept_keys::{adept_device, adept_fingerprint, adept_user, adeptkeys, AdeptKey};

// Non-Windows stub
#[cfg(not(windows))]
#[derive(Debug)]
pub struct AdeptKey {
    pub key: RsaPrivateKey,
    pub name: String,
}

#[cfg(not(windows))]
pub fn adeptkeys() -> Result<AdeptKey> {
    bail!("adeptkeys() is only available on Windows. This function requires access to the Windows Registry.")
}

#[cfg(not(windows))]
pub fn adept_user() -> Result<String> {
    bail!("adept_user() is only available on Windows. This function requires access to the Windows Registry.")
}

#[cfg(not(windows))]
pub fn adept_device() -> Result<String> {
    bail!("adept_device() is only available on Windows. This function requires access to the Windows Registry.")
}

#[cfg(not(windows))]
pub fn adept_fingerprint() -> Result<String> {
    bail!("adept_fingerprint() is only available on Windows. This function requires access to the Windows Registry.")
}

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

/// Extracts the list of encrypted file paths from META-INF/encryption.xml
pub fn list_encrypted_files<P: AsRef<Path>>(epub_path: P) -> Result<Vec<String>> {
    // Open the EPUB file (which is a ZIP archive)
    let file = File::open(epub_path.as_ref())
        .with_context(|| format!("Failed to open EPUB file: {:?}", epub_path.as_ref()))?;
    let reader = BufReader::new(file);
    let mut archive = ZipArchive::new(reader).context("Failed to read EPUB as ZIP archive")?;

    // Try to extract META-INF/encryption.xml
    let mut encryption_file = match archive.by_name("META-INF/encryption.xml") {
        Ok(f) => f,
        Err(_) => {
            // No encryption.xml means no encrypted files
            return Ok(Vec::new());
        }
    };

    // Read the XML content
    let mut xml_content = String::new();
    encryption_file
        .read_to_string(&mut xml_content)
        .context("Failed to read encryption.xml")?;

    // Parse XML and find all CipherReference URIs
    let doc = roxmltree::Document::parse(&xml_content).context("Failed to parse encryption.xml")?;

    let encrypted_files: Vec<String> = doc
        .descendants()
        .filter(|n| n.has_tag_name("CipherReference"))
        .filter_map(|n| n.attribute("URI"))
        .map(|s| s.to_string())
        .collect();

    Ok(encrypted_files)
}

/// Decrypts an entire EPUB and writes a new unencrypted EPUB file.
///
/// # Arguments
/// * `input_path` - Path to the encrypted EPUB file
/// * `output_path` - Path where the decrypted EPUB will be written
/// * `rsa_key` - The RSA private key to decrypt the content key
///
/// # Returns
/// Number of files decrypted
pub fn decrypt_epub<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    rsa_key: &RsaPrivateKey,
) -> Result<usize> {
    use std::io::Write;
    use zip::write::{SimpleFileOptions, ZipWriter};

    // Extract the encrypted content key from the EPUB
    let encrypted_content_key = extract_content_key(&input_path)?;

    // Decrypt the content key using RSA
    let content_key = decrypt_content_key(&encrypted_content_key, rsa_key)?;

    // Get list of encrypted files
    let encrypted_files = list_encrypted_files(&input_path)?;
    let encrypted_set: std::collections::HashSet<String> =
        encrypted_files.iter().cloned().collect();

    // Open input EPUB
    let input_file = File::open(input_path.as_ref())
        .with_context(|| format!("Failed to open input EPUB: {:?}", input_path.as_ref()))?;
    let reader = BufReader::new(input_file);
    let mut input_archive =
        ZipArchive::new(reader).context("Failed to read input EPUB as ZIP archive")?;

    // Create output EPUB
    let output_file = File::create(output_path.as_ref())
        .with_context(|| format!("Failed to create output EPUB: {:?}", output_path.as_ref()))?;
    let mut output_archive = ZipWriter::new(output_file);

    let options: SimpleFileOptions =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut decrypted_count = 0;

    // Process all files in the EPUB
    for i in 0..input_archive.len() {
        let mut file = input_archive.by_index(i)?;
        let name = file.name().to_string();

        // Skip DRM-related metadata files
        if name == "META-INF/rights.xml" || name == "META-INF/encryption.xml" {
            continue;
        }

        // Check if file is encrypted
        if encrypted_set.contains(&name) {
            // Read encrypted data
            let mut encrypted_data = Vec::new();
            file.read_to_end(&mut encrypted_data)?;
            drop(file);

            // Decrypt the file
            if encrypted_data.len() < 16 {
                bail!("Encrypted file '{}' too short", name);
            }

            let iv = &encrypted_data[..16];
            let ciphertext = &encrypted_data[16..];

            // Ensure key is 16 bytes (AES-128)
            if content_key.len() != 16 {
                bail!(
                    "Content key must be 16 bytes for AES-128, got {}",
                    content_key.len()
                );
            }

            // Create AES-128-CBC cipher
            let cipher = Aes128CbcDec::new((&content_key[..16]).into(), iv.into());

            // Decrypt the content
            let mut decrypted = ciphertext.to_vec();
            let decrypted_data = cipher
                .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut decrypted)
                .map_err(|e| anyhow!("Failed to decrypt file '{}': {:?}", name, e))?;

            // Decompress
            let decompressed = decompress_deflate(decrypted_data)
                .with_context(|| format!("Failed to decompress file '{}'", name))?;

            // Write decrypted file to output
            output_archive.start_file(&name, options)?;
            output_archive.write_all(&decompressed)?;

            decrypted_count += 1;
        } else {
            // Copy unencrypted file as-is
            let mut content = Vec::new();
            file.read_to_end(&mut content)?;
            drop(file);

            output_archive.start_file(&name, options)?;
            output_archive.write_all(&content)?;
        }
    }

    output_archive.finish()?;

    Ok(decrypted_count)
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
