use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;

/// Parsed Adobe ADEPT signIn request data
#[derive(Debug)]
pub struct SignInData {
    pub method: String,
    /// Encrypted signIn data (encrypted with Adobe activation server's public key)
    pub sign_in_data_encrypted: Vec<u8>,
    pub public_auth_key: RsaPublicKey,
    pub encrypted_private_auth_key: Vec<u8>,
    pub public_license_key: RsaPublicKey,
    pub encrypted_private_license_key: Vec<u8>,
}

/// Parse an Adobe ADEPT signIn XML file
///
/// # Arguments
/// * `path` - Path to the signIn XML file
///
/// # Returns
/// Parsed SignInData structure with decoded fields
pub fn parse_signin_xml(path: &Path) -> Result<SignInData> {
    // Read the XML file
    let xml_content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read signIn XML file: {}", path.display()))?;

    // Parse XML
    let doc = roxmltree::Document::parse(&xml_content).context("Failed to parse signIn XML")?;

    // Find the signIn element and get method attribute
    let signin_node = doc
        .descendants()
        .find(|n| n.has_tag_name("signIn"))
        .context("No signIn element found")?;

    let method = signin_node
        .attribute("method")
        .unwrap_or("unknown")
        .to_string();

    // Extract signInData (encrypted with Adobe activation server's public key)
    let sign_in_data_b64 = doc
        .descendants()
        .find(|n| n.has_tag_name("signInData"))
        .and_then(|n| n.text())
        .context("No signInData element found")?;

    let sign_in_data_encrypted =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sign_in_data_b64)
            .context("Failed to decode signInData")?;

    // Extract publicAuthKey
    let public_auth_key_b64 = doc
        .descendants()
        .find(|n| n.has_tag_name("publicAuthKey"))
        .and_then(|n| n.text())
        .context("No publicAuthKey element found")?;

    let public_auth_key_der = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        public_auth_key_b64,
    )
    .context("Failed to decode publicAuthKey")?;

    // Public keys are in X509 SubjectPublicKeyInfo (SPKI) format from i2d_X509_PUBKEY()
    let public_auth_key = RsaPublicKey::from_public_key_der(&public_auth_key_der)
        .context("Failed to parse publicAuthKey as RSA public key (SPKI format)")?;

    // Extract encryptedPrivateAuthKey
    let encrypted_private_auth_key_b64 = doc
        .descendants()
        .find(|n| n.has_tag_name("encryptedPrivateAuthKey"))
        .and_then(|n| n.text())
        .context("No encryptedPrivateAuthKey element found")?;

    let encrypted_private_auth_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encrypted_private_auth_key_b64,
    )
    .context("Failed to decode encryptedPrivateAuthKey")?;

    // Extract publicLicenseKey
    let public_license_key_b64 = doc
        .descendants()
        .find(|n| n.has_tag_name("publicLicenseKey"))
        .and_then(|n| n.text())
        .context("No publicLicenseKey element found")?;

    let public_license_key_der = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        public_license_key_b64,
    )
    .context("Failed to decode publicLicenseKey")?;

    // Public keys are in X509 SubjectPublicKeyInfo (SPKI) format from i2d_X509_PUBKEY()
    let public_license_key = RsaPublicKey::from_public_key_der(&public_license_key_der)
        .context("Failed to parse publicLicenseKey as RSA public key (SPKI format)")?;

    // Extract encryptedPrivateLicenseKey
    let encrypted_private_license_key_b64 = doc
        .descendants()
        .find(|n| n.has_tag_name("encryptedPrivateLicenseKey"))
        .and_then(|n| n.text())
        .context("No encryptedPrivateLicenseKey element found")?;

    let encrypted_private_license_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encrypted_private_license_key_b64,
    )
    .context("Failed to decode encryptedPrivateLicenseKey")?;

    Ok(SignInData {
        method,
        sign_in_data_encrypted,
        public_auth_key,
        encrypted_private_auth_key,
        public_license_key,
        encrypted_private_license_key,
    })
}
