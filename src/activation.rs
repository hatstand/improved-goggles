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

/// Parsed Adobe ADEPT signIn response data (credentials)
#[derive(Debug)]
pub struct SignInResponse {
    pub user: String,
    pub username: String,
    pub username_method: String,
    pub pkcs12: Vec<u8>,
    pub encrypted_private_license_key: Vec<u8>,
    pub license_certificate: Vec<u8>,
}

/// Parse an Adobe ADEPT signIn response XML file
///
/// # Arguments
/// * `path` - Path to the signIn response XML file (credentials)
///
/// # Returns
/// Parsed SignInResponse structure with decoded fields
pub fn parse_signin_response(contents: &str) -> Result<SignInResponse> {
    // Parse XML
    let doc =
        roxmltree::Document::parse(contents).context("Failed to parse signIn response XML")?;

    // Find the credentials element
    let credentials_node = doc
        .descendants()
        .find(|n| n.has_tag_name("credentials"))
        .context("No credentials element found")?;

    // Extract user
    let user = credentials_node
        .descendants()
        .find(|n| n.has_tag_name("user"))
        .and_then(|n| n.text())
        .context("No user element found")?
        .to_string();

    // Extract username and method
    let username_node = doc
        .descendants()
        .find(|n| n.has_tag_name("username"))
        .context("No username element found")?;

    let username_method = username_node
        .attribute("method")
        .unwrap_or("unknown")
        .to_string();

    let username = username_node.text().unwrap_or("").to_string();

    // Extract pkcs12
    let pkcs12_b64 = doc
        .descendants()
        .find(|n| n.has_tag_name("pkcs12"))
        .and_then(|n| n.text())
        .context("No pkcs12 element found")?;

    let pkcs12 = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pkcs12_b64)
        .context("Failed to decode pkcs12")?;

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

    // Extract licenseCertificate
    let license_certificate_b64 = doc
        .descendants()
        .find(|n| n.has_tag_name("licenseCertificate"))
        .and_then(|n| n.text())
        .context("No licenseCertificate element found")?;

    let license_certificate = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        license_certificate_b64,
    )
    .context("Failed to decode licenseCertificate")?;

    Ok(SignInResponse {
        user,
        username,
        username_method,
        pkcs12,
        encrypted_private_license_key,
        license_certificate,
    })
}
