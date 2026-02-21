use anyhow::{Context, Result};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use xml::writer::EmitterConfig;

use crate::{
    generate_fulfill_request_minified, load_keys, parse_acsm, parse_fulfillment_response,
    sign_fulfill_request, AdeptKey,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", rename = "adept:credentials")]
struct Credentials {
    #[serde(rename = "adept:user")]
    user: String,
    #[serde(rename = "adept:certificate")]
    certificate: String,
    #[serde(rename = "adept:licenseCertificate")]
    license_certificate: String,
    #[serde(rename = "adept:authenticationCertificate")]
    authentication_certificate: String,
}

pub fn create_signin_request(operatorURL: &str, keys: &AdeptKey) -> Result<String> {
    println!("Signing in to Adobe account at {}...", operatorURL);

    let creds = Credentials {
        user: keys.user.clone(),
        certificate: keys.device.clone(),
        license_certificate: keys.fingerprint.clone(),
        authentication_certificate: keys.fingerprint.clone(),
    };

    let config = serde_xml_rs::SerdeXml::new()
        .namespace("adept", "http://ns.adobe.com/adept")
        .emitter(xml::EmitterConfig::new().perform_indent(true));
    config
        .to_string(&creds)
        .with_context(|| "Failed to serialize credentials to XML")
}

pub fn fetch_epub(
    acsm: PathBuf,
    output: PathBuf,
    dry_run: bool,
    key_path: Option<PathBuf>,
) -> Result<()> {
    if dry_run {
        println!("[DRY RUN] Fetching EPUB from ACSM file...");
    } else {
        println!("Fetching EPUB from ACSM file...");
    }
    println!("  ACSM: {}", acsm.display());
    println!("  Output: {}", output.display());

    // Parse the ACSM file
    println!("  Parsing ACSM file...");
    let acsm_info = parse_acsm(&acsm)?;

    // Extract device key for signing
    let key = load_keys(key_path)?;

    // Generate the minified fulfill request
    println!("  Generating fulfillment request...");
    let fulfill_xml =
        generate_fulfill_request_minified(&acsm_info, &key.user, &key.device, &key.fingerprint);

    // Sign the request
    println!("  Signing fulfillment request...");
    let signature = sign_fulfill_request(&fulfill_xml, &key.private_auth_key)?;
    println!("  ✓ Signed fulfill request");

    // Add signature to complete the XML
    let complete_xml = format!(
        "{}<adept:signature>{}</adept:signature></adept:fulfill>",
        &fulfill_xml[..fulfill_xml.len() - 16], // Remove </adept:fulfill>
        signature
    );

    // Print the fulfillment request
    println!("\n--- Fulfillment Request ---");
    println!("{}", complete_xml);
    println!("--- End Fulfillment Request ---\n");

    // Create debug trace file with RFC3339 timestamp
    let timestamp = Timestamp::now().to_string().replace(':', "-");
    let trace_file = output.with_file_name(format!(
        "{}.{}.trace.txt",
        output.file_stem().unwrap().to_string_lossy(),
        timestamp
    ));
    let trace_content = std::cell::RefCell::new(String::new());
    trace_content
        .borrow_mut()
        .push_str("=== ADEPT Fulfillment Debug Trace ===\n\n");

    // Ensure trace file is written on scope exit
    defer::defer! {
        if let Err(e) = fs::write(&trace_file, &*trace_content.borrow()) {
            eprintln!("Failed to write trace file: {}", e);
        } else {
            println!("  Debug trace saved to: {}", trace_file.display());
        }
    }

    // Make HTTP POST request to operator URL
    // The fulfillment endpoint is operatorURL + "/Fulfill"
    let fulfill_url = format!("{}/Fulfill", acsm_info.operator_url.trim_end_matches('/'));

    if dry_run {
        println!(
            "  [DRY RUN] Would send fulfillment request to {}...",
            fulfill_url
        );
    } else {
        println!("  Sending fulfillment request to {}...", fulfill_url);
    }

    // Log request
    trace_content.borrow_mut().push_str(&format!(
        "--- FULFILLMENT REQUEST ---\n\
                POST {}\n\
                Accept: */*\n\
                Content-Type: application/vnd.adobe.adept+xml\n\
                User-Agent: book2png\n\
                Content-Length: {}\n\n\
                {}\n\n",
        fulfill_url,
        complete_xml.len(),
        complete_xml
    ));

    if dry_run {
        println!(
            "  [DRY RUN] Would POST {} bytes to {}",
            complete_xml.len(),
            fulfill_url
        );
        println!("  [DRY RUN] Skipping actual HTTP request");
        println!("\n✓ Dry run completed successfully");
        println!("  No files were written");
        println!("  No HTTP requests were made");
        return Ok(());
    }

    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true) // Accept invalid certificates
        .build()?;

    let response = client
        .post(&fulfill_url)
        .header("Accept", "*/*")
        .header("Content-Type", "application/vnd.adobe.adept+xml")
        .header("User-Agent", "book2png")
        .body(complete_xml.clone())
        .send()
        .with_context(|| format!("Failed to send request to {}", fulfill_url))?;

    let status = response.status();
    println!("  Response status: {}", status);

    // Log response status and headers
    trace_content.borrow_mut().push_str(&format!(
        "--- FULFILLMENT RESPONSE ---\n\
                Status: {}\n",
        status
    ));
    for (name, value) in response.headers() {
        trace_content.borrow_mut().push_str(&format!(
            "{}: {}\n",
            name,
            value.to_str().unwrap_or("<binary>")
        ));
    }
    trace_content.borrow_mut().push('\n');

    if !status.is_success() {
        use anyhow::bail;
        let response_text = response.text().unwrap_or_default();
        trace_content
            .borrow_mut()
            .push_str(&format!("{}\n\n", response_text));
        bail!(
            "Fulfillment request failed with status {}: {}",
            status,
            response_text
        );
    }

    // Parse the fulfillment response
    let response_text = response.text()?;
    trace_content
        .borrow_mut()
        .push_str(&format!("{}\n\n", response_text));
    println!("  ✓ Received fulfillment response");

    println!("  Parsing fulfillment response...");
    let download_urls = parse_fulfillment_response(&response_text)?;
    println!("  ✓ Found {} download URL(s)", download_urls.len());

    // Download the first EPUB file
    if let Some(epub_url) = download_urls.first() {
        use std::fs;

        println!("  Downloading EPUB from {}...", epub_url);

        // Log EPUB download request
        trace_content.borrow_mut().push_str(&format!(
            "--- EPUB DOWNLOAD REQUEST ---\n\
                    GET {}\n\
                    Accept: */*\n\
                    User-Agent: book2png\n\n",
            epub_url
        ));

        let epub_response = client
            .get(epub_url)
            .header("Accept", "*/*")
            .header("User-Agent", "book2png")
            .send()
            .with_context(|| format!("Failed to download EPUB from {}", epub_url))?;

        let epub_status = epub_response.status();
        println!("  Download status: {}", epub_status);

        // Log EPUB response
        trace_content.borrow_mut().push_str(&format!(
            "--- EPUB DOWNLOAD RESPONSE ---\n\
                    Status: {}\n",
            epub_status
        ));
        for (name, value) in epub_response.headers() {
            trace_content.borrow_mut().push_str(&format!(
                "{}: {}\n",
                name,
                value.to_str().unwrap_or("<binary>")
            ));
        }
        trace_content.borrow_mut().push('\n');

        if !epub_status.is_success() {
            use anyhow::bail;
            bail!("Failed to download EPUB: HTTP {}", epub_status);
        }

        let epub_bytes = epub_response.bytes()?;
        trace_content.borrow_mut().push_str(&format!(
            "Body: <binary data, {} bytes>\n\n",
            epub_bytes.len()
        ));

        fs::write(&output, &epub_bytes)?;

        println!("✓ Successfully downloaded EPUB");
        println!("  Saved to: {}", output.display());
        println!("  Size: {} bytes", epub_bytes.len());
    } else {
        use anyhow::bail;
        bail!("No download URLs found in fulfillment response");
    }

    Ok(())
}
