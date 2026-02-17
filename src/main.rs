use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use jiff::Timestamp;
use log::debug;
use rmpub::{
    decrypt_content_key, decrypt_epub, decrypt_epub_file, decrypt_private_key_with_iv,
    extract_content_key, generate_fulfill_request, generate_fulfill_request_minified, parse_acsm,
    parse_fulfillment_response, parse_signin_response, parse_signin_xml, sign_fulfill_request,
    verify_fulfill_request,
};
use std::fs;
use std::path::PathBuf;

use base64::Engine;
use p12::PFX;
use rsa::pkcs1::DecodeRsaPrivateKey;

#[cfg(windows)]
use rmpub::{adept_device, adept_fingerprint, adept_user, adeptkeys};
#[cfg(windows)]
use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};

#[derive(Parser)]
#[command(name = "rmpub")]
#[command(about = "Adobe ADEPT DRM key extraction and EPUB decryption tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Extract device RSA private key from Windows Registry
    ExtractKey {
        /// Output file path for the private key (DER format)
        #[arg(short, long, default_value = "adept_key.der")]
        output: PathBuf,
    },
    /// Decrypt a file from a DRM-protected EPUB
    DecryptFile {
        /// Path to the EPUB file
        epub: PathBuf,

        /// Path to the file within the EPUB to decrypt (e.g., "OEBPS/Text/chapter1.xhtml")
        file: String,

        /// Output file path for the decrypted content. If not specified, saves to current directory with same filename.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Path to a pre-extracted device key file (DER format). If not provided, will extract from registry.
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    /// Decrypt an entire EPUB file, removing all DRM
    DecryptEpub {
        /// Path to the encrypted EPUB file
        input: PathBuf,

        /// Path for the decrypted output EPUB file
        #[arg(short, long)]
        output: PathBuf,

        /// Path to a pre-extracted device key file (DER format). If not provided, will extract from registry.
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    /// Fetch an encrypted EPUB from an operator based on an ACSM file
    FetchEpub {
        /// Path to the ACSM file
        acsm: PathBuf,

        /// Output file path for the downloaded EPUB
        #[arg(short, long)]
        output: PathBuf,

        /// Path to a pre-extracted device key file (DER format). If not provided, will extract from registry.
        #[arg(short, long)]
        key: Option<PathBuf>,

        /// Dry run - show what would be done without making requests or writing files
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Debug commands for development and troubleshooting
    Debug {
        #[command(subcommand)]
        command: DebugCommands,
    },
}

#[derive(Subcommand)]
enum DebugCommands {
    /// Extract the Adept user GUID from Windows Registry
    ExtractUser,
    /// Extract the Adept device identifier from Windows Registry
    ExtractDevice,
    /// Extract the Adept fingerprint from Windows Registry
    ExtractFingerprint,
    /// Generate a fulfill request XML from an ACSM file
    GenerateFulfillRequest {
        /// Path to the ACSM file
        acsm: PathBuf,

        /// Path to a pre-extracted device key file (DER format). If not provided, will extract from registry.
        #[arg(short, long)]
        key: Option<PathBuf>,

        /// User GUID (e.g., "urn:uuid:..."). If not provided, will extract from registry on Windows.
        #[arg(short, long)]
        user: Option<String>,

        /// Device GUID (e.g., "urn:uuid:..."). If not provided, will extract from registry on Windows.
        #[arg(short, long)]
        device: Option<String>,

        /// Device fingerprint (base64-encoded). If not provided, will extract from registry on Windows.
        #[arg(short, long)]
        fingerprint: Option<String>,

        /// Include signature in the output
        #[arg(short, long)]
        sign: bool,
    },
    /// Verify the RSA signature in a fulfill request XML file
    VerifySignature {
        /// Path to the fulfill request XML file
        xml: PathBuf,

        /// Path to a pre-extracted device key file (DER format). If not provided, will extract from registry.
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    /// Read a PKCS12 file and display its contents
    ReadPkcs12 {
        /// Path to the PKCS12 (.p12 or .pfx) file
        file: PathBuf,

        /// Password for the PKCS12 file (optional)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Parse an Adobe ADEPT signIn XML file and decrypt keys
    ParseSignIn {
        /// Path to the signIn XML file
        xml: PathBuf,

        /// Path to Adobe activation server's private key (for decrypting signInData, rarely available)
        #[arg(short, long)]
        server_key: Option<PathBuf>,
    },
    /// Parse an Adobe ADEPT signIn response (credentials) file
    ParseSignInResponse {
        /// Path to the signIn response XML file
        xml: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::ExtractKey { output } => {
            #[cfg(not(windows))]
            {
                use anyhow::bail;
                _ = output; // Suppress unused variable warning

                bail!("Key extraction from registry is not supported on this platform. Please use --key parameter with a pre-extracted key file.");
            }

            #[cfg(windows)]
            {
                println!("Extracting device key from Windows Registry...");

                let key = adeptkeys()?;

                // Export the RSA private key to DER format
                let der_bytes = key.private_license_key.to_pkcs1_der()?;
                fs::write(&output, der_bytes.as_bytes())?;

                println!(
                    "✓ Successfully extracted device key to: {}",
                    output.display()
                );
                println!("  Key name: {}", key.name);
                println!("  Key size: {} bits", key.private_license_key.size() * 8);
                Ok(())
            }
        }
        Commands::DecryptFile {
            epub,
            file,
            output,
            key,
        } => {
            // Determine output path: use provided or extract filename from file path
            let output_path = if let Some(out) = output {
                out
            } else {
                // Extract just the filename from the file path
                let filename = std::path::Path::new(&file)
                    .file_name()
                    .context("Invalid file path")?
                    .to_string_lossy()
                    .to_string();
                PathBuf::from(filename)
            };

            println!("Decrypting file from EPUB...");
            println!("  EPUB: {}", epub.display());
            println!("  File: {}", file);
            println!("  Output: {}", output_path.display());

            // Get the RSA private key
            let rsa_key = if let Some(key_path) = key {
                use rsa::pkcs1::DecodeRsaPrivateKey;

                debug!("Using key from: {}", key_path.display());
                let der_bytes = fs::read(key_path)?;
                rsa::RsaPrivateKey::from_pkcs1_der(&der_bytes)?
            } else {
                #[cfg(windows)]
                {
                    println!("  Extracting key from registry...");
                    let key = adeptkeys()?;
                    println!("  Using key: {}", key.name);
                    key.private_license_key
                }

                #[cfg(not(windows))]
                {
                    eprintln!("Error: Key extraction from registry is only available on Windows.");
                    eprintln!("Please use --key parameter with a pre-extracted key file.");
                    std::process::exit(1);
                }
            };

            // Extract the encrypted content key from the EPUB
            println!("  Extracting content key from EPUB...");
            let encrypted_content_key = extract_content_key(&epub)?;

            // Decrypt the content key using RSA
            println!("  Decrypting content key...");
            let content_key = decrypt_content_key(&encrypted_content_key, &rsa_key)?;
            debug!("Content key: {}", hex::encode(&content_key));

            // Decrypt the specific file
            println!("  Decrypting file content...");
            let decrypted_content = decrypt_epub_file(&epub, &file, &content_key)?;

            // Write to output
            fs::write(&output_path, &decrypted_content)?;

            println!(
                "✓ Successfully decrypted file ({} bytes)",
                decrypted_content.len()
            );
            println!("  Saved to: {}", output_path.display());

            Ok(())
        }
        Commands::DecryptEpub { input, output, key } => {
            println!("Decrypting entire EPUB...");
            println!("  Input: {}", input.display());
            println!("  Output: {}", output.display());

            // Get the RSA private key
            let rsa_key = if let Some(key_path) = key {
                use rsa::pkcs1::DecodeRsaPrivateKey;

                debug!("Using key from: {}", key_path.display());
                let der_bytes = fs::read(key_path)?;
                rsa::RsaPrivateKey::from_pkcs1_der(&der_bytes)?
            } else {
                #[cfg(windows)]
                {
                    println!("  Extracting key from registry...");
                    let key = adeptkeys()?;
                    println!("  Using key: {}", key.name);
                    key.private_license_key
                }

                #[cfg(not(windows))]
                {
                    eprintln!("Error: Key extraction from registry is only available on Windows.");
                    eprintln!("Please use --key parameter with a pre-extracted key file.");
                    std::process::exit(1);
                }
            };

            // Decrypt the entire EPUB
            println!("  Decrypting files...");
            let decrypted_count = decrypt_epub(&input, &output, &rsa_key)?;

            println!("✓ Successfully decrypted EPUB");
            println!("  Decrypted {} files", decrypted_count);
            println!("  Output: {}", output.display());

            Ok(())
        }
        Commands::FetchEpub {
            acsm,
            output,
            key: _key,
            dry_run,
        } => {
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

            // Get user, device, and fingerprint from registry
            #[cfg(not(windows))]
            {
                use anyhow::bail;
                bail!(
                    "FetchEpub requires registry access and is only available on Windows for now."
                );
            }

            #[cfg(windows)]
            {
                println!("  Extracting credentials from registry...");
                let user_val = adept_user()?;
                let device_val = adept_device()?;
                let fingerprint_val = adept_fingerprint()?;
                println!("  ✓ Got user, device, and fingerprint");

                // Extract device key for signing
                println!("  Extracting device key from registry...");
                let key = adeptkeys()?;
                println!("  ✓ Got device key");

                // Generate the minified fulfill request
                println!("  Generating fulfillment request...");
                let fulfill_xml = generate_fulfill_request_minified(
                    &acsm_info,
                    &user_val,
                    &device_val,
                    &fingerprint_val,
                );

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
                let fulfill_url =
                    format!("{}/Fulfill", acsm_info.operator_url.trim_end_matches('/'));

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
        }
        Commands::Debug { command } => match command {
            DebugCommands::ExtractUser => {
                #[cfg(not(windows))]
                {
                    use anyhow::bail;
                    bail!("User extraction from registry is not supported on this platform. This command is only available on Windows.");
                }

                #[cfg(windows)]
                {
                    println!("Extracting Adept user from Windows Registry...");

                    let user = adept_user()?;

                    println!("✓ Successfully extracted Adept user");
                    println!("  User GUID: {}", user);
                    Ok(())
                }
            }
            DebugCommands::ExtractDevice => {
                #[cfg(not(windows))]
                {
                    use anyhow::bail;
                    bail!("Device extraction from registry is not supported on this platform. This command is only available on Windows.");
                }

                #[cfg(windows)]
                {
                    println!("Extracting Adept device from Windows Registry...");

                    let device = adept_device()?;

                    println!("✓ Successfully extracted Adept device");
                    println!("  Device identifier: {}", device);
                    Ok(())
                }
            }
            DebugCommands::ExtractFingerprint => {
                #[cfg(not(windows))]
                {
                    use anyhow::bail;
                    bail!("Fingerprint extraction from registry is not supported on this platform. This command is only available on Windows.");
                }

                #[cfg(windows)]
                {
                    println!("Extracting Adept fingerprint from Windows Registry...");

                    let fingerprint = adept_fingerprint()?;

                    println!("✓ Successfully extracted Adept fingerprint");
                    println!("  Fingerprint: {}", fingerprint);
                    Ok(())
                }
            }
            DebugCommands::GenerateFulfillRequest {
                acsm,
                key,
                user,
                device,
                fingerprint,
                sign,
            } => {
                println!("Generating fulfill request from ACSM file...");
                println!("  ACSM: {}", acsm.display());

                // Parse the ACSM file
                let acsm_info = parse_acsm(&acsm)?;
                println!("  ✓ Parsed ACSM file");

                // Get user, device, and fingerprint
                let user_val = match user {
                    Some(u) => u,
                    None => {
                        #[cfg(not(windows))]
                        {
                            use anyhow::bail;
                            bail!(
                                "User GUID must be provided with --user on non-Windows platforms"
                            );
                        }
                        #[cfg(windows)]
                        {
                            println!("  Extracting user from registry...");
                            adept_user()?
                        }
                    }
                };

                let device_val = match device {
                    Some(d) => d,
                    None => {
                        #[cfg(not(windows))]
                        {
                            use anyhow::bail;
                            bail!(
                                "Device GUID must be provided with --device on non-Windows platforms"
                            );
                        }
                        #[cfg(windows)]
                        {
                            println!("  Extracting device from registry...");
                            adept_device()?
                        }
                    }
                };

                let fingerprint_val = match fingerprint {
                    Some(f) => f,
                    None => {
                        #[cfg(not(windows))]
                        {
                            use anyhow::bail;
                            bail!("Fingerprint must be provided with --fingerprint on non-Windows platforms");
                        }
                        #[cfg(windows)]
                        {
                            println!("  Extracting fingerprint from registry...");
                            adept_fingerprint()?
                        }
                    }
                };

                println!("  ✓ Got user, device, and fingerprint");

                // Generate the fulfill request
                let fulfill_xml =
                    generate_fulfill_request(&acsm_info, &user_val, &device_val, &fingerprint_val);
                println!("  ✓ Generated fulfill request");

                // Sign if requested
                if sign {
                    let private_key = match key {
                        Some(key_path) => {
                            println!("  Loading device key from {}...", key_path.display());
                            let key_bytes = fs::read(&key_path).with_context(|| {
                                format!("Failed to read key file: {:?}", key_path)
                            })?;
                            rsa::RsaPrivateKey::from_pkcs1_der(&key_bytes)
                                .context("Failed to parse device key")?
                        }
                        None => {
                            #[cfg(not(windows))]
                            {
                                use anyhow::bail;
                                bail!(
                                    "Key file must be provided with --key on non-Windows platforms"
                                );
                            }
                            #[cfg(windows)]
                            {
                                println!("  Extracting device key from registry...");
                                let key = adeptkeys()?;
                                key.private_license_key
                            }
                        }
                    };

                    let signature = sign_fulfill_request(&fulfill_xml, &private_key)?;
                    println!("  ✓ Signed fulfill request");

                    // Output the complete signed request
                    println!("\n{}", fulfill_xml.trim_end());
                    println!("  <adept:signature>{}</adept:signature>", signature);
                    println!("</adept:fulfill>");
                } else {
                    // Output the unsigned request
                    println!("\n{}", fulfill_xml);
                }

                Ok(())
            }
            DebugCommands::VerifySignature { xml, key } => {
                println!("Verifying signature in fulfill request XML...");
                println!("  XML file: {}", xml.display());

                // Load the private key (to derive public key from it)
                let private_key = match key {
                    Some(key_path) => {
                        println!("  Loading device key from {}...", key_path.display());
                        let key_bytes = fs::read(&key_path)
                            .with_context(|| format!("Failed to read key file: {:?}", key_path))?;
                        rsa::RsaPrivateKey::from_pkcs1_der(&key_bytes)
                            .context("Failed to parse device key")?
                    }
                    None => {
                        #[cfg(not(windows))]
                        {
                            use anyhow::bail;
                            bail!("Key file must be provided with --key on non-Windows platforms");
                        }
                        #[cfg(windows)]
                        {
                            println!("  Extracting device key from registry...");
                            let key = adeptkeys()?;
                            key.private_auth_key
                        }
                    }
                };

                println!("  ✓ Loaded private key");

                // Verify the signature
                let is_valid = verify_fulfill_request(&xml, &private_key)?;

                if is_valid {
                    println!("✓ Signature is VALID");
                } else {
                    println!("✗ Signature is INVALID");
                }

                Ok(())
            }
            DebugCommands::ReadPkcs12 { file, password } => {
                println!("Reading PKCS12 file...");
                println!("  File: {}", file.display());

                // Read the PKCS12 file
                let pfx_data = fs::read(&file)
                    .with_context(|| format!("Failed to read PKCS12 file: {}", file.display()))?;

                // Parse the PKCS12 file
                let password = password.as_deref().unwrap_or("");
                println!(
                    "  Using password: {}",
                    if password.is_empty() {
                        "<empty>"
                    } else {
                        "<provided>"
                    }
                );

                let pfx = PFX::parse(&pfx_data)
                    .map_err(|e| anyhow::anyhow!("Failed to parse PKCS12 file: {:?}", e))?;

                // Extract the key and certificate
                let bags = pfx.bags(password).map_err(|e| {
                    anyhow::anyhow!("Failed to decrypt PKCS12 (wrong password?): {:?}", e)
                })?;

                println!("\n✓ Successfully parsed PKCS12 file\n");
                println!("Total bags found: {}\n", bags.len());

                // Try to find and display keys and certificates
                for (i, bag) in bags.iter().enumerate() {
                    println!("  Bag #{}:", i + 1);

                    // Try to get friendly name from attributes
                    for attr in &bag.attributes {
                        // Check the debug format to see what we have
                        let attr_str = format!("{:?}", attr);
                        if attr_str.contains("FriendlyName") {
                            println!("    {}", attr_str);
                        }
                    }

                    // Display bag type
                    let bag_type = format!("{:?}", bag.bag);
                    if bag_type.contains("Data") {
                        let data_len = if let Some(start) = bag_type.find('[') {
                            if let Some(end) = bag_type.find(']') {
                                &bag_type[start + 1..end]
                            } else {
                                "unknown"
                            }
                        } else {
                            "unknown"
                        };
                        println!("    Type: Encrypted data ({} bytes)", data_len);
                    } else {
                        println!(
                            "    Type: {}",
                            bag_type.split('(').next().unwrap_or(&bag_type)
                        );
                    }

                    println!();
                }

                println!("\nNote: Use openssl to extract keys and certificates:");
                println!(
                    "  openssl pkcs12 -in {} -nodes -out output.pem",
                    file.display()
                );
                println!(
                    "  openssl pkcs12 -in {} -nocerts -nodes -out key.pem",
                    file.display()
                );
                println!(
                    "  openssl pkcs12 -in {} -nokeys -out cert.pem",
                    file.display()
                );

                Ok(())
            }
            DebugCommands::ParseSignIn { xml, server_key } => {
                println!("Parsing Adobe ADEPT signIn XML...");
                println!("  XML file: {}", xml.display());

                // Parse the signIn XML
                let signin_data = parse_signin_xml(&xml)?;
                println!("  ✓ Parsed signIn XML");

                // Display basic info
                println!("\nSignIn Information:");
                println!("  Method: {}", signin_data.method);
                println!(
                    "  SignIn data (encrypted): {} bytes",
                    signin_data.sign_in_data_encrypted.len()
                );
                println!("    Note: Encrypted with Adobe activation server's public key");
                println!(
                    "  Public auth key: {} bits",
                    signin_data.public_auth_key.size() * 8
                );
                println!(
                    "  Encrypted private auth key: {} bytes",
                    signin_data.encrypted_private_auth_key.len()
                );
                println!("    Note: Encrypted with device key");
                println!(
                    "  Public license key: {} bits",
                    signin_data.public_license_key.size() * 8
                );
                println!(
                    "  Encrypted private license key: {} bytes",
                    signin_data.encrypted_private_license_key.len()
                );
                println!("    Note: Encrypted with device key");

                // If server key is provided, try to decrypt signInData
                if let Some(server_key_path) = server_key {
                    println!(
                        "\n  Loading Adobe server key from {}...",
                        server_key_path.display()
                    );
                    let server_key_bytes = fs::read(&server_key_path).with_context(|| {
                        format!("Failed to read server key file: {:?}", server_key_path)
                    })?;
                    let server_key = rsa::RsaPrivateKey::from_pkcs1_der(&server_key_bytes)
                        .or_else(|_| {
                            rsa::pkcs8::DecodePrivateKey::from_pkcs8_der(&server_key_bytes)
                        })
                        .context("Failed to parse server key")?;
                    println!("  ✓ Loaded server key ({} bits)", server_key.size() * 8);
                }
                let device_key = adeptkeys()?.device_key;
                let iv: Vec<_> = signin_data.encrypted_private_auth_key[..16].into();
                let cipher: Vec<_> = signin_data.encrypted_private_auth_key[16..].into();
                let auth_key = decrypt_private_key_with_iv(&cipher, &device_key, &iv)?;
                println!("RSA Auth key: {:?}", auth_key);

                let license_key_iv: Vec<_> = signin_data.encrypted_private_license_key[..16].into();
                let license_key_cipher: Vec<_> =
                    signin_data.encrypted_private_license_key[16..].into();
                let license_key =
                    decrypt_private_key_with_iv(&license_key_cipher, &device_key, &license_key_iv)?;
                println!("RSA License key: {:?}", license_key);

                Ok(())
            }
            DebugCommands::ParseSignInResponse { xml } => {
                println!("Parsing signIn response from: {}", xml.display());
                let content = std::fs::read_to_string(&xml)?;
                let response = parse_signin_response(&content)?;

                println!("\n=== SignIn Response ===");
                println!("User: {}", response.user);
                println!(
                    "Username: {} (method: {})",
                    response.username, response.username_method
                );
                println!("PKCS12 size: {} bytes", response.pkcs12.len());
                println!(
                    "Encrypted private license key size: {} bytes",
                    response.encrypted_private_license_key.len()
                );
                println!(
                    "License certificate size: {} bytes",
                    response.license_certificate.len()
                );

                let device_key = adeptkeys()?.device_key;
                let password = base64::prelude::BASE64_STANDARD.encode(&device_key);
                println!("Derived PKCS12 password from device key: {}", password);

                let decrypted_key =
                    p12_keystore::KeyStore::from_pkcs12(&response.pkcs12, &password)?;
                decrypted_key
                    .entries()
                    .for_each(|(alias, entry)| println!("pkcs#12 {} {:?}", alias, entry));

                // Parse X.509 certificate
                println!("\n=== License Certificate ===");
                match x509_parser::parse_x509_certificate(&response.license_certificate) {
                    Ok((_, cert)) => {
                        println!("Certificate parsed successfully");
                        println!("Subject: {}", cert.subject());
                        println!("Issuer: {}", cert.issuer());
                        println!("Serial: {}", cert.serial);
                        println!("Valid from: {}", cert.validity().not_before);
                        println!("Valid to: {}", cert.validity().not_after);
                        println!(
                            "Signature algorithm: {}",
                            cert.signature_algorithm.algorithm
                        );
                    }
                    Err(e) => {
                        println!("Failed to parse certificate: {:?}", e);
                    }
                }

                Ok(())
            }
        },
    }
}
