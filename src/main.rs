use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use log::debug;
use rmpub::{
    decrypt_content_key, decrypt_epub, decrypt_epub_file, decrypt_private_key_with_iv,
    extract_content_key, fetch_epub, load_keys, parse_signin_response, parse_signin_xml,
    verify_fulfill_request, AdeptKey,
};
use std::fs;
use std::path::PathBuf;

use base64::Engine;
use p12::PFX;
use rsa::pkcs1::DecodeRsaPrivateKey;

#[cfg(windows)]
use rmpub::{adept_device, adept_fingerprint, adept_user, adeptkeys};
use rsa::traits::PublicKeyParts;

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
    ExtractKeys {
        /// Output file path for the private key (DER format)
        #[arg(short, long, default_value = "adept_keys.json")]
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

        /// Encrypted key to use for decryption, in Base64 format. If not provided, will attempt to extract from the EPUB file.
        /// This is usually returned during the fulfilment process
        #[arg(short, long)]
        encrypted_key: Option<String>,
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

        /// Encrypted key to use for decryption, in Base64 format. If not provided, will attempt to extract from the EPUB file.
        /// This is usually returned during the fulfilment process
        #[arg(short, long)]
        encrypted_key: Option<String>,
    },
    /// Fetch an encrypted EPUB from an operator based on an ACSM file
    FetchEpub {
        /// Path to the ACSM file
        acsm: PathBuf,

        /// Output file path for the downloaded EPUB
        #[arg(short, long)]
        output: PathBuf,

        /// Dry run - show what would be done without making requests or writing files
        #[arg(short = 'n', long)]
        dry_run: bool,

        /// Path to a pre-extracted device key file (DER format). If not provided, will extract from registry.
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    /// Authenticate with an operator using device keys.
    Auth {
        /// URL of the operator's authentication endpoint (e.g., "http://acs.ebookscorporation.com/fulfillment/Auth") - used in the signIn request XML
        /// Typically, the `operatorURL` from an ACSM file + `/Auth`.
        operator_url: String,

        /// Path to a pre-extracted device key file (DER format). If not provided, will extract from registry.
        #[arg(short, long)]
        key: Option<PathBuf>,
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

        /// Path to a pre-extracted device key file (DER format). If not provided, will extract from registry.
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    /// Parse an Adobe ADEPT signIn response (credentials) file
    ParseSignInResponse {
        /// Path to the signIn response XML file
        xml: PathBuf,

        /// Path to a pre-extracted device key file (DER format). If not provided, will extract from registry.
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    GenerateAuthRequest {
        /// Path to a pre-extracted device key file (DER format). If not provided, will extract from registry.
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
}

fn extract_key(output: PathBuf) -> Result<()> {
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

        let j = serde_json::to_string_pretty(&key).context("Failed to serialize key to JSON")?;
        fs::write(&output, j).context("Failed to write key to output file")?;

        println!(
            "✓ Successfully extracted device key to: {}",
            output.display()
        );
        Ok(())
    }
}

fn decrypt_file(
    epub: PathBuf,
    file: &str,
    output: Option<PathBuf>,
    key: Option<PathBuf>,
    encrypted_key: Option<String>,
) -> Result<()> {
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
    let keys: AdeptKey = load_keys(key)?;

    let encrypted_content_key = match encrypted_key {
        Some(enc_key) => {
            println!("  Using provided encrypted key for decryption");
            debug!("Encrypted key (Base64): {}", enc_key);
            enc_key
        }
        None => {
            // Extract the encrypted content key from the EPUB
            println!("  Extracting content key from EPUB...");
            extract_content_key(&epub)?
        }
    };

    // Decrypt the content key using RSA
    println!("  Decrypting content key...");
    let content_key = decrypt_content_key(&encrypted_content_key, &keys.private_license_key)?;
    debug!("Content key: {}", hex::encode(&content_key));

    // Decrypt the specific file
    println!("  Decrypting file content...");
    let decrypted_content = decrypt_epub_file(&epub, file, &content_key)?;

    // Write to output
    fs::write(&output_path, &decrypted_content)?;

    println!(
        "✓ Successfully decrypted file ({} bytes)",
        decrypted_content.len()
    );
    println!("  Saved to: {}", output_path.display());

    Ok(())
}

fn decrypt_book(
    input: PathBuf,
    output: PathBuf,
    key: Option<PathBuf>,
    encrypted_key: Option<String>,
) -> Result<()> {
    println!("Decrypting entire EPUB...");
    println!("  Input: {}", input.display());
    println!("  Output: {}", output.display());

    let keys = load_keys(key)?;

    // Decrypt the entire EPUB
    println!("  Decrypting files...");
    let decrypted_count = decrypt_epub(&input, &output, &keys.private_license_key, encrypted_key)?;

    println!("✓ Successfully decrypted EPUB");
    println!("  Decrypted {} files", decrypted_count);
    println!("  Output: {}", output.display());

    Ok(())
}

fn auth(operator_url: String, key: Option<PathBuf>) -> Result<()> {
    println!("Generating auth request for operator: {}", operator_url);

    let keys = load_keys(key)?;

    // Generate the auth request XML
    let auth_request_xml = rmpub::create_auth_request(&keys)?;

    println!("\n--- auth Request XML ---");
    println!("{}", auth_request_xml);
    println!("--- End auth Request XML ---\n");

    let client = reqwest::blocking::Client::new();
    println!("Sending auth request to operator...");

    let response = client
        .post(&operator_url)
        .header("Content-Type", "application/vnd.adobe.adept+xml")
        .header("User-Agent", "book2png")
        .header("Accept", "*/*")
        .body(auth_request_xml.clone())
        .send()
        .with_context(|| format!("Failed to send auth request to {}", operator_url))?;
    let status = response.status();
    println!("Received response with status: {}", status);

    let response_text = response
        .text()
        .context("Failed to read auth response body")?;
    println!("Response body:\n{}", response_text);

    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::ExtractKeys { output } => extract_key(output),
        Commands::DecryptFile {
            epub,
            file,
            output,
            key,
            encrypted_key,
        } => decrypt_file(epub, &file, output, key, encrypted_key),
        Commands::DecryptEpub {
            input,
            output,
            key,
            encrypted_key,
        } => decrypt_book(input, output, key, encrypted_key),
        Commands::FetchEpub {
            acsm,
            output,
            dry_run,
            key,
        } => fetch_epub(acsm, output, dry_run, key),
        Commands::Auth { operator_url, key } => auth(operator_url, key),
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
                            key.private_auth_key.clone()
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
            DebugCommands::ParseSignIn {
                xml,
                server_key,
                key,
            } => {
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
                let device_key = load_keys(key)?.device_key;
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
            DebugCommands::ParseSignInResponse { xml, key } => {
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

                let device_key = load_keys(key)?.device_key;
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
            DebugCommands::GenerateAuthRequest { key } => {
                println!("Generating auth request...");

                let keys = load_keys(key)?;

                // Generate the auth request XML
                let auth_request_xml = rmpub::create_auth_request(&keys)?;

                println!("\n--- signIn Request XML ---");
                println!("{}", auth_request_xml);
                println!("--- End signIn Request XML ---\n");

                Ok(())
            }
        },
    }
}
