use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use log::debug;
use rmpub::{
    decrypt_content_key, decrypt_epub, decrypt_epub_file, extract_content_key,
    generate_fulfill_request, parse_acsm, sign_fulfill_request,
};
use std::fs;
use std::path::PathBuf;

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
                let der_bytes = key.key.to_pkcs1_der()?;
                fs::write(&output, der_bytes.as_bytes())?;

                println!(
                    "✓ Successfully extracted device key to: {}",
                    output.display()
                );
                println!("  Key name: {}", key.name);
                println!("  Key size: {} bits", key.key.size() * 8);
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
                    key.key
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
                    key.key
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
        } => {
            println!("Fetching EPUB from ACSM file...");
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

                // Generate the fulfill request
                println!("  Generating fulfillment request...");
                let fulfill_xml =
                    generate_fulfill_request(&acsm_info, &user_val, &device_val, &fingerprint_val);
                println!("  ✓ Generated fulfill request");

                // Print the fulfillment request
                println!("\n--- Fulfillment Request ---");
                println!("{}", fulfill_xml);
                println!("--- End Fulfillment Request ---\n");

                println!("  ACSM: {:?}", acsm_info);

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
                                key.key
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
        },
    }
}
