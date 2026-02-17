use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use log::debug;
use rmpub::{decrypt_content_key, decrypt_epub, decrypt_epub_file, extract_content_key};
use std::fs;
use std::path::PathBuf;

#[cfg(windows)]
use rmpub::adeptkeys;
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
    }
}
