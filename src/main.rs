#[cfg(windows)]
use clap::{Parser, Subcommand};
#[cfg(windows)]
use log::debug;
#[cfg(windows)]
use rmpub::{adeptkeys, decrypt_content_key, decrypt_epub_file, extract_content_key};
#[cfg(windows)]
use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
#[derive(Parser)]
#[command(name = "rmpub")]
#[command(about = "Adobe ADEPT DRM key extraction and EPUB decryption tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[cfg(windows)]
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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        let cli = Cli::parse();

        match cli.command {
            Commands::ExtractKey { output } => {
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
                        .ok_or("Invalid file path")?
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
                    println!("  Extracting key from registry...");
                    let key = adeptkeys()?;
                    println!("  Using key: {}", key.name);
                    key.key
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
        }
    }

    #[cfg(not(windows))]
    {
        eprintln!("Error: This program is Windows-only.");
        eprintln!("It requires access to the Windows Registry to retrieve Adobe Adept keys.");
        std::process::exit(1);
    }
}
