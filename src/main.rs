#[cfg(windows)]
use rmpub::adeptkeys;
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        println!("Adobe Adept Key Retrieval v0.1.0");
        println!("Rust implementation based on DeDRM_tools\n");

        let args = std::env::args().collect::<Vec<String>>();

        match adeptkeys() {
            Ok(key) => {
                println!("Successfully retrieved key");

                if args.len() > 1 {
                    use rmpub::extract_epub_key;

                    let in_path = PathBuf::from(&args[1]);
                    let encrypted_epub_key = extract_epub_key(in_path)?;
                    println!("Encrypted EPUB key: {}", encrypted_epub_key);
                }

                Ok(())
            }
            Err(e) => {
                eprintln!("Error retrieving Adobe Adept keys: {}", e);
                Err(e.into())
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
