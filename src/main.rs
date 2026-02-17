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
                    use rmpub::extract_content_key;

                    let in_path = PathBuf::from(&args[1]);
                    let item_path = &args[2];
                    let encrypted_epub_key = extract_content_key(&in_path)?;
                    println!("Encrypted EPUB key: {}", encrypted_epub_key);
                    let decrypted_epub_key =
                        rmpub::decrypt_content_key(&encrypted_epub_key, &key.key)?;
                    println!("Decrypted EPUB key: {}", hex::encode(&decrypted_epub_key));

                    let cover_image =
                        rmpub::decrypt_epub_file(&in_path, &item_path, &decrypted_epub_key)?;

                    if cover_image[0] != 0xff || cover_image[1] != 0xd8 {
                        eprintln!(
                            "Warning: Decrypted cover image does not start with JPEG magic bytes"
                        );
                    }

                    // Write the decrypted image to a file
                    fs::write("cover_image.jpg", &cover_image)?;
                    println!(
                        "Wrote decrypted cover image to cover_image.jpg ({} bytes)",
                        cover_image.len()
                    );
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
