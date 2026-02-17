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

        match adeptkeys() {
            Ok(keys) => {
                println!("\nSuccessfully retrieved {} key(s)\n", keys.len());

                // Save keys to files
                let output_dir = PathBuf::from(".");

                for (index, key) in keys.iter().enumerate() {
                    let filename = format!("adobekey{}_uuid_{}.der", index + 1, key.name);
                    let filepath = output_dir.join(&filename);

                    fs::write(&filepath, &key.key_data)?;
                    println!("Saved key to: {}", filepath.display());
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
