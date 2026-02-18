use anyhow::Result;
use log::debug;
use std::{fs, path::PathBuf};

use crate::AdeptKey;

pub fn load_keys(key_path: Option<PathBuf>) -> Result<AdeptKey> {
    if let Some(key_path) = key_path {
        debug!("Using keys from: {}", key_path.display());
        let keys_bytes = fs::read(key_path)?;
        let keys: AdeptKey = serde_json::from_slice(&keys_bytes)?;
        Ok(keys)
    } else {
        #[cfg(windows)]
        {
            use crate::adeptkeys;

            println!("  Extracting key from registry...");
            let k = adeptkeys()?;
            Ok(k)
        }

        #[cfg(not(windows))]
        {
            eprintln!("Error: Key extraction from registry is only available on Windows.");
            eprintln!("Please use --key parameter with a pre-extracted key file.");
            std::process::exit(1);
        }
    }
}
