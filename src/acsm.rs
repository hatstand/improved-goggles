use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};

/// Information extracted from an ACSM file
#[derive(Debug)]
pub struct AcsmInfo {
    pub operator_url: String,
    pub resource_id: String,
    pub transaction_id: String,
    pub expiration: jiff::Timestamp,
    pub hmac: String,
}

/// Parses an ACSM file and extracts download information
///
/// # Arguments
/// * `acsm_path` - Path to the ACSM file
///
/// # Returns
/// Parsed ACSM information including download URL
pub fn parse_acsm<P: AsRef<Path>>(acsm_path: P) -> Result<AcsmInfo> {
    let content = std::fs::read_to_string(acsm_path.as_ref())
        .with_context(|| format!("Failed to read ACSM file: {:?}", acsm_path.as_ref()))?;

    let doc = roxmltree::Document::parse(&content).context("Failed to parse ACSM XML")?;

    let operator_url = doc
        .descendants()
        .find(|n| n.has_tag_name("operatorURL"))
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| anyhow!("Operator URL not found in ACSM file"))?;

    let resource_id = doc
        .descendants()
        .find(|n| n.has_tag_name("resourceItemInfo"))
        .and_then(|n| {
            n.descendants()
                .find(|n| n.has_tag_name("resource"))
                .and_then(|n| n.text())
                .map(|s| s.trim().to_string())
        })
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("resource not found in ACSM file"))?;

    let transaction_id = doc
        .descendants()
        .find(|n| n.has_tag_name("transaction"))
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| anyhow!("transactionId not found in ACSM file"))?;

    let expiration_str = doc
        .descendants()
        .find(|n| n.has_tag_name("expiration"))
        .and_then(|n| n.text())
        .ok_or_else(|| anyhow!("Expiration not found in ACSM file"))?;
    let expiration = jiff::Timestamp::from_str(expiration_str.trim())?;

    let hmac = doc
        .descendants()
        .find(|n| n.has_tag_name("hmac"))
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| anyhow!("HMAC not found in ACSM file"))?;

    Ok(AcsmInfo {
        operator_url,
        resource_id,
        transaction_id,
        expiration,
        hmac,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_acsm() {
        // Test parsing the URLLink.acsm test file
        let acsm_path = "src/testdata/URLLink.acsm";
        let result = parse_acsm(acsm_path);

        assert!(result.is_ok(), "Failed to parse ACSM: {:?}", result.err());

        let acsm_info = result.unwrap();

        // Verify the parsed fields
        assert_eq!(
            acsm_info.operator_url,
            "http://acs.ebookscorporation.com/fulfillment"
        );
        assert_eq!(
            acsm_info.resource_id,
            "urn:uuid:e0000000-0000-0000-0000-000123456789"
        );
        assert_eq!(acsm_info.transaction_id, "ABC-123456789");
        assert_eq!(acsm_info.hmac, "placeholder_base64_mac");

        // Verify expiration timestamp is parsed correctly
        // Expected: 2026-02-17T21:00:59+00:00
        let expiration_str = acsm_info.expiration.to_string();
        assert!(expiration_str.contains("2026-02-17T21:00:59"));
    }
}
