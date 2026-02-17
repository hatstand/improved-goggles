use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha1::{Digest, Sha1};

/// Metadata extracted from ACSM file (Dublin Core elements)
#[derive(Debug, Clone)]
pub struct AcsmMetadata {
    pub title: Option<String>,
    pub creator: Option<String>,
    pub publisher: Option<String>,
    pub identifier: Option<String>,
    pub format: Option<String>,
    pub language: Option<String>,
}

/// License token permissions
#[derive(Debug, Clone)]
pub struct AcsmPermissions {
    pub display: bool,
    pub play: bool,
}

/// License token information
#[derive(Debug, Clone)]
pub struct AcsmLicenseToken {
    pub resource: String,
    pub permissions: AcsmPermissions,
}

/// Information extracted from an ACSM file
#[derive(Debug)]
pub struct AcsmInfo {
    pub distributor: String,
    pub operator_url: String,
    pub resource_id: String,
    pub transaction_id: String,
    pub purchase: jiff::Timestamp,
    pub expiration: jiff::Timestamp,
    pub hmac: String,
    pub metadata: AcsmMetadata,
    pub license_token: AcsmLicenseToken,
    /// Raw fulfillmentToken XML (preserves HMAC)
    pub fulfillment_token_xml: String,
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

    let distributor = doc
        .descendants()
        .find(|n| n.has_tag_name("distributor"))
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| anyhow!("Distributor not found in ACSM file"))?;

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

    let purchase_str = doc
        .descendants()
        .find(|n| n.has_tag_name("purchase"))
        .and_then(|n| n.text())
        .ok_or_else(|| anyhow!("Purchase not found in ACSM file"))?;
    let purchase = jiff::Timestamp::from_str(purchase_str.trim())?;

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

    // Extract metadata if present
    let metadata = doc
        .descendants()
        .find(|n| n.has_tag_name("metadata"))
        .map_or_else(
            || AcsmMetadata {
                title: None,
                creator: None,
                publisher: None,
                identifier: None,
                format: None,
                language: None,
            },
            |metadata_node| {
                let title = metadata_node
                    .descendants()
                    .find(|n| n.tag_name().name() == "title")
                    .and_then(|n| n.text())
                    .map(|s| s.trim().to_string());

                let creator = metadata_node
                    .descendants()
                    .find(|n| n.tag_name().name() == "creator")
                    .and_then(|n| n.text())
                    .map(|s| s.trim().to_string());

                let publisher = metadata_node
                    .descendants()
                    .find(|n| n.tag_name().name() == "publisher")
                    .and_then(|n| n.text())
                    .map(|s| s.trim().to_string());

                let identifier = metadata_node
                    .descendants()
                    .find(|n| n.tag_name().name() == "identifier")
                    .and_then(|n| n.text())
                    .map(|s| s.trim().to_string());

                let format = metadata_node
                    .descendants()
                    .find(|n| n.tag_name().name() == "format")
                    .and_then(|n| n.text())
                    .map(|s| s.trim().to_string());

                let language = metadata_node
                    .descendants()
                    .find(|n| n.tag_name().name() == "language")
                    .and_then(|n| n.text())
                    .map(|s| s.trim().to_string());

                AcsmMetadata {
                    title,
                    creator,
                    publisher,
                    identifier,
                    format,
                    language,
                }
            },
        );

    // Extract license token
    let license_token = doc
        .descendants()
        .find(|n| n.has_tag_name("licenseToken"))
        .map_or_else(
            || AcsmLicenseToken {
                resource: String::new(),
                permissions: AcsmPermissions {
                    display: false,
                    play: false,
                },
            },
            |license_node| {
                let resource = license_node
                    .descendants()
                    .find(|n| n.has_tag_name("resource"))
                    .and_then(|n| n.text())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();

                let permissions_node = license_node
                    .descendants()
                    .find(|n| n.has_tag_name("permissions"));

                let permissions = if let Some(perms) = permissions_node {
                    AcsmPermissions {
                        display: perms.descendants().any(|n| n.has_tag_name("display")),
                        play: perms.descendants().any(|n| n.has_tag_name("play")),
                    }
                } else {
                    AcsmPermissions {
                        display: false,
                        play: false,
                    }
                };

                AcsmLicenseToken {
                    resource,
                    permissions,
                }
            },
        );

    // Extract raw fulfillmentToken XML to preserve HMAC
    // The entire ACSM content is the fulfillmentToken element
    let fulfillment_token_xml = content.trim().to_string();

    Ok(AcsmInfo {
        distributor,
        operator_url,
        resource_id,
        transaction_id,
        purchase,
        expiration,
        hmac,
        metadata,
        license_token,
        fulfillment_token_xml,
    })
}

/// Generates an `<adept:targetDevice>` XML element for Adobe ADEPT fulfillment requests
///
/// # Arguments
/// * `user` - User GUID (e.g., "urn:uuid:54f2e5c9-0071-46e4-8452-df4f7fe0cc3f")
/// * `device` - Device GUID (e.g., "urn:uuid:a69fd2ee-8b78-4410-a1a1-8c782e379fb7")
/// * `fingerprint` - Device fingerprint (base64-encoded)
///
/// # Returns
/// XML string representing the targetDevice element
pub fn generate_target_device(user: &str, device: &str, fingerprint: &str) -> String {
    let mut writer = Writer::new_with_indent(Vec::new(), b' ', 4);

    // Helper function to write a simple element with text content
    let write_element = |writer: &mut Writer<Vec<u8>>, name: &str, text: &str| {
        writer
            .write_event(Event::Start(BytesStart::new(name)))
            .unwrap();
        writer
            .write_event(Event::Text(BytesText::new(text)))
            .unwrap();
        writer.write_event(Event::End(BytesEnd::new(name))).unwrap();
    };

    // Start targetDevice
    writer
        .write_event(Event::Start(BytesStart::new("adept:targetDevice")))
        .unwrap();

    // Write child elements
    write_element(
        &mut writer,
        "adept:softwareVersion",
        "12.5.4.HOBBES_VERSION_BUILD_NUMBER_X",
    );
    write_element(&mut writer, "adept:clientOS", "Windows 8");
    write_element(&mut writer, "adept:clientLocale", "en");
    write_element(
        &mut writer,
        "adept:clientVersion",
        "com.adobe.adobedigitaleditions.exe v4.5.12.112",
    );
    write_element(&mut writer, "adept:deviceType", "standalone");
    write_element(&mut writer, "adept:productName", "ADOBE Digitial Editions");
    write_element(&mut writer, "adept:fingerprint", fingerprint);

    // Start activationToken
    writer
        .write_event(Event::Start(BytesStart::new("adept:activationToken")))
        .unwrap();

    write_element(&mut writer, "adept:user", user);
    write_element(&mut writer, "adept:device", device);

    // End activationToken
    writer
        .write_event(Event::End(BytesEnd::new("adept:activationToken")))
        .unwrap();

    // End targetDevice
    writer
        .write_event(Event::End(BytesEnd::new("adept:targetDevice")))
        .unwrap();

    String::from_utf8(writer.into_inner()).unwrap()
}

/// Generates a fulfill request XML for Adobe ADEPT fulfillment
///
/// # Arguments
/// * `acsm_info` - Parsed ACSM information (includes raw fulfillmentToken XML)
/// * `user` - User GUID (e.g., "urn:uuid:54f2e5c9-0071-46e4-8452-df4f7fe0cc3f")
/// * `device` - Device GUID (e.g., "urn:uuid:a69fd2ee-8b78-4410-a1a1-8c782e379fb7")
/// * `fingerprint` - Device fingerprint (base64-encoded)
///
/// # Returns
/// XML string representing the fulfill request
pub fn generate_fulfill_request(
    acsm_info: &AcsmInfo,
    user: &str,
    device: &str,
    fingerprint: &str,
) -> String {
    let mut result = String::from("<?xml version=\"1.0\"?>\n");
    result.push_str("<adept:fulfill xmlns:adept=\"http://ns.adobe.com/adept\">\n");

    // Add user, device, deviceType
    result.push_str(&format!("  <adept:user>{}</adept:user>\n", user));
    result.push_str(&format!("  <adept:device>{}</adept:device>\n", device));
    result.push_str("  <adept:deviceType>standalone</adept:deviceType>\n");

    // Add the raw fulfillmentToken XML with proper indentation
    // The fulfillmentToken XML should be indented by 2 spaces
    let indented_token = acsm_info
        .fulfillment_token_xml
        .lines()
        .map(|line| {
            if line.trim().is_empty() {
                String::new()
            } else {
                format!("  {}", line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    result.push_str(&indented_token);
    result.push('\n');

    // Add targetDevice
    let target_device = generate_target_device(user, device, fingerprint);
    let indented_target = target_device
        .lines()
        .map(|line| {
            if line.trim().is_empty() {
                String::new()
            } else {
                format!("  {}", line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    result.push_str(&indented_target);
    result.push('\n');

    result.push_str("</adept:fulfill>\n");

    result
}

/// Generates a minified fulfill request XML for HTTP transmission
///
/// This version removes whitespace between elements except for the fulfillmentToken
/// content which preserves its original formatting to maintain the HMAC.
///
/// # Arguments
/// * `acsm_info` - Parsed ACSM information (includes raw fulfillmentToken XML)
/// * `user` - User GUID (e.g., "urn:uuid:54f2e5c9-0071-46e4-8452-df4f7fe0cc3f")
/// * `device` - Device GUID (e.g., "urn:uuid:a69fd2ee-8b78-4410-a1a1-8c782e379fb7")
/// * `fingerprint` - Device fingerprint (base64-encoded)
///
/// # Returns
/// Minified XML string for HTTP POST
pub fn generate_fulfill_request_minified(
    acsm_info: &AcsmInfo,
    user: &str,
    device: &str,
    fingerprint: &str,
) -> String {
    let mut result = String::from("<?xml version=\"1.0\"?>");
    result.push_str("<adept:fulfill xmlns:adept=\"http://ns.adobe.com/adept\">");

    // Add user, device, deviceType (minified)
    result.push_str(&format!("<adept:user>{}</adept:user>", user));
    result.push_str(&format!("<adept:device>{}</adept:device>", device));
    result.push_str("<adept:deviceType>standalone</adept:deviceType>");

    // Add the raw fulfillmentToken XML (preserve original formatting)
    result.push_str(&acsm_info.fulfillment_token_xml);

    // Add targetDevice (minified)
    let target_device = generate_target_device(user, device, fingerprint);
    // Remove all newlines and extra spaces from targetDevice
    let minified_target = target_device
        .lines()
        .map(|line| line.trim())
        .collect::<Vec<_>>()
        .join("");
    result.push_str(&minified_target);

    result.push_str("</adept:fulfill>");

    result
}

// ASN.1-like tags used by Adobe's XML hashing algorithm
const ASN_NS_TAG: u8 = 1; // BEGIN_ELEMENT
const ASN_CHILD: u8 = 2; // END_ATTRIBUTES
const ASN_END_TAG: u8 = 3; // END_ELEMENT
const ASN_TEXT: u8 = 4; // TEXT_NODE
const ASN_ATTRIBUTE: u8 = 5; // ATTRIBUTE

/// Hash a string with length prefix (Adobe's format)
fn hash_append_string(hasher: &mut Sha1, s: &str) {
    let bytes = s.as_bytes();
    let length = bytes.len();
    let len_upper = (length / 256) as u8;
    let len_lower = (length & 0xFF) as u8;

    hasher.update(&[len_upper, len_lower]);
    hasher.update(bytes);
}

/// Hash a single tag byte
fn hash_append_tag(hasher: &mut Sha1, tag: u8) {
    hasher.update(&[tag]);
}

/// Recursively hash an XML node using Adobe's algorithm
fn hash_node_recursive(node: roxmltree::Node, hasher: &mut Sha1) {
    if !node.is_element() {
        return;
    }

    if node.tag_name().name() == "signature" || node.tag_name().name() == "hmac" {
        // Skip signature element and its children
        return;
    }

    // Hash namespace and tag name
    hash_append_tag(hasher, ASN_NS_TAG);

    let namespace = node.tag_name().namespace().unwrap_or("");
    hash_append_string(hasher, namespace);

    let local_name = node.tag_name().name();
    hash_append_string(hasher, local_name);

    // Hash attributes (must be sorted)
    let mut attributes: Vec<_> = node.attributes().collect();
    attributes.sort_by_key(|attr| (attr.namespace().unwrap_or(""), attr.name()));

    for attr in attributes {
        hash_append_tag(hasher, ASN_ATTRIBUTE);
        hash_append_string(hasher, attr.namespace().unwrap_or(""));
        hash_append_string(hasher, attr.name());
        hash_append_string(hasher, attr.value());
    }

    // End of attributes
    hash_append_tag(hasher, ASN_CHILD);

    // Hash text content if present
    if let Some(text) = node.text() {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            // Split into 32KB chunks as per Adobe's implementation
            let mut offset = 0;
            while offset < trimmed.len() {
                let chunk_size = std::cmp::min(0x7fff, trimmed.len() - offset);
                hash_append_tag(hasher, ASN_TEXT);
                hash_append_string(hasher, &trimmed[offset..offset + chunk_size]);
                offset += chunk_size;
            }
        }
    }

    // Recursively hash child elements
    for child in node.children() {
        if child.is_element() {
            hash_node_recursive(child, hasher);
        }
    }

    // End tag
    hash_append_tag(hasher, ASN_END_TAG);
}

/// Hash an XML document using Adobe's custom algorithm
fn hash_xml_document(xml: &str) -> Result<Vec<u8>> {
    let doc = roxmltree::Document::parse(xml).context("Failed to parse XML for hashing")?;

    let mut hasher = Sha1::new();
    hash_node_recursive(doc.root_element(), &mut hasher);

    Ok(hasher.finalize().to_vec())
}

/// Sign fulfill request XML with device key
///
/// # Arguments
/// * `xml` - The fulfill request XML (without signature element)
/// * `private_key` - RSA private key
///
/// # Returns
/// Base64-encoded RSA signature
pub fn sign_fulfill_request(xml: &str, private_key: &RsaPrivateKey) -> Result<String> {
    // Hash the XML using Adobe's algorithm
    let hash = hash_xml_document(xml)?;

    // Sign the hash using textbook RSA (PKCS#1 v1.5)
    let signature = private_key
        .sign(Pkcs1v15Sign::new_unprefixed(), &hash)
        .context("Failed to sign hash")?;

    // Return base64-encoded signature
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::DecodeRsaPrivateKey;

    #[test]
    fn test_parse_acsm() {
        // Test parsing the URLLink.acsm test file
        let acsm_path = "src/testdata/URLLink.acsm";
        let result = parse_acsm(acsm_path);

        assert!(result.is_ok(), "Failed to parse ACSM: {:?}", result.err());

        let acsm_info = result.unwrap();

        // Verify the parsed fields
        assert_eq!(
            acsm_info.distributor,
            "urn:uuid:d051ad0d-03ed-4b63-b257-5bfe2e304a80"
        );
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

        // Verify purchase timestamp is parsed correctly
        // Expected: 2026-02-17T15:00:59+00:00
        let purchase_str = acsm_info.purchase.to_string();
        assert!(purchase_str.contains("2026-02-17T15:00:59"));

        // Verify expiration timestamp is parsed correctly
        // Expected: 2026-02-17T21:00:59+00:00
        let expiration_str = acsm_info.expiration.to_string();
        assert!(expiration_str.contains("2026-02-17T21:00:59"));

        // Verify metadata is extracted
        assert_eq!(
            acsm_info.metadata.title,
            Some("Against All Gods".to_string())
        );
        assert_eq!(
            acsm_info.metadata.creator,
            Some("Cameron, Miles".to_string())
        );
        assert_eq!(acsm_info.metadata.publisher, Some("Orion".to_string()));
        assert_eq!(
            acsm_info.metadata.identifier,
            Some("URN:ISBN:9781473232532".to_string())
        );
        assert_eq!(
            acsm_info.metadata.format,
            Some("application/epub+zip".to_string())
        );
        assert_eq!(acsm_info.metadata.language, Some("en".to_string()));

        // Verify license token is extracted
        assert_eq!(
            acsm_info.license_token.resource,
            "urn:uuid:e0000000-0000-0000-0000-000123456789"
        );
        assert!(acsm_info.license_token.permissions.display);
        assert!(acsm_info.license_token.permissions.play);
    }

    #[test]
    fn test_generate_target_device() {
        let user = "urn:uuid:e995bfd8-46ec-4740-ba98-c404d0b00c87";
        let device = "urn:uuid:b6b5c282-1f1c-467c-b0f3-3bf2124ddc3a";
        let fingerprint = "placeholder_fingerprint_base64";

        let xml = generate_target_device(user, device, fingerprint);

        // Load expected XML (excluding the signature element)
        let expected = std::fs::read_to_string("src/testdata/target_device.xml")
            .expect("Failed to read target_device.xml");

        let expected = expected.lines().collect::<Vec<_>>().join("\n");

        assert_eq!(xml.trim(), expected.trim());
    }

    #[test]
    fn test_generate_fulfill_request() {
        let user = "urn:uuid:e995bfd8-46ec-4740-ba98-c404d0b00c87";
        let device = "urn:uuid:b6b5c282-1f1c-467c-b0f3-3bf2124ddc3a";
        let fingerprint = "placeholder_fingerprint_base64";

        // Parse the test ACSM file
        let acsm_info =
            parse_acsm("src/testdata/URLLink.acsm").expect("Failed to parse test ACSM file");

        let xml = generate_fulfill_request(&acsm_info, user, device, fingerprint);

        // Parse the generated XML to verify structure
        let doc = roxmltree::Document::parse(&xml).expect("Generated XML should be valid");

        // Verify root element
        assert_eq!(doc.root_element().tag_name().name(), "fulfill");

        // Verify required elements are present
        assert!(doc.descendants().any(|n| n.has_tag_name("user")));
        assert!(doc.descendants().any(|n| n.has_tag_name("device")));
        assert!(doc.descendants().any(|n| n.has_tag_name("deviceType")));
        assert!(doc
            .descendants()
            .any(|n| n.has_tag_name("fulfillmentToken")));
        assert!(doc.descendants().any(|n| n.has_tag_name("targetDevice")));
        assert!(doc.descendants().any(|n| n.has_tag_name("hmac")));
        assert!(doc.descendants().any(|n| n.has_tag_name("fingerprint")));

        // Verify no signature element (we don't generate that)
        assert!(!doc.descendants().any(|n| n.has_tag_name("signature")));

        // Verify the passed values appear in the XML
        assert!(xml.contains(user));
        assert!(xml.contains(device));
        assert!(xml.contains(fingerprint));

        // Verify the HMAC from ACSM is preserved
        assert!(xml.contains(&acsm_info.hmac));
    }

    #[test]
    fn test_sign_fulfill_request() {
        let user = "urn:uuid:e995bfd8-46ec-4740-ba98-c404d0b00c87";
        let device = "urn:uuid:b6b5c282-1f1c-467c-b0f3-3bf2124ddc3a";
        let fingerprint = "placeholder_fingerprint_base64";

        // Parse the test ACSM file
        let acsm_info =
            parse_acsm("src/testdata/URLLink.acsm").expect("Failed to parse test ACSM file");

        let xml = generate_fulfill_request(&acsm_info, user, device, fingerprint);

        // Load device key
        let device_key_bytes =
            std::fs::read("device_key.der").expect("Failed to read device_key.der");
        let private_key =
            RsaPrivateKey::from_pkcs1_der(&device_key_bytes).expect("Failed to parse device key");

        // Sign the request
        let signature = sign_fulfill_request(&xml, &private_key);

        assert!(signature.is_ok(), "Failed to sign: {:?}", signature.err());

        let signature = signature.unwrap();

        // Verify signature is base64 encoded
        assert!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &signature).is_ok()
        );

        // Verify signature is not empty
        assert!(!signature.is_empty());
        assert!(signature.len() > 100); // RSA signature should be fairly long
    }

    #[test]
    fn test_hash_fulfill_request() {
        // Load the fulfill request XML (excluding signature)
        let raw_xml = std::fs::read_to_string("src/testdata/fulfill_request.xml")
            .expect("Failed to read fulfill_request.xml");

        // Hash the XML
        let hash_result = hash_xml_document(&raw_xml);
        assert!(
            hash_result.is_ok(),
            "Failed to hash XML: {:?}",
            hash_result.err()
        );

        let hash = hash_result.unwrap();
        let hash_hex = hex::encode(&hash);

        // Verify against expected hash
        // Based on https://github.com/Leseratte10/acsm-calibre-plugin/blob/fb288afb3a83156f0e534eb1e0ec1cbc45a3e675/calibre-plugin/libadobe.py#L573
        assert_eq!(hash_hex, "1d1598745cd4a52ff1942d876b3dce13d2e823e7");
    }

    #[test]
    fn test_generate_fulfill_request_minified() {
        let user = "urn:uuid:54f2e5c9-0071-46e4-8452-df4f7fe0cc3f";
        let device = "urn:uuid:a69fd2ee-8b78-4410-a1a1-8c782e379fb7";
        let fingerprint = "poA5CcMwBNV9SFY8wyoVPCPhkI4=";

        // Parse the test ACSM file
        let acsm_info =
            parse_acsm("src/testdata/URLLink.acsm").expect("Failed to parse test ACSM file");

        let xml = generate_fulfill_request_minified(&acsm_info, user, device, fingerprint);

        // Verify structure
        assert!(xml.starts_with("<?xml version=\"1.0\"?>"));
        assert!(xml.contains("<adept:fulfill xmlns:adept=\"http://ns.adobe.com/adept\">"));
        assert!(xml.contains(&format!("<adept:user>{}</adept:user>", user)));
        assert!(xml.contains(&format!("<adept:device>{}</adept:device>", device)));
        assert!(xml.contains("<adept:deviceType>standalone</adept:deviceType>"));

        // Verify fulfillmentToken preserves formatting (has newlines)
        assert!(xml.contains("<fulfillmentToken"));
        assert!(xml.contains("\n  <distributor>"));

        // Verify targetDevice is minified (no newlines between its elements)
        let target_start = xml
            .find("<adept:targetDevice>")
            .expect("targetDevice not found");
        let target_end = xml
            .find("</adept:targetDevice>")
            .expect("targetDevice end not found");
        let target_section = &xml[target_start..target_end + 21];
        // Should not have newlines within targetDevice elements (they're minified)
        assert!(
            !target_section.contains("\n"),
            "targetDevice should be minified"
        );

        // Verify it ends correctly
        assert!(xml.ends_with("</adept:fulfill>"));
    }
}
