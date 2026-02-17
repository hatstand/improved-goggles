use anyhow::{Context, Result};
use sha1::{Digest, Sha1};

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

    hasher.update([len_upper, len_lower]);
    hasher.update(bytes);
}

/// Hash a single tag byte
fn hash_append_tag(hasher: &mut Sha1, tag: u8) {
    hasher.update([tag]);
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
pub fn hash_xml_document(xml: &str) -> Result<Vec<u8>> {
    let doc = roxmltree::Document::parse(xml).context("Failed to parse XML for hashing")?;

    let mut hasher = Sha1::new();
    hash_node_recursive(doc.root_element(), &mut hasher);

    let ret = hasher.finalize().to_vec();
    assert_eq!(ret.len(), 20, "SHA-1 hash should be 20 bytes");

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
