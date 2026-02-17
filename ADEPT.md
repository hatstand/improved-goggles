# Adobe ADEPT DRM Technical Documentation

_Based on Adobe Digital Editions 4.5.12.112_

## Overview

Adobe ADEPT (Adobe Digital Experience Protection Technology) is a DRM system used to protect EPUB files. It uses a multi-layer encryption scheme combining RSA and AES encryption to protect content.

## Architecture

The ADEPT DRM system consists of several layers:

1. Device-specific AES key stored in Windows Registry.
2. Device-specific RSA key stored in Windows Registry, encrypted with above AES key.
3. Per-book AES key stored in individual epub, encrypted with above RSA key.

## Registry Structure

### Device Keys Location
```
HKEY_CURRENT_USER\Software\Adobe\Adept\Device
```

Contains:
- `username` (REG_SZ): Adobe account username
- `key` (REG_BINARY): Encrypted device-specific AES key (the "key-key")

### Activation Keys Location
```
HKEY_CURRENT_USER\Software\Adobe\Adept\Activation\<activation-id>\credentials
```

Structure:
- Each activation has a unique GUID as its key
- Contains a `credentials` subkey
- Under credentials, there are multiple subkeys for different credential types:
  - `privateLicenseKey`: The encrypted RSA private key (base64-encoded)
  - `user`: GUID

## Device Entropy Generation

The device-specific entropy is a 32-byte value derived from hardware and system information to bind keys to a specific machine.
This data is used as the `entropy` parameter for [`CryptUnprotectData`](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata).

### Entropy Composition (bytes 0-31):

```
Offset | Length | Content
-------|--------|--------------------------------------------------
0-3    | 4      | Volume serial number (big-endian u32)
4-15   | 12     | CPU vendor string (e.g., "GenuineIntel"/"AuthenticAMD") from CPUID(0)
16-18  | 3      | CPU signature (bytes 1-3 of EAX from CPUID(1))
19-31  | 13     | Adobe username (first 13 bytes), padded with zeroes
```

### Generation Process:

1. **Volume Serial Number**: Get from system drive (e.g., `C:\`)
   - Windows API: `GetVolumeInformationW()`
   - From Command Line:
   ```
    C:\> vol c:
     Volume in drive C has no label.
     Volume Serial Number is 1234-ABCD
   ```
   
2. **CPU Vendor**: From CPUID instruction with EAX=0
   - Returns 12 chars in EBX, EDX, ECX registers
   - Common values: "GenuineIntel", "AuthenticAMD"

3. **CPU Signature**: From CPUID instruction with EAX=1
   - Full signature in EAX, but only use bytes 1-3 (skip first byte)
   - Encodes family, model, and stepping information

4. **Adobe Username**: From registry key `Software\Adobe\Adept\Device\username`
   - First 13 bytes used as entropy
   - Padding with zeroes if shorter

## Decryption Process

### Step 1: Retrieve the Device key

1. Retrieve the encrypted device key from the Windows Registry key `\\HKEY_CURRENT_USER\Software\Adobe\Adept\Device\key`.

2. Generate device entropy.

3. Decrypt the device key

    The device RSA key is stored encrypted in the registry using Windows DPAPI (Data Protection API).

    ```
    Encrypted Key → CryptUnprotectData(entropy) → Decrypted AES-128 Key
    ```

    where:

    * `pDataIn`: the encrypted AES key from the registry.
    * `pOptionalEntropy`: the [32 bytes of entropy from above](#device-entropy-generation).


### Step 2: Retrieve the RSA private key

1. Retrieve the encrypted key from the Windows Registry key `\\HKEY_CURRENT_USER\Software\Adobe\Adept\Activation\{id}\{id}\privateLicenseKey`.

2. Base64 decode the key.

3. Decrypt the key using AES-128 CBC.

    where:

    * the key is the device key from [Step 1](#step-1-retrieve-the-device-key)
    * the IV is 16 bytes of all zeroes

4. Unpad the data based on PKCS#7

    * Read the final byte of the data.
    * Remove that many bytes from the _end_ of the data (includes the padding byte).

5. Remove the first 26 bytes of the data.

6. Parse the data as a DER-encoded 1024-bit RSA key.

```
Base64 Encoded → AES-128-CBC Decrypt → PKCS#7 Unpad → Skip 26 bytes → DER-encoded RSA key
```

### Step 3: Retrieve the book encryption key

An epub file is simply a zipfile containing the encrypted book contents and metadata.

1. Read the contents of the `<encryptedKey>` element from `META-INF/rights.xml`.

2. Decode the encrypted book key from standard base64.

3. Decrypt the encrypted book key with the RSA private key using PKCS#1 v1.5.

### Step 4: Decrypt book content

1. Read the first 16 bytes of an encrypted file to obtain the AES IV.

2. Decrypt the remaining bytes of the file using AES128 CBC.

    where:
    * the key is the [book encryption key](#step-3-retrieve-the-book-encryption-key)
    * the IV is the first 16 bytes of the file from above.

3. Decompress the data with raw DEFLATE (not zlib).

## EPUB File Structure

### Standard EPUB Structure
```
book.epub (ZIP file)
├── META-INF/
│   ├── container.xml
│   ├── encryption.xml      # Lists encrypted files
│   └── rights.xml          # Contains encrypted content key
├── OEBPS/
│   ├── content.opf
│   ├── Text/
│   │   ├── chapter1.xhtml  # Encrypted if DRM protected
│   │   └── chapter2.xhtml
│   └── Images/
│       └── cover.jpg       # Encrypted if DRM protected
└── mimetype
```

### DRM-Specific Files

#### `META-INF/rights.xml`
Contains the encrypted content key in the `<encryptedKey>` tag:

```xml
<?xml version="1.0"?>
<rights xmlns="http://ns.adobe.com/adept">
    <licenseToken>
        <encryptedKey>BASE64_ENCRYPTED_CONTENT_KEY</encryptedKey>
    </licenseToken>
</rights>
```

The encrypted key is:
- Base64-encoded
- Encrypted with RSA PKCS#1 v1.5 padding
- Contains a 16-byte AES-128 key for content decryption

#### `META-INF/encryption.xml`
Lists which files in the EPUB are encrypted and how:

```xml
<?xml version="1.0"?>
<encryption xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
    <EncryptedData>
        <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></EncryptionMethod>
        <KeyInfo>
            <resource>urn:uuid:e0000000-0000-0000-0000-000123456789</resource>
        </KeyInfo>
        <CipherData>
            <CipherReference URI="OEBPS/Images/cover.jpg"></CipherReference>
        </CipherData>
        <EncryptionProperties>
            <!-- Expected size after decryption -->
            <ResourceSize>123456</ResourceSize>
        </EncryptionProperties>
    </EncryptedData>
</encryption>
```

### Encryption Scheme Diagram

```
┌─────────────────────────────────────────────────────────┐
│ Windows Registry                                         │
│ ┌─────────────────┐                                     │
│ │ Device Key      │ ← Encrypted with DPAPI + Entropy   │
│ │ (AES-128)       │                                     │
│ └─────────────────┘                                     │
│         │                                                │
│         ├→ Decrypts                                      │
│         ↓                                                │
│ ┌─────────────────┐                                     │
│ │ RSA Private Key │ ← Encrypted with Device Key        │
│ │ (1024/2048-bit) │                                     │
│ └─────────────────┘                                     │
└─────────────────────────────────────────────────────────┘
         │
         ├→ Decrypts
         ↓
┌─────────────────────────────────────────────────────────┐
│ EPUB Book (META-INF/rights.xml)                         │
│ ┌─────────────────┐                                     │
│ │ Content Key     │ ← Encrypted with RSA Public Key    │
│ │ (AES-128)       │                                     │
│ └─────────────────┘                                     │
└─────────────────────────────────────────────────────────┘
         │
         ├→ Decrypts
         ↓
┌─────────────────────────────────────────────────────────┐
│ Individual Files (XHTML, images, etc.)                   │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ [IV][Encrypted Data]                                 │ │
│ │      ↓                                               │ │
│ │ AES-128-CBC Decrypt                                  │ │
│ │      ↓                                               │ │
│ │ Deflate Decompress                                   │ │
│ │      ↓                                               │ │
│ │ Original Content                                     │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Cryptographic Details

### AES-128-CBC
- **Key Size**: 128 bits (16 bytes)
- **Block Size**: 128 bits (16 bytes)
- **Mode**: CBC (Cipher Block Chaining)
- **Padding**: PKCS#7 for content files, manual for RSA key

### RSA
- **Key Size**: 1024 or 2048 bits (varies by activation)
- **Padding**: PKCS#1 v1.5 for encryption
- **Encoding**: DER (PKCS#1 format)

### Compression
- **Algorithm**: Deflate (RFC 1951)
- **Format**: Raw deflate (no zlib/gzip headers)
- **Window Size**: -15 (no header, 32K window)

## References

* [DeDRM_Tools](https://github.com/noDRM/DeDRM_tools/blob/7379b453199ed1ba91bf3a4ce4875d5ed3c309a9/DeDRM_plugin/adobekey.py)
