# Adobe Adept Registry Keys

#### `\HKEY_CURRENT_USER\Software\Adobe\Adept\Device`

* `key`: The "device" key. An AES128CBC key encrypted using `CryptProtectData` and entropy derived from the device.
* `username`: The Windows user at setup time, contributes to the device entropy.

#### `HKEY_CURRENT_USER\Software\Adobe\Adept\Activation`

* `credentials`:
    * `user`: The anonymous user ID used in fulfilment requests.
    * `pkcs12`: The "auth" key. A 1024-bit RSA key stored as pkcs#12 where the password is the (standard) base64-encoded device key. Used for signing requests, such as fulfilment requests.
    * `licenseCertificate`: TODO
    * `privateLicenseKey`: The "license" key. A 1024-bit RSA key encrypted with AES128CBC using the "device" key & an IV of 0. Used to decrypt epubs.
    * `authenticationCertificate`: TODO

* `activationToken`:
    * `device`: The device ID user in fulfilment requests.
    * `fingerprint`: The device fingerprint (stable over activations), used in fulfilment requests.
    * `deviceType`: `standalone` for ADE on PC. Used in fulfilment requests.
    * `activationURL`: TODO
    * `user`: The anonymous user ID used in fulfilment requests (same as above).
    * `signature`: TODO