# ACSM

[ACSM files](#example-acsm) are pointers to books provided by "operators".
They provide metadata that can be combined with device & user data to exchange for an actual epub.

The `fulfillmentToken` within can be exchanged using the `operatorURL` combined with `/Fulfill`, e.g.,
`http://acs.ebookscorporation.com/fulfullment/Fulfill`.

## Fulfilment request

The `fulfillmentToken` can be included verbatim from the ACSM file.

The request body is an XML `fulfill` element containing a `fulfillmentToken` from the
ACSM file.
It also contains an `adept` element, that contains user and device activation data and a signature.
These fields can be filled based on the activation data from the [registry](/REGISTRY.md).

### Signature

The body also includes a signature.
This is based off a SHA1 hash of the XML tree, ignoring the hmac (and the signature itself).
The RSA key from the `pkcs12` registry key should be used to sign this.

```
POST {operator_url}/Fulfill
Accept: */*
Content-Type: application/vnd.adobe.adept+xml
User-Agent: book2png
Content-Length: {...}
```

```xml
<?xml version="1.0"?>
<adept:fulfill xmlns:adept="http://ns.adobe.com/adept">
  <adept:user>{user}</adept:user>
  <adept:device>{device}</adept:device>
  <adept:deviceType>standalone</adept:deviceType>
  <fulfillmentToken fulfillmentType="buy" auth="user" xmlns="http://ns.adobe.com/adept">
    <distributor>urn:uuid:d051ad0d-03ed-4b63-b257-5bfe2e304a80</distributor>
    <operatorURL>http://acs.ebookscorporation.com/fulfillment</operatorURL>
    <transaction>ABC-123456789</transaction>
    <purchase>2026-02-17T22:46:59+00:00</purchase>
    <expiration>2026-02-18T04:46:59+00:00</expiration>
    <resourceItemInfo>
      <resource>urn:uuid:e0000000-0000-0000-0000-000123456789</resource>
      <resourceItem>1</resourceItem>
      <metadata>
        <dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">Book Title</dc:title>
        <dc:creator xmlns:dc="http://purl.org/dc/elements/1.1/">Book Author</dc:creator>
        <dc:publisher xmlns:dc="http://purl.org/dc/elements/1.1/">Book Publisher</dc:publisher>
        <dc:identifier xmlns:dc="http://purl.org/dc/elements/1.1/">URN:ISBN:some_isbn</dc:identifier>
        <dc:format xmlns:dc="http://purl.org/dc/elements/1.1/">application/epub+zip</dc:format>
        <dc:language xmlns:dc="http://purl.org/dc/elements/1.1/">en</dc:language>
      </metadata>
      <licenseToken>
        <resource>urn:uuid:e0000000-0000-0000-0000-000123456789</resource>
        <permissions>
          <display/>
          <play/>
        </permissions>
      </licenseToken>
    </resourceItemInfo>
    <hmac>Base64-hmac</hmac>
  </fulfillmentToken>
  <adept:targetDevice>
    <adept:softwareVersion>12.5.4.HOBBES_VERSION_BUILD_NUMBER_X</adept:softwareVersion>
    <adept:clientOS>Windows 8</adept:clientOS>
    <adept:clientLocale>en</adept:clientLocale>
    <adept:clientVersion>com.adobe.adobedigitaleditions.exe v4.5.12.112</adept:clientVersion>
    <adept:deviceType>standalone</adept:deviceType>
    <adept:productName>ADOBE Digitial Editions</adept:productName>
    <adept:fingerprint>{device fingerprint}</adept:fingerprint>
    <adept:activationToken>
      <adept:user>{user}</adept:user>
      <adept:device>{device}</adept:device>
    </adept:activationToken>
  </adept:targetDevice>
  <adept:signature>{signature}</adept:signature>
</adept:fulfill>
```

## Example ACSM

```
<fulfillmentToken fulfillmentType="buy" auth="user" xmlns="http://ns.adobe.com/adept">
  <distributor>urn:uuid:d051ad0d-03ed-4b63-b257-5bfe2e304a80</distributor>
  <operatorURL>http://acs.ebookscorporation.com/fulfillment</operatorURL>
  <transaction>ABC-123456789</transaction>
  <purchase>2026-02-17T22:46:59+00:00</purchase>
  <expiration>2026-02-18T04:46:59+00:00</expiration>
  <resourceItemInfo>
    <resource>urn:uuid:e0000000-0000-0000-0000-000123456789</resource>
    <resourceItem>1</resourceItem>
    <metadata>
      <dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">Book Title</dc:title>
      <dc:creator xmlns:dc="http://purl.org/dc/elements/1.1/">Book Author</dc:creator>
      <dc:publisher xmlns:dc="http://purl.org/dc/elements/1.1/">Book Publisher</dc:publisher>
      <dc:identifier xmlns:dc="http://purl.org/dc/elements/1.1/">URN:ISBN:some_isbn</dc:identifier>
      <dc:format xmlns:dc="http://purl.org/dc/elements/1.1/">application/epub+zip</dc:format>
      <dc:language xmlns:dc="http://purl.org/dc/elements/1.1/">en</dc:language>
    </metadata>
    <licenseToken>
      <resource>urn:uuid:e0000000-0000-0000-0000-000123456789</resource>
      <permissions>
        <display/>
        <play/>
      </permissions>
    </licenseToken>
  </resourceItemInfo>
  <hmac>Base64-hmac</hmac>
</fulfillmentToken>
```