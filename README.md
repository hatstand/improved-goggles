```bash
> cargo run

Adobe ADEPT DRM key extraction and EPUB decryption tool

Usage: rmpub.exe <COMMAND>

Commands:
  extract-keys  Extract device RSA private key from Windows Registry
  decrypt-file  Decrypt a file from a DRM-protected EPUB
  decrypt-epub  Decrypt an entire EPUB file, removing all DRM
  fetch-epub    Fetch an encrypted EPUB from an operator based on an ACSM file
  auth          Authenticate with an operator using device keys
  debug         Debug commands for development and troubleshooting
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

Most commands run on any platform, but extracting keys currently only works on Windows
as it extracts the keys from the Registry.

## Linux

`cargo run --target x86_64-unknown-linux-gnu`

## Mac

`cargo run --target aarch64-apple-darwin`

## Examples

* Fetch & decrypt an epub from a `URLLink.acsm`:

    `rmpub fetch-epub {path-to-acsm} --output {output-path-for-epub}`

* Extract keys from ADE on windows for later use:

    `rmpub extract-keys`

    This will output a file named `adept_keys.json` by default, which can be used later by most commands with the `--key` option.

* Decrypt a previously downloaded book:

    `rmpub decrypt-epub {path-to-encrypted-epub} --output {output-path-for-epub}`


### Debugging

Currently, if you have never bought a book from a particular operator before in ADE,
fetching will fail as it needs a one-time auth. This can be accomplished with:

    rmpub auth {operatorURL/Auth}

You can find the `operatorURL` in the `URLLink.acsm` file.