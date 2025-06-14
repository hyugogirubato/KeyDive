# KeyDive Developer Documentation

This document explains the internal workings of KeyDive, including key concepts in the JS hook scripts, the meaning of critical fields, and the flow of the extraction process.

## Key Concepts & Terminology

| Key                   | Description                                                                               |
|-----------------------|-------------------------------------------------------------------------------------------|
| `provisioning_method` | Indicates the method used to provision Widevine DRM.                                      |
| `challenge`           | Unencrypted challenge data sent to Widevine CDM to trigger provisioning or key requests.  |
| `client_id`           | Unique identifier extracted from the device representing the Widevine client credentials. |
| `private_key`         | RSA private key used for DRM content decryption and authentication.                       |
| `keybox`              | Device-specific key storage blob containing keys for DRM operations.                      |
| `certificate`         | Device OEM certificate chain for verifying keys and trust.                                |
| `encryption_context`  | Session-specific message context used to derive AES/CMAC keys for provisioning and media. |

## Script Execution Flow

The core extraction logic is implemented in a Frida hook script injected into Widevine CDM processes. The following sequence diagram illustrates the general flow, including options for player choice and output formats:

````text
+----------------+       +------------------+      +---------------------+        +------------------+
| Start Script   |       | Select Player    |      | Provisioning Method |        | Extraction Steps |
+----------------+       +------------------+      +---------------------+        +------------------+
|                        |                        |                               |
|--(option: -a player)-->| Launch Kaltura app     |                               |
|                        |                        |                               |
|--(option: -a web)----->| Launch Bitmovin player |                               |
|                        |                        |                               |
|                        |                        |---Check provisioning_method-->| 
|                        |                        |                               |
|                        |                        |<--Send challenge data---------| 
|                        |                        |                               |
|                        |                        |---Extract client_id---------->| 
|                        |                        |---Extract private_key-------->| 
|                        |                        |---Extract keybox (optional)-->| 
|                        |                        |                               |
|                        |                        |---Export data to output dir-->| 
|                        |                        |                               |
|                        |                        |                               |
V                        V                        V                               V
(Process ends)           (Process ends)           (Process ends)                  (Process ends)
````

## Key Data Handling

### Provisioning Method

The provisioning method determines how the device is authenticated with Widevine. Internally, KeyDive uses the following enum:

| Enum Value          | Meaning                                                                     |
|---------------------|-----------------------------------------------------------------------------|
| `ProvisioningError` | Device cannot be provisioned (typically unsupported or failed setup).       |
| `DrmCertificate`    | The device uses a pre-installed baked-in DRM certificate (usually L3 only). |
| `Keybox`            | A factory-installed keybox is used to identify the device and decrypt keys. |
| `OEMCertificate`    | A factory-provisioned OEM certificate chain is present for full L1 support. |

These values are automatically detected at runtime to determine the correct extraction strategy.

### Challenge Handling

The `challenge` is a critical blob of data sent during provisioning or license acquisition. KeyDive can:

* Intercept it during DRM playback.
* Accept an external file via the `--challenge` argument.

This challenge contains the encrypted request for keys or certificates and is essential for key extraction workflows.

### Encryption Context

The `encryption_context` is a byte sequence intercepted from CDM session messages, typically unique per provisioning
session.

It is used to derive:

* `enc` key: for AES-CBC decryption of RSA private keys or media keys
* `auth_1` and `auth_2` keys: for HMAC or CMAC authentication of messages

This context plays a central role in:

* Reconstructing derived AES keys during Keybox or OTA provisioning
* Verifying responses and signing requests
* Securely decrypting the RSA private key in post-provisioning stages

The context is usually extracted from specific intercepted Widevine function arguments and stored alongside other
credentials.

### Client ID & Private Key

Both the `client_id` and `private_key` are extracted from the intercepted CDM functions. They are:

* Required for device emulation or license response reconstruction.
* Automatically exported to formats like `client_id.bin`, `private_key.pem`, and `.wvd`.

## Advanced Options & Debugging

The advanced command-line options allow:

* Overriding automatic provisioning detection.
* Injecting Ghidra-extracted symbol maps via `--symbols`.
* Forcing use of unencrypted challenges (`--unencrypt`) for debugging or fallback workflows.
* Extracting optional blobs like the Widevine keybox or certificates.

These are primarily useful for development, debugging, or supporting less common device models.

## Contribution Guidelines

Feel free to contribute by submitting PRs or reporting issues. Please follow the coding style and provide tests for new features.

---

© hyugogirubato 2025