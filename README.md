# KeyDive: Widevine L3 Extractor for Android

KeyDive is a sophisticated Python script designed for precise extraction of Widevine L3 DRM (Digital Rights Management) keys from Android devices. This tool leverages the capabilities of the Widevine CDM (Content Decryption Module) to facilitate the recovery of DRM keys, enabling a deeper understanding and analysis of the Widevine L3 DRM implementation across various Android SDK versions.

> [!IMPORTANT]
> 
> Support for OEM API 18+ (SDK > 33) require the use of functions extracted from Ghidra.

## Features

- **Automated extraction** of Widevine L3 DRM keys.
- Compatibility with a wide range of Android versions (SDK > 22), ensuring broad applicability.
- Seamless extraction process, yielding essential DRM components such as the `client_id.bin` for device identification and the `private_key.pem` for the RSA private key.
- **Offline extraction mode** for situations without internet access.
- Command-line options for flexibility in usage.
- Support for custom functions extracted from Widevine libraries using Ghidra.

## Prerequisites

Before you begin, ensure you have the following prerequisites in place:

1. **ADB (Android Debug Bridge):** Make sure to install [ADB](https://github.com/hyugogirubato/KeyDive/blob/main/docs/PACKAGE.md#adb-android-debug-bridge) and include it in your system's PATH environment variable for easy command-line access.
2. **Frida-Server:** Install `frida-server` on your target Android device. This requires root access on the device. For installation instructions and downloads, visit the [official Frida documentation](https://frida.re/docs/installation/).

## Installation

Follow these steps to set up KeyDive:

1. Ensure all prerequisites are met (see above).
2. Install KeyDive from PyPI using Poetry:
   ```shell
   pip install keydive
   ```

## Usage

1. Play a DRM-protected video on the target device.
2. Launch the KeyDive script.
3. Reload the DRM-protected video on your device.
4. The script will automatically extract the Widevine L3 keys, saving them as follows:
   - `client_id.bin` - This file contains device identification information.
   - `private_key.pem` - This file contains the RSA private key.

This sequence ensures that the DRM-protected content is active and ready for key extraction by the time the KeyDive script is initiated, optimizing the extraction process.

### Offline Extraction Process

For situations where internet access is limited or unavailable, KeyDive supports an offline extraction mode. This mode allows for the extraction of DRM keys without an active internet connection. Follow these steps to prepare:

1. **Prepare the Android Device:**
   - Install all necessary dependencies and tools while connected to the internet. Ensure that all software and libraries required by KeyDive are properly configured on the device. This includes making sure the device is fully prepared to handle DRM extraction in an offline environment.

2. **Execute KeyDive in Offline Mode:**
   - Once all the preparations are complete and the device is disconnected from the internet, run the KeyDive script to extract the Widevine L3 keys. Ensure that the DRM-protected content is ready and available on the device for extraction.

For a detailed step-by-step guide on setting up and executing KeyDive without internet access, please refer to our dedicated document: [Offline Mode Detailed Guide](./docs/axinom/OFFLINE.md).

### Command-Line Options

```shell
usage: keydive [-h] [-d <id>] [-v] [-l <dir>] [--delay <delay>] [--version] [-a] [-c <file>] [-w] [-o <dir>] [-f <file>]

Extract Widevine L3 keys from an Android device.

options:
  -h, --help            show this help message and exit

Global options:
  -d <id>, --device <id>
                        Specify the target Android device ID to connect with via ADB.
  -v, --verbose         Enable verbose logging for detailed debug output.
  -l <dir>, --log <dir>
                        Directory to store log files.
  --delay <delay>       Delay (in seconds) between process checks in the watcher.
  --version             Display KeyDive version information.

Cdm options:
  -a, --auto            Automatically open Bitmovin's demo.
  -c <file>, --challenge <file>
                        Path to unencrypted challenge for extracting client ID.
  -w, --wvd             Generate a pywidevine WVD device file.
  -o <dir>, --output <dir>
                        Output directory path for extracted data.
  -f <file>, --functions <file>
                        Path to Ghidra XML functions file.

```

### Extracting Functions for Advanced Usage

For advanced users looking to use custom functions with KeyDive, a comprehensive guide on extracting functions from Widevine libraries using Ghidra is available. Please refer to our [Functions Extraction Guide](./docs/FUNCTIONS.md) for detailed instructions.

## Temporary Disabling L1 for L3 Extraction

Some manufacturers (e.g., Xiaomi) allow the use of L1 keyboxes even after unlocking the bootloader. In such cases, it's necessary to install a Magisk module called [liboemcrypto-disabler](https://github.com/hyugogirubato/KeyDive/blob/main/docs/PACKAGE.md#liboemcrypto-disabler) to temporarily disable L1, thereby facilitating L3 key extraction.

## Credits

Special thanks to the original developers and contributors who have made KeyDive possible. This tool is the culmination of collaborative efforts, research, and a deep understanding of DRM technologies.

## Disclaimer

KeyDive is intended for educational and research purposes only. The use of this tool in unauthorized testing of protected content is strictly prohibited. Please ensure you have permission before proceeding with DRM key extraction.

---

By using KeyDive, you acknowledge and agree to the terms of use and disclaimer stated above.
