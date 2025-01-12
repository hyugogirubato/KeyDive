# KeyDive: Widevine L3 Extractor for Android

KeyDive is a sophisticated Python script designed for precise extraction of Widevine L3 DRM (Digital Rights Management) keys from Android devices. This tool leverages the capabilities of the Widevine CDM (Content Decryption Module) to facilitate the recovery of DRM keys, enabling a deeper understanding and analysis of the Widevine L3 DRM implementation across various Android SDK versions.

> [!IMPORTANT]  
> Support for OEM API 18+ (SDK > 33) requires the use of functions extracted from Ghidra.

## Features

- 🚀 Seamless Installation via [pip](#installation)
- 🔄 Automated extraction of Widevine L3 DRM keys
- 📱 Compatibility with a wide range of Android versions (SDK > 21), ensuring broad applicability
- 💾 Seamless extraction process, yielding essential DRM components
- 🌐 Offline extraction mode for environments without internet access
- 🖥️ Command-line options for flexible usage
- 🛠️ Support for custom functions extracted from Widevine libraries using Ghidra
- ❤️ Fully Open-Source! Pull Requests Welcome

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
    - `private_key.pem` - This file contains the RSA private key for decryption.

This sequence ensures that the DRM-protected content is active and ready for key extraction by the time the KeyDive script is initiated, optimizing the extraction process.

### Command-Line Options

```shell
usage: keydive [-h] [-d <id>] [-v] [-l <dir>] [--delay <delay>] [--version] [-o <dir>] [-w] [-s] [-a] [-p] [-f <file>] [-k] [--challenge <file>] [--private-key <file>]

Extract Widevine L3 keys from an Android device.

options:
  -h, --help            show this help message and exit

Global:
  -d <id>, --device <id>
                        Specify the target Android device ID for ADB connection.
  -v, --verbose         Enable verbose logging for detailed debug output.
  -l <dir>, --log <dir>
                        Directory to store log files.
  --delay <delay>       Delay (in seconds) between process checks.
  --version             Display KeyDive version information.

Cdm:
  -o <dir>, --output <dir>
                        Output directory for extracted data.
  -w, --wvd             Generate a pywidevine WVD device file.
  -s, --skip            Skip auto-detection of the private function.
  -a, --auto            Automatically start the Bitmovin web player.
  -p, --player          Install and start the Kaltura app automatically.

Advanced:
  -f <file>, --functions <file>
                        Path to Ghidra XML functions file.
  -k, --keybox          Enable export of the Keybox data if it is available.
  --challenge <file>    Path to unencrypted challenge for extracting client ID.
  --private-key <file>  Path to private key for extracting client ID.

```

## Advanced Usage

### Extracting Functions

For advanced users looking to use custom functions with KeyDive, a comprehensive guide on extracting functions from Widevine libraries using Ghidra is available. Please refer to our [Functions Extraction Guide](https://github.com/hyugogirubato/KeyDive/blob/main/docs/FUNCTIONS.md) for detailed instructions.

### Offline Extraction

KeyDive supports offline extraction mode for situations without internet access. This mode allows you to extract DRM keys directly from your Android device. Ensure all necessary dependencies are installed and follow the detailed [Offline Mode Guide](https://github.com/hyugogirubato/KeyDive/blob/main/docs/OFFLINE.md) for step-by-step instructions.

### Obtaining Unencrypted Challenge Data

> [!NOTE]  
> Usage of unencrypted challenge is not required by default. It is only necessary when the script cannot extract the client id.

To extract the unencrypted challenge data required for KeyDive's advanced features, follow the steps outlined in our [Challenge Extraction Guide](https://github.com/hyugogirubato/KeyDive/blob/main/docs/CHALLENGE.md). This data is crucial for analyzing DRM-protected content and enhancing your DRM key extraction capabilities.

### Temporary Disabling L1 for L3 Extraction

> [!WARNING]  
> Usage of the module is now deprecated because the deactivation of the library was natively added.

Some manufacturers (e.g., Xiaomi) allow the use of L1 keyboxes even after unlocking the bootloader. In such cases, it's necessary to install a Magisk module called [liboemcrypto-disabler](https://github.com/hyugogirubato/KeyDive/blob/main/docs/PACKAGE.md#liboemcrypto-disabler) to temporarily disable L1, thereby facilitating L3 key extraction.

## Disclaimer

KeyDive is intended for educational and research purposes only. The use of this tool in unauthorized testing of protected content is strictly prohibited. Please ensure you have permission before proceeding with DRM key extraction.

## Contributors

<a href="https://github.com/hyugogirubato"><img src="https://images.weserv.nl/?url=avatars.githubusercontent.com/u/65763543?v=4&h=25&w=25&fit=cover&mask=circle&maxage=7d" alt="hyugogirubato"/></a>
<a href="https://github.com/FoxRefire"><img src="https://images.weserv.nl/?url=avatars.githubusercontent.com/u/155989196?v=4&h=25&w=25&fit=cover&mask=circle&maxage=7d" alt="FoxRefire"/></a>
<a href="https://github.com/azimabid00"><img src="https://images.weserv.nl/?url=avatars.githubusercontent.com/u/110490898?v=4&h=25&w=25&fit=cover&mask=circle&maxage=7d" alt="azimabid00"/></a>
<a href="https://github.com/JohnDoe1964"><img src="https://images.weserv.nl/?url=avatars.githubusercontent.com/u/167800584?v=4&h=25&w=25&fit=cover&mask=circle&maxage=7d" alt="JohnDoe1964"/></a>
<a href="https://github.com/Nineteen93"><img src="https://images.weserv.nl/?url=avatars.githubusercontent.com/u/107993263?v=4&h=25&w=25&fit=cover&mask=circle&maxage=7d" alt="Nineteen93"/></a>
<a href="https://github.com/sn-o-w"><img src="https://images.weserv.nl/?url=avatars.githubusercontent.com/u/2406819?v=4&h=25&w=25&fit=cover&mask=circle&maxage=7d" alt="sn-o-w"/></a>


## Licensing

This software is licensed under the terms of [MIT License](https://github.com/hyugogirubato/KeyDive/blob/main/LICENSE).  
You can find a copy of the license in the LICENSE file in the root folder.

* * * 

© hyugogirubato 2025