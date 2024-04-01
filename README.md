# KeyDive: Widevine L3 Extractor for Android

KeyDive is a sophisticated Python script designed for the precise extraction of Widevine L3 DRM (Digital Rights Management) keys from Android devices. This tool leverages the capabilities of the Widevine CDM (Content Decryption Module) to facilitate the recovery of DRM keys, enabling a deeper understanding and analysis of the Widevine L3 DRM implementation across various Android SDK versions.

> [!WARNING]
> Support for Android 14+ (SDK > 33) is currently under development. Some features may not function as expected on these newer versions.

## Features

- Automated extraction of Widevine L3 DRM keys.
- Compatibility with a wide range of Android versions (SDK > 22), ensuring broad applicability.
- Seamless extraction process, yielding essential DRM components such as the `client_id.bin` for device identification and the `private_key.pem` for the RSA private key.

## Prerequisites

Before you begin, ensure you have the following prerequisites in place:

1. **ADB (Android Debug Bridge):** Make sure to install [ADB](https://developer.android.com/studio/command-line/adb) and include it in your system's PATH environment variable for easy command-line access.
2. **Frida-Server:** Install `frida-server` on your target Android device. This requires root access on the device. For installation instructions and downloads, visit the [official Frida documentation](https://frida.re/docs/installation/).
3. **Python Requirements:** KeyDive requires specific Python libraries to function correctly. Install them using the provided `requirements.txt` file:
   ```shell
   pip install -r requirements.txt
   ```

## Installation

Follow these steps to set up KeyDive:

1. Ensure all prerequisites are met (see above).
2. Clone this repository to your local machine.
3. Navigate to the cloned directory and install the required Python dependencies as mentioned.

## Usage

1. Play a DRM-protected video on the target device.
2. Launch the KeyDive script.
3. Reload the DRM-protected video on your device.
4. The script will automatically extract the Widevine L3 keys, saving them as follows:
   - `client_id.bin` - This file contains device identification information.
   - `private_key.pem` - This file contains the RSA private key.

This sequence ensures that the DRM-protected content is active and ready for key extraction by the time the KeyDive script is initiated, optimizing the extraction process.

### Command-Line Options

```shell
usage: keydive.py [-h] [--device DEVICE] [--functions FUNCTIONS]

Extract Widevine L3 keys from an Android device.

options:
  -h, --help            show this help message and exit
  --device DEVICE       Target Android device ID.
  --functions FUNCTIONS
                        Ghidra XML functions file.

```

### Extracting Functions for Advanced Usage

For advanced users looking to use custom functions with KeyDive, a comprehensive guide on extracting functions from Widevine libraries using Ghidra is available. Please refer to our [Functions Extraction Guide](./docs/FUNCTIONS.md) for detailed instructions.

## Temporary Disabling L1 for L3 Extraction

Some manufacturers (e.g., Xiaomi) allow the use of L1 keyboxes even after unlocking the bootloader. In such cases, it's necessary to install a Magisk module called [liboemcrypto-disabler](https://github.com/Magisk-Modules-Repo/liboemcryptodisabler) to temporarily disable L1, thereby facilitating L3 key extraction.

## Credits

Special thanks to the original developers and contributors who have made KeyDive possible. This tool is the culmination of collaborative efforts, research, and a deep understanding of DRM technologies. 

## Disclaimer

KeyDive is intended for educational and research purposes only. The use of this tool in unauthorized testing of protected content is strictly prohibited. Please ensure you have permission before proceeding with DRM key extraction.

---

By using KeyDive, you acknowledge and agree to the terms of use and disclaimer stated above.