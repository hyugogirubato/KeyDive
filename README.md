# KeyDive: Widevine L3 Key Extractor for Android

KeyDive is a Python tool designed to extract Widevine L3 DRM keys from Android devices seamlessly, supporting multiple Android versions for DRM research, education, and analysis.

> [!IMPORTANT]  
> For dynamic key extraction on devices with Android SDK > 33 (OEM API 18+), a minimum `frida-server 16.6.0` is required. Otherwise, pre-extracted functions from Ghidra are necessary.

## Features

- 🚀 Easy installation with [pip](https://pip.pypa.io/)
- 🔄 Automated Widevine L3 key extraction supporting SDK > 21
- 📱 Supports a wide range of Android devices and versions
- 💾 Export extracted keys and device credentials in multiple formats including pywidevine `.wvd`
- 🌐 Offline extraction mode available
- 🖥️ Flexible command-line interface with multiple customization options
- 🛠️ Supports injecting custom Widevine functions extracted from Ghidra XML files
- ❤️ Fully open-source and actively maintained

## Prerequisites

- **ADB (Android Debug Bridge):** Make sure to install [ADB](https://github.com/hyugogirubato/KeyDive/blob/main/docs/PACKAGE.md#adb-android-debug-bridge) and include it in your system's PATH environment variable for easy command-line access.
- **frida-server:** Install `frida-server` on your target Android device. **This requires root access on the device**. For installation instructions and downloads, visit the [official Frida documentation](https://frida.re/docs/installation/).
- **Python 3.8+**

## Installation

Follow these steps to set up KeyDive:

1. Ensure all prerequisites are met (see above).
2. Install KeyDive directly from PyPI:
   ````shell
   pip install keydive
   ````

## Usage

1. Run the KeyDive script:
   ````bash
   keydive -kw -a player
   ````
2. The script will install and launch the [Kaltura](https://github.com/kaltura/kaltura-device-info-android) DRM test app (if not already installed).
3. Follow these steps within the app:
    - **Provision Widevine** (if the device isn't provisioned).
    - **Refresh** to intercept the keybox or private key.
    - **Test DRM Playback** to extract the challenge.
4. KeyDive automatically captures the Widevine keys, saving them as:
    - `client_id.bin` (device identification data).
    - `private_key.pem` (RSA private key).

This will automatically install and launch the recommended DRM test app (Kaltura), provision Widevine if necessary, and perform the extraction steps.

> [!TIP]  
> This sequence ensures that the DRM-protected content is active and ready for key extraction by the time the KeyDive script is initiated, optimizing the extraction process.

### Command-Line Options

````shell
Usage: keydive [-h] [-s <serial>] [-d <delay>] [-v] [-l <dir>] [-V] [-o <dir>] [-w] [-k] [-a <type>] [--no-detect] [--no-disabler] [--no-stop] [--unencrypt] [--symbols <symbols>] [--challenge <challenge>] [--rsa-key <rsa-key>] [--aes-key <aes-key>]

Extract Widevine CDM components from an Android device.

Optional Arguments:
  -h, --help            show this help message and exit

Global Options:
  -s, --serial <serial>
                        ADB serial number of the target Android device.
  -d, --delay <delay>   Delay in seconds between process status checks. (default: 1.0)
  -v, --verbose         Enable detailed logging for debugging.
  -l, --log <dir>       Directory to save log files.
  -V, --version         Show tool version and exit.

Cdm Extraction:
  -o, --output <dir>    Directory to store extracted CDM files. (default: ./device)
  -w, --wvd             Export data in pywidevine-compatible WVD format.
  -k, --keybox          Export Widevine keybox if available on the device.
  -a, --auto <type>     Automatically launch a DRM playback test. ("web" or "player")

Advanced Options:
  --no-detect           Disable automatic detection of OEM private key function.
  --no-disabler         Disable liboemcrypto-disabler module (patches memory protection).
  --no-stop             Do not stop once minimum CDM data is intercepted.
  --unencrypt           Force the license challenge to keep client ID data unencrypted.
  --symbols <symbols>   Path to Ghidra-generated XML symbol file for function mapping.
  --challenge <challenge>
                        Protobuf challenge file(s) captured via MITM proxy.
  --rsa-key <rsa-key>   RSA private key(s) in PEM or DER format for client ID decryption.
  --aes-key <aes-key>   AES key(s) in hex, base64, or file form for decrypting keybox data.
````

> [!NOTE]  
> The advanced options are primarily intended for debugging and development purposes. Regular users do not need to use them.

## Advanced Usage

### Extracting Functions

Custom functions extracted from Widevine libraries with Ghidra can be provided to KeyDive to improve compatibility on some devices. See the [Functions Extraction Guide](https://github.com/hyugogirubato/KeyDive/blob/main/docs/advanced/FUNCTIONS.md).

### Offline Extraction

KeyDive supports offline extraction workflows suitable for restricted environments. See the [Offline Mode Guide](https://github.com/hyugogirubato/KeyDive/blob/main/docs/advanced/OFFLINE.md).

### Using Unencrypted Challenge Data

> [!CAUTION]  
> The `--unencrypt` option forces the license challenge to keep client ID data unencrypted. This option can cause repetitive crashes or instability in the Widevine library on certain devices.

When client ID extraction fails, provide an unencrypted challenge via `--challenge`. See the [Challenge Extraction Guide](https://github.com/hyugogirubato/KeyDive/blob/main/docs/advanced/CHALLENGE.md).

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
<a href="https://github.com/sn-o-w"><img src="https://images.weserv.nl/?url=avatars.githubusercontent.com/u/206893953?v=4&h=25&w=25&fit=cover&mask=circle&maxage=7d" alt="samu87d8dh2"/></a>
<a href="https://github.com/flloschy"><img src="https://images.weserv.nl/?url=avatars.githubusercontent.com/u/69321390?v=4&h=25&w=25&fit=cover&mask=circle&maxage=7d" alt="flloschy "/></a>

## Licensing

This software is licensed under the terms of [MIT License](https://github.com/hyugogirubato/KeyDive/blob/main/LICENSE).  
You can find a copy of the license in the LICENSE file in the root folder.

---

© hyugogirubato 2025
