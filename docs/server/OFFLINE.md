# Offline DRM Key Extraction for Axinom Content

This project focuses on extracting DRM keys offline from streams protected by Axinom DRM. It involves patching an open-source application to customize stream definitions, disabling network connectivity checks, and optionally bypassing SSL pinning. Additionally, it includes steps for handling device provisioning requests using a fake server.

## Prerequisites

- Android Studio SDK to modify and build the APK.
- Frida setup on your device/emulator for runtime instrumentation.
- HTTP Toolkit for intercepting and modifying network traffic.
- Basic understanding of Android development and network protocols.

## Setup

### Step 1: Patch the APK

1. Clone the repository of the open-source app you intend to patch.
2. Modify the app’s source code to:
   - Define the correct stream URL.
   - Disable any network connectivity checks in the app. For example, bypass methods that check for active internet connections.
   ```shell
   python3 builder_mobile.py
   ```
3. Build the modified APK and install it on your Android device or emulator.
   ```shell
   python3 patcher.py
   ```

### Step 2: Bypass SSL Pinning (if necessary)

If the app implements SSL pinning, follow the steps below to bypass it using Frida:

1. Ensure Frida is installed on your device or emulator.
2. Use the script provided in the [Frida-CodeShare repository](https://github.com/hyugogirubato/Frida-CodeShare/tree/main/scripts/android-pinning) to intercept SSL pinning methods dynamically.
3. Run the script using the command:
   ```
   frida -D "DEVICE_ID" -l "pinning.js" -f "PACKAGE_NAME"
   ```
   Replace `"DEVICE_ID"` with your device or emulator ID and `"PACKAGE_NAME"` with the package name of your patched app.

### Step 3: Setup Fake Server for Provisioning

1. Setup a Python server to mimic the license server. This server should always respond with a 302 redirect loop, essentially providing an infinite timeout.
   ```shell
   python3 app.py
   ```
2. Implement the fake server with endpoints required for the DRM license and provisioning requests.

### Step 4: Use HTTP Toolkit

1. Install and set up HTTP Toolkit on your PC.
2. Import predefined rules to simulate the static responses needed for the app, like `manifest.mpd`.
3. Direct your app traffic through HTTP Toolkit to manipulate the responses as needed.

## Running the App

Launch the patched app on your device. Since the network checks are disabled, and the app is configured to use the fake server responses, it should function without real internet access, allowing for offline DRM key extraction.