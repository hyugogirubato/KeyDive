# Functions

To utilize custom functions with KeyDive, particularly when extracting Widevine L3 DRM keys from Android devices, you might need to generate a `functions.xml` file using Ghidra. This file helps KeyDive accurately identify necessary functions within the Widevine library, facilitating a more efficient extraction process. Below is a step-by-step guide on how to create a `functions.xml` file using Ghidra:

### Retrieving Library Binary from Device Using ADB

#### 1. Identify Library Path with KeyDive

Run KeyDive to detect the library path on the Android device:

```shell
keydive --device <DEVICE_ID>
```

Replace `<DEVICE_ID>` with the ID of your Android device connected via ADB.

#### 2. Copy Library to `/data/local/tmp`

Once KeyDive has detected the library path, proceed to copy the library from its detected location to `/data/local/tmp` on the device. This requires root access, so use `su` to switch to root:

```shell
adb -s <DEVICE_ID> shell
su
cp /path/to/detected/library /data/local/tmp
```

Replace `/path/to/detected/library` with the actual path detected by KeyDive.

#### 3. Adjust Permissions

Set the correct permissions for the copied library to ensure access:

```shell
chown shell:shell /data/local/tmp/library_name
```

Replace `library_name` with the name of the library file.

#### 4. Download Library to Local Machine

Download the library from `/data/local/tmp` to your local machine using ADB:

```shell
adb -s <DEVICE_ID> pull /data/local/tmp/library_name /path/on/your/local/machine
```

Replace `<DEVICE_ID>` with your device ID and `/path/on/your/local/machine` with the destination path on your local machine where you want to save the library.

### Extracting functions with Ghidra

#### 1. Preparing Ghidra

Ensure you have Ghidra installed on your system. If not, download it from the [Ghidra project page](https://ghidra-sre.org/) and follow the installation instructions.

#### 2. Importing the ELF Binary

- Launch Ghidra and start a new project (or open an existing one).
- Import the ELF binary file (e.g., the Widevine CDM library from the Android device) by navigating to `File` > `Import File` and selecting the binary.
- Choose the default options for the import settings, unless you have specific requirements.

#### 3. Analyzing the Binary

- Once the binary is imported, double-click on it in the project window to open it in the CodeBrowser tool.
- Begin the analysis by navigating to `Analysis` > `Auto Analyze` from the top menu.
- In the "Auto Analysis" window, ensure all relevant analyzers are selected, especially those related to symbol and function discovery. Click "Analyze" to start the process.
- Wait for the analysis to complete, which may take some time depending on the binary's size and complexity.

#### 4. Exporting Functions as XML

- After analysis, navigate to `File` > `Export Program...`.
- In the "Export Program" window, choose the "XML" format from the dropdown menu.
- Click "Options" and ensure that only the "Functions" option is selected. This step is crucial as it filters the export to include only the functions necessary for KeyDive, making the XML file more manageable and relevant.
- Choose a destination for the `functions.xml` file and confirm the export.

#### 5. Using the Functions with KeyDive

Once you have the `functions.xml` file:

- Ensure KeyDive is set up according to its documentation.
- When running KeyDive, use the `--functions` argument to specify the path to your `functions.xml` file. For example:
  ```shell
  keydive --device <DEVICE_ID> --functions /path/to/functions_x86.xml
  ```
- Proceed with the key extraction process as detailed in KeyDive's usage instructions.

### Additional Tips

- **Understanding Functions:** The `functions.xml` file maps function names and variables within the Widevine CDM library, enabling KeyDive to correctly identify and hook into specific processes for key extraction.
- **Ghidra Compatibility:** Ensure your version of Ghidra supports the binary format you're analyzing. Newer versions of Ghidra typically offer better support for a wide range of binary formats.
- **Analysis Depth:** While a full analysis is recommended, you can customize the analysis options based on your understanding of the binary and the functions you are specifically interested in. This can significantly reduce analysis time.
- **Security Considerations:** Be aware of the security implications of extracting and handling DRM keys. Always comply with legal restrictions and ethical guidelines when using tools like KeyDive and Ghidra for reverse engineering.

By following these steps, you can generate a `functions.xml` file that aids in the effective use of KeyDive for
educational, research, or security analysis purposes.