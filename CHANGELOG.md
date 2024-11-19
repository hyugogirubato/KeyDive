# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.4] - 2024-11-19

### Changed

- Library disabler error messages are now displayed in `DEBUG` mode for improved verbosity.

### Fixed

- Fixed errors in ADB shell messages.
- Resolved issues with executing shell commands via `subprocess`.

## [2.1.3] - 2024-11-03

### Added

- Detection system for keybox data changes to prevent redundant exports.
- Max API version available for plaintext keybox.

### Changed

- Encrypted keybox files are now exported with a `.enc` extension for clarity.

### Fixed

- Issue with invalid keybox data preventing proper reception and export.
- Device token encoding error for keybox data.

## [2.1.2] - 2024-11-02

#### Added

- Descriptions for functions used by the Frida script.
- Support for dumping the keybox from older versions of CDM.

### Changed

- Replaced `libc`-based keybox interception with a native function.
- Adjusted player/auto options to execute before DRM detection, enhancing detection on legacy devices.
- Improved handling for displaying varying keybox contents based on the device ID.
- Streamlined JS function detection for better performance.

### Fixed

- Resolved startup issue with the Widevine service when launching the script.
- Addressed unsupported error with the new `ADB` class.
- Fixed detection of the `MAIN` activity in applications.
- Corrected parsing errors when listing applications.
- Improved detection of minimum required functions.

## [2.1.1] - 2024-10-28

### Added

- Private key functionality for enhanced key extraction security.
- Local DRM server for (almost) offline use.
- Option to import the private key for easier management.
- Automatic installation and usage of a local player.
- New `Advanced` group for better argument organization.
- Experimental keybox extraction from the device.
- Added CDM details for SDK 35.

### Changed

- Device interactions migrated to the `ADB` class for better encapsulation.
- Code comments added and optimizations made for clarity.
- Displaying the `GetDeviceId` function name.

### Fixed

- Improved error handling for shell commands.
- `xmltodict` is now a required dependency.
- Enhanced formatting of `logging` messages for better readability.
- Error in skip option for using a function file.

## [2.1.0] - 2024-10-20

### Added

- Added private key function.
- Option to skip automatic detection of private functions.
- Confirmed support for Widevine SDK 22.

### Changed

- Updated dependencies.
- Clarified details regarding optional dependencies.

### Fixed

- Extra argument in the `GetDeviceID` function.
- Incorrect handling of the display of unknown functions.

## [2.0.9] - 2024-09-25

### Added

- Added private key function.

### Changed

- Improved error handling related to file path issues during write operations.

## [2.0.8] - 2024-07-27

### Added

- Added compatibility with WSA (Windows Subsystem for Android).

### Changed

- Display location of `liboemcrypto.so` if detected (instead of the base address of the library).
- Simplified text for disabling the library.

### New Contributors

- [sn-o-w](https://github.com/sn-o-w)

## [2.0.7] - 2024-07-23

### Changed

- Improved library disabler display.
- Optimized data export.
- Removed unnecessary cast.

### Fixed

- Corrected disabled library address.
- Fixed multiple hooks in library disabler.
- Enhanced process enumeration for older Android versions.

### New Contributors

- [JohnDoe1964](https://github.com/JohnDoe1964)
- [Nineteen93](https://github.com/Nineteen93)

## [2.0.6] - 2024-07-12

### Changed

- Renamed the private key function.
- Updated the device ID function.
- Improved the deactivation message for a library.

### Fixed

- Prevented multiple function replacements during a single execution.

## [2.0.5] - 2024-07-08

### Added

- Added new private functions.
- Support for encrypted challenges in error messages.
- Dynamic disabling of `liboemcrypto.so` without using Magisk module.

### Changed

- Organized imports.
- Updated some messages.
- New verbosity level for CDM to prevent confusion.

### Fixed

- Detection of Widevine process.

## [2.0.4] - 2024-07-07

### Fixed

- Vendor now in list to maintain the order of items (python `set` issue).

## [2.0.3] - 2024-07-07

### Added

- Added support for private key function (SDK 35 x86_64).

### Changed

- Removed confusing `Malformed message` warning.

## [2.0.2] - 2024-07-07

### Added

- Vendor filtering based on device SDK.
- Improved device ID retrieval from challenges.

### Changed

- Clarified library arguments in documentation.
- Improve library vendor detection.

### Fixed

- Corrected Frida script encoding.
- Adjusted library arguments in documentation for clarity.
- Refined usage of function reference files.
- Updated support for OEM 18+ devices.

## [2.0.1] - 2024-07-06

### Added

- Added support for handling Frida server running errors.

### Changed

- Enhanced the relevance of pywidevine device (WVD) help documentation.

### Fixed

- Corrected the size of the private key.

## [2.0.0] - 2024-07-06

### Added

- Support for custom library names.
- Patch for the `GetCdmClientPropertySet` function to enforce unencrypted challenges on specific devices.
- Hook for the `getOemcryptoDeviceId` function for compatible devices.
- Native C API filter to prevent crashes during hooks.
- Handling of a binary challenge file to aid in resolving client IDs.
- Optional verbosity with output files if specified.
- Process watcher for library resolution, primarily for older devices.

### Changed

- Removed display of OEM and library version as they were often incorrect.
- New patch method (rewriting) to enforce unencrypted challenges.
- Widevine detection method now based on process names.
- Program no longer stops when the function file is not used when normally required.
- Full path display of the library (instead of parent only).
- Program is now formatted as a library.
- Simplified symbol address resolution.
- New, more relevant output structure.
- Private key size is no longer recalculated.

### Fixed

- Dynamic detection of the argument position for challenges.
- Corrected path for extracted files.
- Backward-compatible support for listing all processes via ADB.
- Fixed automatic mode device usage.
- Support for parsing errors related to CDM data.
- Frida session closure after process analysis.

## [1.1.0] - 2024-06-22

### Added

- Implemented a system to filter potentially crash-inducing native C function names.

### Changed

- Support for custom library names for new versions.

### Fixed

- Corrected directory structure creation for devices.

### New Contributors

- [azimabid00](https://github.com/azimabid00)

## [1.0.9] - 2024-06-02

### Added

- Added autostart error message.
- Added private key function (30/arm64-v8a).
- Added private key function (34/arm64-v8a)

### Changed

- Changed `.wvd` filename to original filename.
- Updated liboemcrypto-disabler link in docs.

### Fixed

- Changed default index for vendor 34.

## [1.0.8] - 2024-05-22

### Added

- Auto mode for opening the Bitmovin DRM player.
- Additional generation of the .wvd device.
- Added a function known from SDK 30 (arm64-v8a).

### Changed

- Renamed JS script.
- Updated dependency versions.
- Use pywidevine for the protobuf part.

### Fixed

- Support for int device names.
- Fixed dynamic auto mode.

### New Contributors

- [FoxRefire](https://github.com/FoxRefire)

## [1.0.7] - 2024-05-12

### Added

- Added a new function specific to VENDOR 15 based on insights from [videohelp](https://forum.videohelp.com/threads/414104-Impossible-situation-dumping-keys-using-virtual-Android#post2730673).
- Included a detailed process for extracting keys in offline mode.

## [1.0.6] - 2024-04-26

### Added

- Added `mksrc` script to manually improve Android shell interaction.

### Changed

- Removed example from the XML functions to prevent misunderstandings.
- Enhanced the Android shell functionality.

### Fixed

- Fixed encoding issues with ADB commands, addressing issue [#3](https://github.com/hyugogirubato/KeyDive/issues/3).

## [1.0.5] - 2024-04-08

### Added

- Added a function known from SDK 33 (arm64-v8a).

### Fixed

- Removed import analysis that was causing the JavaScript script to crash.

## [1.0.4] - 2024-04-06

### Added

- Added the `--force` option to use the default vendor, bypassing analysis.
- Progress information for analysis stages.
- Support for Android 14.
- Error message for using SDK version 34 and above without an XML functions file.
- Documentation links for certain error messages.

### Changed

- Switched from Frida to ADB for listing processes due to a [Frida issue](https://github.com/frida/frida/issues/1225#issuecomment-604181822).
- Optimized process search to improve performance.
- Improved error reporting when the Widevine process is not detected.

### Fixed

- Fixed compatibility with buggy `frida-server` versions by using direct PID attachment.
- Updated the script handling for non-standard version scenarios.

## [1.0.3] - 2024-04-01

### Added

- Environment check for ADB and automatic start if not running.
- Extraction function support for SDK version 34 and above.
- Simplified command-line argument processing.

### Changed

- Enhanced error handling to avoid Frida library hook errors.
- Transitioned from using symbols to functions for better clarity and efficiency.
- Display of loaded script for improved debugging and verification.

### Fixed

- Resolved target analysis issues, ensuring accurate process targeting.
- Corrected function argument count errors for more robust script execution.
- Fixed function selection by name to accurately identify and use the correct functions.

## [1.0.2] - 2024-03-31

### Added

- Added support for interpreting and using symbols, enhancing analysis capabilities.

### Changed

- Optimized analysis logic during the hook process for increased efficiency.
- Improved script generation process for more reliable and effective hooking.

## [1.0.1] - 2024-03-31

### Added

- Introduced support for non-standard version handling, accommodating a wider range of target applications.

## [1.0.0] - 2024-03-30

### Added

- Initial release of the project, laying the foundation for future enhancements and features.

[2.1.4]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.1.4
[2.1.3]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.1.3
[2.1.2]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.1.2
[2.1.1]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.1.1
[2.1.0]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.1.0
[2.0.9]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.0.9
[2.0.8]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.0.8
[2.0.7]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.0.7
[2.0.6]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.0.6
[2.0.5]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.0.5
[2.0.4]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.0.4
[2.0.3]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.0.3
[2.0.2]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.0.2
[2.0.1]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.0.1
[2.0.0]: https://github.com/hyugogirubato/KeyDive/releases/tag/v2.0.0
[1.1.0]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.1.0
[1.0.9]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.9
[1.0.8]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.8
[1.0.7]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.7
[1.0.6]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.6
[1.0.5]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.5
[1.0.4]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.4
[1.0.3]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.3
[1.0.2]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.2
[1.0.1]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.1
[1.0.0]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.0