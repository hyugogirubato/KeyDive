# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.6] - 2024-04-26

### Added

- Added `mksrc` script to manually improve Android shell interaction.
- Added `editor` script for a text editor within the Android shell.

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

[1.0.6]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.6
[1.0.5]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.5
[1.0.4]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.4
[1.0.3]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.3
[1.0.2]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.2
[1.0.1]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.1
[1.0.0]: https://github.com/hyugogirubato/KeyDive/releases/tag/v1.0.0