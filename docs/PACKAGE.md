# Package

This document provides an overview of the external libraries, tools, and applications utilized within the KeyDive project. Each package plays a crucial role in enabling the project to efficiently extract Widevine L3 keys from Android devices for educational and research purposes.

## Tools and Libraries

### [rootAVD](https://gitlab.com/newbit/rootAVD)

A tool designed to root Android Virtual Devices (AVDs). It enables users to gain superuser privileges on their AVDs, essential for accessing and modifying system-level files and settings that are otherwise restricted.

### [DRM Info](https://apkcombo.app/drm-info/com.androidfung.drminfo)

An Android application providing detailed information about the device's Digital Rights Management (DRM) modules, including Widevine. Useful for verifying the DRM support level (L1, L2, L3) on the target device.

### [Root Explorer](https://apkcombo.com/root-explorer/com.speedsoftware.rootexplorer/)

A file manager for root users, offering access to the entire Android file system, including typically hidden or inaccessible data folders.

### [Firefox](https://apkcombo.com/fr/firefox/org.mozilla.firefox/)

A free and open-source web browser for Android, used for downloading files, testing DRM content playback, and other web-related tasks during research.

### [liboemcrypto Disabler](https://github.com/hzy132/liboemcryptodisabler)

A Magisk module that disables the OEMCrypto service, responsible for L1 DRM protection, forcing devices to fallback to L3 protection and enabling the extraction of L3 keys.

### [MagiskFrida](https://github.com/ViRb3/magisk-frida)

Allows Frida, a dynamic instrumentation toolkit, to run as a Magisk module, ideal for environments where adb access is limited or not possible.

### [Frida](https://github.com/frida/frida/releases)

A dynamic code instrumentation toolkit for injecting JavaScript or your own library into native apps on Android and other platforms.

### [ADB (Android Debug Bridge)](https://developer.android.com/tools/adb)

A command-line tool for communicating with a device, facilitating actions such as app installation and debugging, and providing access to a Unix shell for running various commands.

### [Ghidra](https://github.com/NationalSecurityAgency/ghidra)

A software reverse engineering (SRE) framework developed by the National Security Agency (NSA) that helps analyze malicious code and malware, and understand their functionality. Ghidra is essential for decompiling and analyzing the binaries and libraries involved in the DRM mechanisms, offering insights into how they operate and can be interacted with.

### [HTTP Toolkit](https://httptoolkit.com/)

An HTTP and HTTPS traffic debugging and testing tool that intercepts traffic between devices and servers. It provides a user-friendly interface to inspect, manipulate, and analyze HTTP requests and responses, crucial for monitoring DRM-related communications during research.

### Additional Tips

- **Native liboemcrypto Handling:** As of the latest updates to KeyDive, it manages liboemcrypto directly within the `keydive.js` script using the `disableLibrary` function. This eliminates the need for the liboemcrypto Disabler Magisk module in many cases, streamlining the setup process and reducing dependencies.
- **Optimize Frida-Server Usage:** To optimize the performance of Frida-Server, ensure that it is compatible with your device's architecture and that you have the appropriate permissions set on the device. Running it as a background process (`adb shell /data/local/tmp/frida-server -D`) ensures that it remains active during your research sessions without interruptions.

The combination of these tools provides a comprehensive toolkit for DRM research, allowing for the exploration of digital content protection mechanisms on Android devices. Each tool has been selected for its ability to contribute to the setup, execution, or support of the KeyDive project, enabling detailed analysis and extraction of digital rights management keys.