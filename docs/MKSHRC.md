# mkshrc - Advanced Shell Environment for Android

`mkshrc` is a script designed to enhance the shell environment on Android devices. It sets up a customized environment with advanced command line tools and utilities, improving the overall user experience for shell interaction, especially for developers and power users who need more robust tools than what the default Android shell offers.

## Features

- **Environment Customization**: Sets HOSTNAME, USER, LOGNAME, and TMPDIR environment variables based on the device properties.
- **Architecture Detection**: Automatically detects the device's CPU architecture to download appropriate binaries.
- **BusyBox Integration**: Downloads and aliases BusyBox utilities, providing a wide range of standard Unix tools missing from standard Android shells.
- **Frida Server Management**: Simplifies the installation and management of Frida, a dynamic instrumentation toolkit, for non-rooted environments without Magisk.
- **Enhanced Command Aliases**: Includes aliases for color support in command output and common command shortcuts to improve usability.
- **Custom Commands**: Includes custom functions such as `tree`, `cfind`, `man`, and `sudo`, enhancing the functionality available in a typical Android shell.
- **Dynamic Frida Control**: Allows starting, stopping, and checking the status of the Frida server directly from the shell.

## Requirements

- **Root Access**: Needed for certain operations like setting certain environment variables or running commands as superuser.
- **BusyBox**: Required for most of the enhanced commands and utilities.
- **Internet Connection**: Needed to download necessary binaries like BusyBox and Frida.
- **ADB Setup**: ADB must be set up on your computer to push the script to your Android device.

## Installation

1. **Push the Script to Your Device**:
   Use ADB to push the `mkshrc` script to your device. Open your terminal or command prompt and run:
   ```bash
   adb push mkshrc /data/local/tmp/mkshrc
   ```
   
2. **Access Your Device via ADB**:
   Connect to your device shell using ADB:
   ```bash
   adb shell
   ```

3. **Gain Superuser Access**:
   If your device is rooted, you may need to switch to the superuser mode to allow the script to perform operations that require root privileges:
   ```bash
   su
   ```

4. **Navigate to the Script Location**:
   Change directory to where the script is located:
   ```bash
   cd /data/local/tmp
   ```

5. **Source the Script**:
   To apply the enhancements provided by `mkshrc`, you need to source it in the current shell session:
   ```bash
   source mkshrc
   ```

   **Note**: The `source` command needs to be run in each new shell session where you want the enhancements to be active.

## Additional Functions

- **`tree`**: Display a directory tree of the current or specified directory.
- **`cfind`**: Custom find command that outputs results with color support if available.
- **`man`**: Simulates the man command for built-in shell commands by showing command help.
- **`sudo`**: Function that tries to elevate privileges using `su` if not running as root.

## Usage Notes

## Usage Notes

Due to the nature of the default Android shell, typical initialization files like `.bashrc` or `.profile` do not exist. To ensure the enhancements and functions provided by `mkshrc` are available across all shell sessions, you need to manually source the script each time you open a new shell session. Here's how you can do it:

```bash
source /data/local/tmp/mkshrc
```

If you frequently use the shell on your Android device and want to automate the sourcing process, consider adding the source command to the shell's startup commands. This can often be achieved by modifying the shell's startup script if your device's shell environment allows it. For example, if using Termux or a similar terminal emulator app, you might be able to add the source command to its initialization script.

Another approach is to create a shortcut command that you can easily type upon starting a shell session. For instance:

```bash
alias startenv="source /data/local/tmp/mkshrc"
```

Then, whenever you start a new shell session, you simply type `startenv` to initialize your environment with `mkshrc` enhancements.

This setup script is designed to make the shell experience on Android more powerful and user-friendly, particularly for developers and power users who require advanced command-line tools and functionality. Enjoy the improved productivity and enhanced capabilities that `mkshrc` brings to your Android device!