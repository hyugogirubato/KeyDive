import logging
import re
import shutil

from subprocess import Popen, PIPE
from typing import Optional, List, Tuple
from pathlib import Path

import frida
import requests

from frida.core import Device

# Suppress urllib3 warnings
logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)


def shell(prompt: List[str]) -> Tuple[bool, str]:
    """
    Executes a shell command and returns its success status along with the output.

    Args:
        prompt (List[str]): A list representing the command and its arguments to be executed.

    Returns:
        Tuple[bool, str]: A tuple where the first value is True if the command failed,
                          and the second value is the decoded standard output (stdout) string.

    Note:
        The return status is inverted (True means failure), which should be considered
        when checking execution outcomes.
    """
    # Convert all arguments to strings in case any are not
    prompt = list(map(str, prompt))

    # Uncomment for debugging shell command execution
    # logging.getLogger('Shell').debug('Executing command: %s', ' '.join(prompt))
    try:
        # Start the process with stdout and stderr redirected to PIPE
        process = Popen(prompt, stdout=PIPE, stderr=PIPE, universal_newlines=True, encoding='utf-8')
        stdout, stderr = process.communicate()  # Waits for process to finish and collects output

        # Return True on failure (non-zero exit code), and the decoded stdout
        return process.wait() != 0, (stdout + stderr).strip()
    except KeyboardInterrupt:
        return False, ''


class Remote:
    """
    Handles ADB-based operations on Android devices using Frida.

    This class provides a set of utilities for interacting with Android devices connected via ADB,
    including retrieving system properties, managing applications, enumerating processes, and executing shell commands.
    """

    def __init__(self, serial: Optional[str] = None, timeout: int = 5):
        """
        Initializes and connects to an Android device using ADB and Frida.

        Args:
            serial (Optional[str]): Specific device serial number. If not provided,
                                    the first connected USB device will be used.
            timeout (int): Timeout (in seconds) for connecting to the device.

        Raises:
            EnvironmentError: If ADB is not found in the system PATH.
            Exception: If connection to the Android device fails.
            KeyError: If essential properties (e.g., SDK or ABI) cannot be retrieved.
        """
        self.logger = logging.getLogger('Remote')

        # Ensure ADB is installed and available in the system PATH
        if not shutil.which('adb'):
            raise EnvironmentError(
                'ADB is not recognized as an environment variable. '
                'Ensure ADB is installed and refer to the documentation: '
                'https://github.com/hyugogirubato/KeyDive/blob/main/docs/PACKAGE.md#adb-android-debug-bridge'
            )

        # Start the ADB server if it's not already running
        sp = shell(['adb', 'start-server'])
        if sp[0]:
            self.logger.warning('Unable to start ADB server (Error: %s)', sp[1])

        # Attempt to connect to the device (or default to the first USB device)
        try:
            self.socket: Device = frida.get_device(serial, timeout) if serial else frida.get_usb_device(timeout)
            self.logger.info('Connected to device: %s (%s)', self.socket.name, self.socket.id)
        except Exception as e:
            self.logger.critical('Could not connect to any device: %s', e)
            raise e

        # Construct the shell command prefix using the connected device ID
        self.__prefix = ['adb', '-s', self.socket.id, 'shell']

        # Retrieve system properties (e.g., SDK version, CPU ABI)
        properties = self.enumerate_properties()

        try:
            self.sdk = properties['ro.build.version.sdk']
            self.abi = properties['ro.product.cpu.abi']
        except Exception as e:
            raise KeyError('Failed to enumerate properties: %s', e)

        self.logger.info('SDK API: %s', self.sdk)
        self.logger.info('ABI CPU: %s', self.abi)

    def enumerate_properties(self) -> dict:
        """
        Retrieves Android system properties from the connected device via ADB.

        This method parses the output of the `getprop` shell command, casting values
        to appropriate Python types (e.g., integers or booleans) when possible. It is
        useful for gathering device configuration, build info, and environment metadata.

        Returns:
            dict: A dictionary of system properties where keys are property names and
                  values are their corresponding parsed values.
        """
        # https://source.android.com/docs/core/architecture/configuration/add-system-properties?#shell-commands
        properties = {}

        # Execute shell command to fetch all system properties using 'getprop'
        sp = shell([*self.__prefix, 'getprop', '|', 'strings'])
        if sp[0]:
            self.logger.error('Unable to retrieve system properties from the device (error: %s)', sp[1])
            return properties

        # Parse each line of the output and extract key-value pairs
        for line in sp[1].splitlines():
            match = re.match(r'\[(.*?)]: \[(.*?)]', line)
            if match:
                key, value = match.groups()

                # Try casting numeric strings to integers
                if value.isdigit():
                    value = int(value)

                # Try converting string booleans to Python boolean
                elif value.lower() in ('true', 'false'):
                    value = value.lower() == 'true'

                # Store the parsed key-value pair
                properties[key] = value

        return properties

    def enumerate_processes(self, pids: List[int] = None, names: List[str] = None) -> dict:
        """
        Retrieves a list of running processes from the connected Android device.

        This method uses ADB to run the `ps` command, processes the output, and filters
        the result by provided process IDs or names if specified. It gracefully handles
        variability in output format across Android versions.

        Args:
            pids (List[int], optional): A list of process IDs to filter against. Only
                processes with these PIDs will be included in the result.
            names (List[str], optional): A list of process names to filter against.
                Only processes with these names will be included in the result.

        Returns:
            dict: A dictionary mapping process IDs (int) to process names (str).

        Exception:
            Logs and returns an empty dictionary if the `ps` command fails to execute.
        """
        # https://github.com/frida/frida/issues/1225#issuecomment-604181822
        processes = {}

        # Attempt to get the list of processes using the 'ps -A' command
        prompt = [*self.__prefix, 'ps']
        sp = shell([*prompt, '-A'])
        lines = sp[1].splitlines()

        # Retry with simpler 'ps' if output seems too short (older Android or restricted shell)
        if len(lines) < 10:
            sp = shell(prompt)
            if sp[0]:
                self.logger.error('Failed to execute ps command (Error: %s)', sp[1])
                return processes
            lines = sp[1].splitlines()

        # Iterate through process list, skipping the header
        for line in lines[1:]:
            try:
                parts = line.split()  # USER,PID,PPID,VSZ,RSS,WCHAN,ADDR,S,NAME
                pid = int(parts[1])  # Extract the PID from the 2nd column
                name = ' '.join(parts[8:]).strip()  # Extract the process name (column 9+)

                # Handle cases where process name might be in brackets (e.g., kernel threads)
                name = name if name.startswith('[') else Path(name).name

                # Apply optional filters
                if (pids and pid not in pids) or (names and name not in names):
                    continue
                processes[pid] = name
            except Exception as e:
                # Suppress and skip lines that cannot be parsed correctly
                pass

        return processes

    def enumerate_applications(self, user: bool = True, system: bool = False) -> dict:
        """
        Lists installed Android applications on the connected device.

        This method uses ADB's package manager (pm) to list installed apps,
        with optional filtering for user-installed or system apps. It returns
        a mapping of package names to their corresponding APK file paths.

        Args:
            user (bool): If True, include user-installed applications (default: True).
            system (bool): If True, include system applications (default: False).

        Returns:
            dict: A dictionary where the keys are package names (str) and the values
                  are file paths (str) to their APKs.
        """
        applications = {}

        # Validate input to ensure at least one filter is active
        if not user and not system:
            return applications  # Nothing to return if both are disabled

        # Construct the command to retrieve package info
        prompt = [*self.__prefix, 'pm', 'list', 'packages', '-f']
        if user and not system:
            prompt.append('-3')  # Filter only user-installed apps
        elif not user and system:
            prompt.append('-s')  # Filter only system apps

        # Run the shell command to get the list of packages
        sp = shell(prompt)
        if sp[0]:
            self.logger.error('Unable to list installed apps (Error: %s)', sp[1])
            return applications

        # Parse command output line-by-line
        for line in sp[1].splitlines():
            try:
                # Example line format: package:/data/app/com.example.app-1/base.apk=com.example.app
                path, package = line.strip().split(':', 1)[1].rsplit('=', 1)
                applications[package] = path
            except Exception as e:
                # Skip lines that do not conform to expected structure
                pass

        return applications

    def open_url(self, url: str) -> bool:
        """
        Launches the specified URL on the connected Android device using the default browser.

        This uses Android's Activity Manager (am) to start an intent with the action
        `android.intent.action.VIEW`, which is the standard way to launch URLs.

        Args:
            url (str): The web address to open on the device (e.g., "https://example.com").

        Returns:
            bool: True if the command executed successfully and the intent was launched;
                  False if the shell command failed or was rejected by the system.
        """
        # Execute the shell command to open the URL using the Android 'am' (Activity Manager) command.
        sp = shell([*self.__prefix, 'am', 'start', '-a', 'android.intent.action.VIEW', '-d', url])
        if sp[0]:
            self.logger.error('Failed to open URL: %s (Error: %s)', url, sp[1])

        # Return True if command succeeded (sp[0] is 0), False otherwise
        return not sp[0]

    def install_application(self, path: Optional[Path] = None, url: Optional[str] = None) -> bool:
        """
        Installs an APK on the connected Android device from either a local file or a remote URL.

        Args:
            path (Optional[Path]): Path to the APK file stored locally.
            url (Optional[str]): Direct URL to download the APK from.

        Returns:
            bool: True if the application was successfully installed, False otherwise.
        """
        # Prepare the shell command for installation
        prompt = [*self.__prefix[:-1], 'install']

        # If a valid local path is provided, attempt to install the APK from that file
        if path and path.is_file():
            sp = shell([*prompt, path])  # Run the installation command with the local file path
            if not sp[0]:
                return True  # Installation succeeded
            self.logger.error('Could not install the APK from local path: %s (Error: %s)', path, sp[1])

        # If a URL is provided, try to download the APK and install it temporarily
        status = False
        if url:
            file = Path('tmp.apk')  # Temporary file to store the downloaded APK
            try:
                # Send a GET request to download the APK
                r = requests.request(
                    method='GET',
                    url=url,
                    headers={
                        'Accept': '*/*',
                        'User-Agent': 'KeyDive/ADB'
                    }
                )
                r.raise_for_status()

                # Write the downloaded content to a temporary APK file
                file.write_bytes(r.content)

                # Attempt to install the downloaded APK
                status = self.install_application(path=file)
            except Exception as e:
                self.logger.error('Failed to download or install APK from URL: %s (Error: %s)', url, e)
            finally:
                # Clean up the temporary file regardless of success or failure
                file.unlink(missing_ok=True)

        return status

    def start_application(self, package: str) -> bool:
        """
        Attempts to start an Android application using its package name by locating
        and invoking its main activity via the Activity Manager.

        Args:
            package (str): The package name of the application to start.

        Returns:
            bool: True if the application was successfully launched, False otherwise.
        """
        # Get package information using dumpsys
        sp = shell([*self.__prefix, 'dumpsys', 'package', package])
        if sp[0]:
            self.logger.error('Unable to retrieve package information (Error: %s)', sp[1])
            return False

        # Clean up output and filter out empty lines for consistency
        lines = sp[1].splitlines()
        lines = [l.strip() for l in lines if l.strip()]

        # Scan for the MAIN intent line and extract the associated activity
        for i, line in enumerate(lines):
            if 'android.intent.action.MAIN' in line:
                match = re.search(fr'({package}/[^ ]+)', lines[i + 1])
                if match:
                    # Format: com.example.package/.MainActivity
                    main_activity = match.group()

                    # Attempt to start the application using the resolved activity
                    sp = shell([*self.__prefix, 'am', 'start', '-n', main_activity])
                    if not sp[0]:
                        return True

                    self.logger.error('Failed to start app %s (Error: %s)', package, sp[1])
                break

        # TODO: adb shell monkey -p com.topjohnwu.magisk -c android.intent.category.LAUNCHER 1
        self.logger.error('No MAIN activity found for package "%s" or package not installed.', package)
        return False


__all__ = ('Remote',)
