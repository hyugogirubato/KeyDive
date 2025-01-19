import logging
import re
import shutil
import subprocess

from pathlib import Path

import frida
import requests

from frida.core import Device

# Suppress urllib3 warnings
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)


def shell(prompt: list) -> subprocess.CompletedProcess:
    """
    Executes a shell command and returns the result.

    Parameters:
        prompt (list): The command to execute as a list of strings.

    Returns:
        subprocess.CompletedProcess: The result containing return code, stdout, and stderr.
    """
    prompt = list(map(str, prompt))  # Ensure all command parts are strings
    # logging.getLogger("Shell").debug(" ".join(prompt))
    return subprocess.run(prompt, capture_output=True)  # Run the command and capture output


class ADB:
    """
    Class for managing interactions with the Android device via ADB.
    """

    def __init__(self, device: str = None, timeout: int = 5):
        """
        Initializes ADB connection to the device.

        Parameters:
            device (str, optional): Device ID to connect to, defaults to the first USB device.
            timeout (int, optional): Timeout for connection in seconds. Defaults to 5.

        Raises:
            EnvironmentError: If ADB is not found in the system path.
            Exception: If connection to the device fails.
        """
        self.logger = logging.getLogger(self.__class__.__name__)

        # Ensure ADB is available
        if not shutil.which("adb"):
            raise EnvironmentError(
                "ADB is not recognized as an environment variable. "
                "Ensure ADB is installed and refer to the documentation: "
                "https://github.com/hyugogirubato/KeyDive/blob/main/docs/PACKAGE.md#adb-android-debug-bridge"
            )

        # Start the ADB server if not already running
        sp = shell(['adb', 'start-server'])
        if sp.returncode != 0:
            self.logger.warning("ADB server startup failed (Error: %s)", sp.stdout.decode("utf-8").strip())

        # Connect to device (or default to the first USB device)
        try:
            self.device: Device = frida.get_device(id=device, timeout=timeout) if device else frida.get_usb_device(timeout=timeout)
            self.logger.info("Connected to device: %s (%s)", self.device.name, self.device.id)
        except Exception as e:
            self.logger.error("Failed to connect to device: %s", e)
            raise e

        self.prompt = ['adb', '-s', self.device.id, 'shell']

        # Retrieve and log device properties
        properties = self.device_properties()
        if properties:
            self.logger.info("SDK API: %s", properties.get("ro.build.version.sdk", "Unknown"))
            self.logger.info("ABI CPU: %s", properties.get("ro.product.cpu.abi", "Unknown"))
        else:
            self.logger.warning("No device properties retrieved")

    def device_properties(self) -> dict:
        """
        Retrieves system properties from the device.

        Returns:
            dict: A dictionary mapping property keys to their corresponding values.
        """
        # https://source.android.com/docs/core/architecture/configuration/add-system-properties?#shell-commands
        properties = {}

        # Execute the shell command to retrieve device properties
        sp = shell([*self.prompt, 'getprop'])
        if sp.returncode != 0:
            self.logger.error("Failed to retrieve device properties (Error: %s)", sp.stdout.decode("utf-8").strip())
            return properties

        # Parse the output and cast values accordingly
        for line in sp.stdout.decode("utf-8").splitlines():
            match = re.match(r"\[(.*?)\]: \[(.*?)\]", line)
            if match:
                key, value = match.groups()

                # Cast numeric and boolean values where appropriate
                if value.isdigit():
                    value = int(value)
                elif value.lower() in ("true", "false"):
                    value = value.lower() == "true"

                properties[key] = value

        return properties

    def list_applications(self, user: bool = True, system: bool = False) -> dict:
        """
        Lists installed applications on the device, with optional filters for user/system apps.

        Parameters:
            user (bool, optional): Include user-installed apps. Defaults to True.
            system (bool, optional): Include system apps. Defaults to False.

        Returns:
            dict: A dictionary of application packages and their file paths.
        """
        applications = {}

        # Validate input; return empty dict if no filter is set
        if not user and not system:
            return applications

        # Set the appropriate shell command based on user/system filters
        prompt = [*self.prompt, 'pm', 'list', 'packages', '-f']
        if user and not system:
            prompt.append("-3")
        elif not user and system:
            prompt.append("-s")

        # Execute the shell command to list applications
        sp = shell(prompt)
        if sp.returncode != 0:
            self.logger.error("Failed to retrieve app list (Error: %s)", sp.stdout.decode("utf-8").strip())
            return applications

        # Parse and add applications to the dictionary
        for line in sp.stdout.decode("utf-8").splitlines():
            try:
                path, package = line.strip().split(":", 1)[1].rsplit("=", 1)
                applications[package] = path
            except Exception as e:
                pass

        return applications

    def start_application(self, package: str) -> bool:
        """
        Starts an application by its package name.

        Parameters:
            package (str): The package name of the application.

        Returns:
            bool: True if the app was started successfully, False otherwise.
        """
        # Get package information using dumpsys
        sp = shell([*self.prompt, 'dumpsys', 'package', package])
        lines = sp.stdout.decode("utf-8").splitlines()

        # Remove empty lines to ensure backwards compatibility
        lines = [l.strip() for l in lines if l.strip()]

        # Look for MAIN activity to identify entry point
        for i, line in enumerate(lines):
            if "android.intent.action.MAIN" in line:
                match = re.search(fr"({package}/[^ ]+)", lines[i + 1])
                if match:
                    # Start the application by its main activity
                    main_activity = match.group()
                    sp = shell([*self.prompt, 'am', 'start', '-n', main_activity])
                    if sp.returncode == 0:
                        return True

                    self.logger.error("Failed to start app %s (Error: %s)", package, sp.stdout.decode("utf-8").strip())
                break

        self.logger.error("Package %s not found or no MAIN intent", package)
        return False

    def enumerate_processes(self) -> dict:
        """
        Lists running processes and maps process names to their PIDs.

        Returns:
            dict: Dictionary of process names and corresponding PIDs.
        """
        # https://github.com/frida/frida/issues/1225#issuecomment-604181822
        processes = {}

        # Attempt to get the list of processes using the 'ps -A' command
        prompt = [*self.prompt, 'ps']
        sp = shell([*prompt, '-A'])
        lines = sp.stdout.decode("utf-8").splitlines()

        # If the output has less than 10 lines, retry with a simpler 'ps' command
        if len(lines) < 10:
            sp = shell(prompt)
            if sp.returncode != 0:
                self.logger.error("Failed to execute ps command (Error: %s)", sp.stdout.decode("utf-8").strip())
                return processes
            lines = sp.stdout.decode("utf-8").splitlines()

        # Iterate through lines starting from the second line (skipping header)
        for line in lines[1:]:
            try:
                parts = line.split()  # USER,PID,PPID,VSZ,RSS,WCHAN,ADDR,S,NAME
                pid = int(parts[1])  # Extract PID
                name = " ".join(parts[8:]).strip()  # Extract process name

                # Handle cases where process name might be in brackets (e.g., kernel threads)
                name = name if name.startswith("[") else Path(name).name
                processes[name] = pid
            except Exception as e:
                pass

        return processes

    def install_application(self, path: Path = None, url: str = None) -> bool:
        """
        Installs an application on the device either from a local file or by downloading from a URL.

        Parameters:
            path (Path, optional): The local file path of the APK to install. Defaults to None.
            url (str, optional): The URL to download the APK from. Defaults to None.

        Returns:
            bool: True if the installation was successful, False otherwise.
        """
        # Prepare the shell command for installation
        prompt = [*self.prompt[:-1], 'install']

        # Install from a local file path if a valid path is provided
        if path and path.is_file():
            sp = shell([*prompt, path])  # Run the installation command with the local file path
            if sp.returncode == 0:
                return True
            self.logger.error("Installation failed for local path: %s (Error: %s)", path, sp.stdout.decode("utf-8").strip())

        # If URL is provided, attempt to download the APK and install it
        status = False
        if url:
            file = Path("tmp.apk")  # Temporary file to store the downloaded APK
            try:
                # Download the APK from the provided URL
                r = requests.get(url, headers={"Accept": "*/*", "User-Agent": "KeyDive/ADB"})
                r.raise_for_status()

                # Save the downloaded APK to a temporary file
                file.write_bytes(r.content)

                # Attempt installation from the downloaded APK
                status = self.install_application(path=file)
            except Exception as e:
                self.logger.error("Failed to download application from URL: %s (Error: %s)", url, e)
            file.unlink(missing_ok=True)  # Clean up the temporary file, even if there was an error

        return status

    def open_url(self, url: str) -> bool:
        """
        Opens a specified URL on the device.

        Parameters:
            url (str): The URL to be opened on the device.

        Returns:
            bool: True if the URL was successfully opened, False otherwise.
        """
        # Execute the shell command to open the URL using the Android 'am' (Activity Manager) command.
        sp = shell([*self.prompt, 'am', 'start', '-a', 'android.intent.action.VIEW', '-d', url])

        # Check the result of the command execution and log if there is an error
        if sp.returncode != 0:
            self.logger.error("URL open failed for: %s (Return: %s)", url, sp.stdout.decode("utf-8").strip())
            return False
        return True


__all__ = ("ADB",)
