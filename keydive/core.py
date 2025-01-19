import json
import logging
import re

from pathlib import Path

import frida
import xmltodict

from frida.core import Session, Script

from keydive.adb import ADB
from keydive.cdm import Cdm
from keydive.constants import OEM_CRYPTO_API, NATIVE_C_API, CDM_FUNCTION_API
from keydive.vendor import Vendor


class Core:
    """
    Core class for managing DRM operations and interactions with Android devices.
    """

    def __init__(self, adb: ADB, cdm: Cdm, functions: Path = None, skip: bool = False):
        """
        Initializes a Core instance.

        Parameters:
            adb (ADB): ADB instance for device communication.
            cdm (Cdm): Instance for handling DRM-related operations.
            functions (Path, optional): Path to Ghidra XML file for symbol extraction. Defaults to None.
            skip (bool, optional): Whether to skip predefined functions (e.g., OEM_CRYPTO_API). Defaults to False.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.running = True
        self.cdm = cdm
        self.adb = adb

        # Flag to skip predefined functions based on the vendor's API level
        # https://github.com/hyugogirubato/KeyDive/issues/38#issuecomment-2411932679
        self.skip = skip

        # Load the hook script with relevant data and prepare for injection
        self.functions = functions
        self.script = self.__prepare_hook_script()
        self.logger.info("Hook script prepared successfully")

    def __prepare_hook_script(self) -> str:
        """
        Prepares the hook script by injecting library-specific data.

        Returns:
            str: The finalized hook script content with placeholders replaced.
        """
        # Read the base JavaScript template file
        content = Path(__file__).with_name("keydive.js").read_text(encoding="utf-8")

        # Generate the list of symbols from the functions file
        symbols = self.__prepare_symbols(self.functions)

        # Define the placeholder replacements
        replacements = {
            "${OEM_CRYPTO_API}": json.dumps(list(OEM_CRYPTO_API)),
            "${NATIVE_C_API}": json.dumps(list(NATIVE_C_API)),
            "${SYMBOLS}": json.dumps(symbols),
            "${SKIP}": str(self.skip)
        }

        # Replace placeholders in the script content
        for placeholder, value in replacements.items():
            content = content.replace(placeholder, value, 1)

        return content

    def __prepare_symbols(self, path: Path) -> list:
        """
        Extracts relevant functions from a Ghidra XML file.

        Parameters:
            path (Path): Path to the Ghidra XML functions file.

        Returns:
            list: List of selected functions as dictionaries.

        Raises:
            FileNotFoundError: If the functions file is not found.
            ValueError: If functions extraction fails.
        """
        # Return an empty list if no path is provided
        if not path:
            return []

        try:
            # Parse the XML file and extract program data
            program = xmltodict.parse(path.read_bytes())["PROGRAM"]
            addr_base = int(program["@IMAGE_BASE"], 16)  # Base address for function addresses
            functions = program["FUNCTIONS"]["FUNCTION"]  # List of functions in the XML

            # Identify a target function from the predefined OEM_CRYPTO_API list (if not skipped)
            target = next((f["@NAME"] for f in functions if f["@NAME"] in OEM_CRYPTO_API and not self.skip), None)

            # Prepare a dictionary to store selected functions
            selected = {}
            for func in functions:
                name = func["@NAME"]  # Function name
                args = len(func.get("REGISTER_VAR", []))  # Number of arguments

                """
                Add the function if it matches specific criteria
                - Match the target function if identified
                - Match API keywords
                - Match unnamed functions with 6+ args
                """
                if name not in selected and (
                        name == target
                        or any(True if self.skip else keyword in name for keyword in CDM_FUNCTION_API)
                        or (not target and re.match(r"^[a-z]+$", name) and args >= 6)
                ):
                    selected[name] = {
                        "type": "function",
                        "name": name,
                        "address": hex(int(func["@ENTRY_POINT"], 16) - addr_base)  # Calculate relative address
                    }

            # Return the list of selected functions
            return list(selected.values())
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Functions file not found: {path}") from e
        except Exception as e:
            raise ValueError("Failed to extract functions from Ghidra XML file") from e

    def __process_message(self, message: dict, data: bytes) -> None:
        """
        Handles messages received from the Frida script.

        Parameters:
            message (dict): The message payload.
            data (bytes): The raw data associated with the message.
        """
        logger = logging.getLogger("Script")
        level = message.get("payload")

        if isinstance(level, int):
            # Log the message based on its severity level
            logger.log(level=level, msg=data.decode("utf-8"))
            if level in (logging.FATAL, logging.CRITICAL):
                self.running = False  # Stop the process on critical errors
        elif isinstance(level, dict) and "private_key" in level:
            # Set the private key in the DRM handler
            self.cdm.set_private_key(data=data, name=level["private_key"])
        elif level == "challenge":
            # Set the challenge data in the DRM handler
            self.cdm.set_challenge(data=data)
        elif level == "device_id":
            # Set the device ID in the DRM handler
            self.cdm.set_device_id(data)
        elif level == "keybox":
            # Set the keybox data in the DRM handler
            self.cdm.set_keybox(data)

    def hook_process(self, pid: int, vendor: Vendor, timeout: int = 0) -> bool:
        """
        Hooks into the specified process.

        Parameters:
            pid (int): The process ID to hook.
            vendor (Vendor): Instance of Vendor class representing the vendor information.
            timeout (int, optional): Timeout for attaching to the process. Defaults to 0.

        Returns:
            bool: True if the process was successfully hooked, otherwise False.
        """
        try:
            # Attach to the target process using the specified PID.
            # The 'persist_timeout' parameter ensures the session persists for the given duration.
            session: Session = self.adb.device.attach(pid, persist_timeout=timeout)
        except frida.ServerNotRunningError as e:
            # Handle the case where the Frida server is not running on the device.
            raise EnvironmentError("Frida server is not running") from e
        except Exception as e:
            # Log other exceptions and return False to indicate failure.
            self.logger.error(e)
            return False

        # Define a callback to handle when the process is destroyed.
        def __process_destroyed() -> None:
            session.detach()

        # Create a Frida script object using the prepared script content.
        script: Script = session.create_script(self.script)
        script.on("message", self.__process_message)
        script.on("destroyed", __process_destroyed)
        script.load()

        # Fetch a list of libraries loaded by the target process.
        libraries = script.exports_sync.getlibraries()
        library = next((l for l in libraries if re.match(vendor.pattern, l["name"])), None)

        if library:
            # Log information about the library if it is found.
            self.logger.info("Library: %s (%s)", library["name"], library["path"])

            # Retrieve and log the version of the Frida server.
            version = script.exports_sync.getversion()
            self.logger.debug(f"Server: %s", version)

            # Determine if the Frida server version is older than 16.6.0.
            code = tuple(map(int, version.split(".")))
            minimum = code[0] < 16 or (code == 16 and code[1] < 6)

            # Warn the user if certain conditions related to the functions option are met.
            if minimum and self.functions:
                self.logger.warning("The '--functions' option is deprecated starting from Frida 16.6.0")
            elif not minimum and vendor.oem < 18 and self.functions:
                self.logger.warning("The '--functions' option is deprecated for OEM API < 18")
            elif not minimum and vendor.oem > 17 and not self.functions:
                self.logger.warning("For OEM API > 17, specifying '--functions' is required. Refer to https://github.com/hyugogirubato/KeyDive/blob/main/docs/FUNCTIONS.md")

            return script.exports_sync.hooklibrary(library["name"])

        # Unload the script if the target library is not found.
        script.unload()
        self.logger.warning("Library not found: %s" % vendor.pattern)
        return False


__all__ = ("Core",)
