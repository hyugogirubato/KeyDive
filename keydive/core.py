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

        Args:
            adb (ADB): ADB instance for device communication.
            cdm (Cdm): Instance of Cdm for managing DRM related operations.
            functions (Path, optional): Path to Ghidra XML functions file for symbol extraction. Defaults to None.
            skip (bool, optional): Flag to determine whether to skip predefined functions (e.g., OEM_CRYPTO_API).
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.running = True
        self.cdm = cdm
        self.adb = adb

        # https://github.com/hyugogirubato/KeyDive/issues/38#issuecomment-2411932679
        # Flag to skip predefined functions based on the vendor's API level
        self.skip = skip

        # Load the hook script and prepare for injection
        self.functions = functions
        self.script = self.__prepare_hook_script()
        self.logger.info('Script loaded successfully')

    def __prepare_hook_script(self) -> str:
        """
        Prepares the hook script content by injecting the library-specific scripts.

        Returns:
            str: The prepared script content.
        """
        content = Path(__file__).with_name('keydive.js').read_text(encoding='utf-8')
        symbols = self.__prepare_symbols(self.functions)

        # Replace placeholders in script template
        replacements = {
            '${OEM_CRYPTO_API}': json.dumps(list(OEM_CRYPTO_API)),
            '${NATIVE_C_API}': json.dumps(list(NATIVE_C_API)),
            '${SYMBOLS}': json.dumps(symbols),
            '${SKIP}': str(self.skip)
        }

        for placeholder, value in replacements.items():
            content = content.replace(placeholder, value)

        return content

    def __prepare_symbols(self, path: Path) -> list:
        """
        Parses the provided XML functions file to select relevant functions.

        Args:
            path (Path): Path to Ghidra XML functions file.

        Returns:
            list: List of selected functions as dictionaries.

        Raises:
            FileNotFoundError: If the functions file is not found.
            ValueError: If functions extraction fails.
        """
        if not path:
            return []
        elif not path.is_file():
            raise FileNotFoundError('Functions file not found')

        try:
            program = xmltodict.parse(path.read_bytes())['PROGRAM']
            addr_base = int(program['@IMAGE_BASE'], 16)
            functions = program['FUNCTIONS']['FUNCTION']

            # Find a target function from a predefined list
            target = None if self.skip else next((f['@NAME'] for f in functions if f['@NAME'] in OEM_CRYPTO_API), None)

            # Extract relevant functions
            selected = {}
            for func in functions:
                name = func['@NAME']
                args = len(func.get('REGISTER_VAR', []))

                # Add function if it matches specific criteria
                if name not in selected and (
                        name == target
                        or any(None if self.skip else keyword in name for keyword in CDM_FUNCTION_API)
                        or (not target and re.match(r'^[a-z]+$', name) and args >= 6)
                ):
                    selected[name] = {
                        'type': 'function',
                        'name': name,
                        'address': hex(int(func['@ENTRY_POINT'], 16) - addr_base)
                    }
            return list(selected.values())
        except Exception as e:
            raise ValueError('Failed to extract functions from Ghidra') from e

    def __process_message(self, message: dict, data: bytes) -> None:
        """
        Handles messages received from the Frida script.

        Args:
            message (dict): The message payload.
            data (bytes): The raw data associated with the message.
        """
        logger = logging.getLogger('Script')
        level = message.get('payload')

        if isinstance(level, int):
            # Process logging messages from Frida script
            logger.log(level=level, msg=data.decode('utf-8'))
            if level in (logging.FATAL, logging.CRITICAL):
                self.running = False
        elif isinstance(level, dict) and 'private_key' in level:
            self.cdm.set_private_key(data=data, name=level['private_key'])
        elif level == 'challenge':
            self.cdm.set_challenge(data=data)
        elif level == 'device_id':
            self.cdm.set_device_id(data)
        elif level == 'keybox':
            self.cdm.set_keybox(data)

    def hook_process(self, pid: int, vendor: Vendor, timeout: int = 0) -> bool:
        """
        Hooks into the specified process.

        Args:
            pid (int): The process ID to hook.
            vendor (Vendor): Instance of Vendor class representing the vendor information.
            timeout (int, optional): Timeout for attaching to the process. Defaults to 0.

        Returns:
            bool: True if the process was successfully hooked, otherwise False.
        """
        try:
            session: Session = self.adb.device.attach(pid, persist_timeout=timeout)
        except frida.ServerNotRunningError as e:
            raise EnvironmentError('Frida server is not running') from e
        except Exception as e:
            self.logger.error(e)
            return False

        def __process_destroyed() -> None:
            session.detach()

        script: Script = session.create_script(self.script)
        script.on('message', self.__process_message)
        script.on('destroyed', __process_destroyed)
        script.load()

        library = script.exports_sync.getlibrary(vendor.name)
        if library:
            self.logger.info('Library: %s (%s)', library['name'], library['path'])

            # Check if Ghidra XML functions loaded
            if vendor.oem > 17 and not self.functions:
                self.logger.warning('For OEM API > 17, specifying "functions" is required, refer to https://github.com/hyugogirubato/KeyDive/blob/main/docs/FUNCTIONS.md')
            elif vendor.oem < 18 and self.functions:
                self.logger.warning('The "functions" attribute is deprecated for OEM API < 18')

            return script.exports_sync.hooklibrary(vendor.name)

        script.unload()
        self.logger.warning('Library not found: %s' % vendor.name)
        return False


__all__ = ('Core',)
