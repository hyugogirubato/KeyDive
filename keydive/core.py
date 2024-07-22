import json
import logging
import re
import subprocess

from pathlib import Path

import frida
import xmltodict

from frida.core import Device, Session, Script

from keydive.cdm import Cdm
from keydive.constants import OEM_CRYPTO_API, NATIVE_C_API, CDM_FUNCTION_API
from keydive.vendor import Vendor


class Core:
    """
    Core class for handling DRM operations and device interactions.
    """

    def __init__(self, cdm: Cdm, device: str = None, functions: Path = None):
        """
        Initializes a Core instance.

        Args:
            cdm (Cdm): Instance of Cdm for managing DRM related operations.
            device (str, optional): ID of the Android device to connect to via ADB. Defaults to None (uses USB device).
            functions (Path, optional): Path to Ghidra XML functions file for symbol extraction. Defaults to None.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.running = True
        self.cdm = cdm

        # Select device based on provided ID or default to the first USB device.
        self.device: Device = frida.get_device(id=device, timeout=5) if device else frida.get_usb_device(timeout=5)
        self.logger.info('Device: %s (%s)', self.device.name, self.device.id)

        # Obtain device properties
        properties = self.device_properties()
        self.logger.info('SDK API: %s', properties['ro.build.version.sdk'])
        self.logger.info('ABI CPU: %s', properties['ro.product.cpu.abi'])

        # Load the hook script
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
            '${SYMBOLS}': json.dumps(symbols)
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
            target = next((f['@NAME'] for f in functions if f['@NAME'] in OEM_CRYPTO_API), None)

            # Extract relevant functions
            selected = {}
            for func in functions:
                name = func['@NAME']
                args = len(func.get('REGISTER_VAR', []))

                # Add function if it matches specific criteria
                if name not in selected and (
                        name == target
                        or any(keyword in name for keyword in CDM_FUNCTION_API)
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

    def device_properties(self) -> dict:
        """
        Retrieves system properties from the connected device using ADB shell commands.

        Returns:
            dict: A dictionary of device properties.
        """
        # https://source.android.com/docs/core/architecture/configuration/add-system-properties?#shell-commands
        properties = {}
        sp = subprocess.run(['adb', '-s', str(self.device.id), 'shell', 'getprop'], capture_output=True)
        for line in sp.stdout.decode('utf-8').splitlines():
            match = re.match(r'\[(.*?)\]: \[(.*?)\]', line)
            if match:
                key, value = match.groups()
                # Attempt to cast numeric and boolean values to appropriate types
                try:
                    value = int(value)
                except ValueError:
                    if value.lower() in ('true', 'false'):
                        value = value.lower() == 'true'
                properties[key] = value
        return properties

    def enumerate_processes(self) -> dict:
        """
        Lists processes running on the device, returning a mapping of process names to PIDs.

        Returns:
            dict: A dictionary mapping process names to PIDs.
        """
        processes = {}

        # https://github.com/frida/frida/issues/1225#issuecomment-604181822
        prompt = ['adb', '-s', str(self.device.id), 'shell', 'ps']
        lines = subprocess.run([*prompt, '-A'], capture_output=True).stdout.decode('utf-8').strip().splitlines()
        if len(lines) <= 1:
            lines = subprocess.run(prompt, capture_output=True).stdout.decode('utf-8').strip().splitlines()
        # Iterate through lines starting from the second line (skipping header)
        for line in lines[1:]:
            try:
                line = line.split()  # USER,PID,PPID,VSZ,RSS,WCHAN,ADDR,S,NAME
                name = ' '.join(line[8:]).strip()
                name = name if name.startswith('[') else Path(name).name
                processes[name] = int(line[1])
            except Exception:
                pass

        return processes

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
        elif level == 'challenge':
            self.cdm.set_challenge(data=data)
        elif level == 'private_key':
            self.cdm.set_private_key(data=data)
        elif level == 'client_id':
            self.cdm.set_client_id(data=data)

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
            session: Session = self.device.attach(pid, persist_timeout=timeout)
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
