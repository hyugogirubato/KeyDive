import json
import logging
import re
import subprocess
from pathlib import Path

import xmltodict
import frida
from _frida import Process
from frida.core import Device, Session, Script
from Cryptodome.PublicKey import RSA

from extractor.license_protocol_pb2 import SignedMessage, LicenseRequest, ClientIdentification, DrmCertificate, SignedDrmCertificate
from extractor.vendor import Vendor

SCRIPT_PATH = Path(__file__).parent / 'script.js'


class Cdm:
    """
    Manages the capture and processing of DRM keys from a specified device using Frida to inject custom hooks.
    """
    OEM_CRYPTO_API = {
        # Mapping of function names across different API levels (obfuscated names may vary).
        'rnmsglvj', 'polorucp', 'kqzqahjq', 'pldrclfq', 'kgaitijd',
        'cwkfcplc', 'crhqcdet', 'ulns', 'dnvffnze', 'ygjiljer',
        'qbjxtubz', 'qkfrcjtw', 'rbhjspoh'
        # Add more as needed for different versions.
    }

    def __init__(self, device: str = None, functions: Path = None):
        self.logger = logging.getLogger('Cdm')
        self.running = True
        self.keys = {}
        self.device: Device = frida.get_device(id=device, timeout=5) if device else frida.get_usb_device(timeout=5)
        self.logger.info('Device: %s (%s)', self.device.name, self.device.id)

        # Fetch and log device properties
        self.properties = self._fetch_device_properties()
        self.sdk_api = self.properties['ro.build.version.sdk']
        self.logger.info('SDK API: %s', self.sdk_api)
        self.logger.info('ABI CPU: %s', self.properties['ro.product.cpu.abi'])

        # Determine vendor based on SDK API
        self.script = self._prepare_hook_script(functions)
        self.vendor = self._prepare_vendor()

    def _fetch_device_properties(self) -> dict:
        """
        Retrieves system properties from the connected device using ADB shell commands.
        """
        # https://source.android.com/docs/core/architecture/configuration/add-system-properties?#shell-commands
        properties = {}
        for line in subprocess.getoutput(f'adb -s "{self.device.id}" shell getprop').splitlines():
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

    def _prepare_hook_script(self, path: Path) -> str:
        """
        Prepares and returns the hook script by replacing placeholders with actual values, including
        SDK API version and selected functions from a given XML file.
        """
        selected = {}
        if path:
            # Verify symbols file path
            if not path.is_file():
                raise FileNotFoundError('Symbols file not found')

            try:
                # Parse the XML file
                program = xmltodict.parse(path.read_bytes())['PROGRAM']
                addr_base = int(program['@IMAGE_BASE'], 16)
                functions = program['FUNCTIONS']['FUNCTION']

                # Find a target function from a predefined list
                target = next((f'@NAME' for f in functions if f['@NAME'] in self.OEM_CRYPTO_API), None)

                # Extract relevant functions
                for func in functions:
                    name = func['@NAME']
                    params = func['ADDRESS_RANGE']
                    args = len(params) - 1 if isinstance(params, list) else 0

                    # Add function if it matches specific criteria
                    if (
                            name == target
                            or any(keyword in name for keyword in ['UsePrivacyMode', 'PrepareKeyRequest'])
                            or (not target and re.match(r'^[a-z]+$', name) and args >= 6)
                    ):
                        addr = int(func['@ENTRY_POINT'], 16) - addr_base
                        selected[addr] = {'name': name, 'address': hex(addr)}
            except Exception:
                raise ValueError('Failed to extract functions from Ghidra')

        # Read and prepare the hook script content
        content = SCRIPT_PATH.read_text(encoding='utf-8')
        # Replace placeholders with actual values
        content = content.replace('${SDK_API}', str(self.sdk_api))
        content = content.replace('${OEM_CRYPTO_API}', json.dumps(self.OEM_CRYPTO_API))
        content = content.replace('${SYMBOLS}', json.dumps(list(selected.values())))

        return content

    def _prepare_vendor(self) -> Vendor:
        """
        Prepares and selects the most compatible vendor version based on the device's processes.
        """
        details: [int] = []
        for p in self.device.enumerate_processes():
            for k, v in Vendor.SDK_VERSIONS.items():
                if p.name == v[2]:
                    session: Session = self.device.attach(p.name)
                    script: Script = session.create_script(self.script)
                    script.load()
                    if script.exports_sync.getlibrary(v[3]):
                        details.append(k)
                    session.detach()

        if not details:
            return Vendor.from_sdk_api(self.sdk_api)

        # Find the closest SDK version to the current one, preferring lower matches in case of a tie.
        sdk_api = min(details, key=lambda x: abs(x - self.sdk_api))
        if sdk_api == Vendor.SDK_MAX and self.sdk_api > Vendor.SDK_MAX:
            sdk_api = self.sdk_api
        elif sdk_api != self.sdk_api:
            self.logger.warning('Non-default Widevine version for SDK %s', sdk_api)

        return Vendor.from_sdk_api(sdk_api)

    def _process_message(self, message: dict, data: bytes) -> None:
        """
        Handles messages received from the Frida script.
        """
        logger = logging.getLogger('Script')
        level = message.get('payload')

        if isinstance(level, int):
            # Process logging messages from Frida script
            logger.log(level=level, msg=data.decode('utf-8'))
            if level in (logging.FATAL, logging.CRITICAL):
                self.running = False
        elif level == 'device_info':
            if data:
                self._extract_device_info(data)
            else:
                logger.critical('No data for device info, invalid argument position')
                self.running = False
        elif level == 'private_key':
            self._extract_private_key(data)

    def _extract_private_key(self, data: bytes) -> None:
        """
        Extracts and stores the private key from the provided data.
        """
        key = RSA.import_key(data)
        key_id = key.n
        if key_id not in self.keys:
            self.keys[key_id] = key
            self.logger.debug('Retrieved key: \n\n%s\n', key.exportKey('PEM').decode('utf-8'))

    def _extract_device_info(self, data: bytes) -> None:
        """
        Extracts device information and associated private keys, storing them to disk.
        """
        # https://github.com/devine-dl/pywidevine
        signed_message = SignedMessage()
        signed_message.ParseFromString(data)

        license_request = LicenseRequest()
        license_request.ParseFromString(signed_message.msg)

        client_id: ClientIdentification = license_request.client_id

        signed_drm_certificate = SignedDrmCertificate()
        drm_certificate = DrmCertificate()

        signed_drm_certificate.ParseFromString(client_id.token)
        drm_certificate.ParseFromString(signed_drm_certificate.drm_certificate)

        public_key = drm_certificate.public_key
        key = RSA.importKey(public_key)
        key_id = key.n

        private_key = self.keys.get(key_id)
        if private_key:
            path = Path() / 'device' / self.device.name / 'private_keys' / str(drm_certificate.system_id) / str(key_id)[:10]
            path.mkdir(parents=True, exist_ok=True)
            path_client_id = path / 'client_id.bin'
            path_private_key = path / 'private_key.pem'

            path_client_id.write_bytes(data=client_id.SerializeToString())
            path_private_key.write_bytes(data=private_key.exportKey('PEM'))

            self.logger.info('Dumped client ID: %s', path_client_id)
            self.logger.info('Dumped private key: %s', path_private_key)
            self.running = False
        else:
            self.logger.warning('Failed to intercept the private key')

    def hook_process(self, process: Process) -> bool:
        """
        Hooks into the specified process to intercept DRM keys.
        """
        session: Session = self.device.attach(process.name)
        script: Script = session.create_script(self.script)
        script.on('message', self._process_message)
        script.load()

        library_info = script.exports_sync.getlibrary(self.vendor.library)
        if library_info:
            self.logger.info('Library: %s (%s)', library_info['name'], library_info['path'])
            return script.exports_sync.hooklibrary(library_info['name'])
        return False
