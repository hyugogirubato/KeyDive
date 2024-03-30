import logging
import re
import subprocess
from pathlib import Path

import frida
from _frida import Process
from frida.core import Device, Session, Script, RPCException
from Cryptodome.PublicKey import RSA

from extractor.license_protocol_pb2 import SignedMessage, LicenseRequest, ClientIdentification, DrmCertificate, SignedDrmCertificate
from extractor.vendor import Vendor

SCRIPT_PATH = Path(__file__).parent / 'script.js'


class Cdm:
    """
    Manages the capture and processing of DRM keys from a specified device using Frida to inject custom hooks.
    """

    def __init__(self, device: str = None):
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
        self.vendor = Vendor.from_sdk_api(self.sdk_api)
        self.script: str = self._prepare_hook_script()

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

    def _prepare_hook_script(self) -> str:
        """
        Prepares and returns the hook script with the SDK API version replaced.
        """
        script_content = SCRIPT_PATH.read_text(encoding='utf-8')
        return script_content.replace("'${SDK_API}'", str(self.sdk_api))

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

        try:
            library_info = script.exports_sync.getlibrary(self.vendor.library)
            self.logger.info('Library: %s (%s)', library_info['name'], library_info['path'])
            return script.exports_sync.hooklibrary(library_info['name'])
        except RPCException:
            return False
