import base64
import json
import logging
import re
from pathlib import Path
from typing import Union
from zlib import crc32

from Cryptodome.PublicKey import RSA
from Cryptodome.PublicKey.RSA import RsaKey
from pywidevine.device import Device, DeviceTypes
from pywidevine.license_protocol_pb2 import (SignedMessage, LicenseRequest, ClientIdentification, SignedDrmCertificate,
                                             DrmCertificate, EncryptedClientIdentification)
from unidecode import unidecode


def sanitize(path: Path) -> Path:
    """
    Sanitizes the given path by replacing invalid characters.

    Args:
        path (Path): The path to sanitize.

    Returns:
        Path: The sanitized path.
    """
    paths = [path.name, *[p.name for p in path.parents if p.name]][::-1]
    for i, p in enumerate(paths):
        p = p.replace('...', '').strip()
        p = re.sub(r'[<>:"/|?*\x00-\x1F]', '_', p)
        paths[i] = p

    return Path().joinpath(*paths)


class Cdm:
    """
    The Cdm class manages CDM-related operations, such as setting challenge data,
    extracting and storing private keys, and exporting device information.
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        # https://github.com/devine-dl/pywidevine
        self.client_id: dict[int, ClientIdentification] = {}
        self.private_key: dict[int, RsaKey] = {}

    def __client_info(self, client_id: ClientIdentification) -> dict:
        """
        Converts client identification information to a dictionary.

        Args:
            client_id (ClientIdentification): The client identification.

        Returns:
            dict: A dictionary of client information.
        """
        return {e.name: e.value for e in client_id.client_info}

    def __encrypted_client_info(self, encrypted_client_id: EncryptedClientIdentification) -> dict:
        """
        Converts encrypted client identification information to a dictionary.

        Args:
            encrypted_client_id (EncryptedClientIdentification): The encrypted client identification.

        Returns:
            dict: A dictionary of encrypted client information.
        """
        content = {
            'providerId': encrypted_client_id.provider_id,
            'serviceCertificateSerialNumber': encrypted_client_id.service_certificate_serial_number,
            'encryptedClientId': encrypted_client_id.encrypted_client_id,
            'encryptedClientIdIv': encrypted_client_id.encrypted_client_id_iv,
            'encryptedPrivacyKey': encrypted_client_id.encrypted_privacy_key
        }
        return {
            k: base64.b64encode(v).decode('utf-8') if isinstance(v, bytes) else v
            for k, v in content.items()
        }

    def set_challenge(self, data: Union[Path, bytes]) -> None:
        """
        Sets the challenge data by extracting device information.

        Args:
            data (Union[Path, bytes]): The challenge data as a file path or bytes.

        Raises:
            FileNotFoundError: If the provided file path does not exist.
        """
        if isinstance(data, Path):
            if not data.is_file():
                raise FileNotFoundError(data)
            data = data.read_bytes()

        try:
            signed_message = SignedMessage()
            signed_message.ParseFromString(data)

            license_request = LicenseRequest()
            license_request.ParseFromString(signed_message.msg)

            # https://integration.widevine.com/diagnostics
            encrypted_client_id: EncryptedClientIdentification = license_request.encrypted_client_id
            if encrypted_client_id.SerializeToString():
                self.logger.debug('Receive encrypted client id: \n\n%s\n', json.dumps(self.__encrypted_client_info(encrypted_client_id), indent=2))
                self.logger.warning('The client ID of the challenge is encrypted')
            else:
                client_id: ClientIdentification = license_request.client_id
                self.set_client_id(data=client_id)
        except Exception as e:
            self.logger.debug('Failed to set challenge data: %s', e)

    def set_private_key(self, data: bytes) -> None:
        """
        Sets the private key from the provided data.

        Args:
            data (bytes): The private key data.
        """
        try:
            key = RSA.import_key(data)
            if key.n not in self.private_key:
                self.logger.debug('Receive private key: \n\n%s\n', key.exportKey('PEM').decode('utf-8'))
            self.private_key[key.n] = key
        except Exception as e:
            self.logger.debug('Failed to set private key: %s', e)

    def set_client_id(self, data: Union[ClientIdentification, bytes]) -> None:
        """
        Sets the client ID from the provided data.

        Args:
            data (Union[ClientIdentification, bytes]): The client ID data.
        """
        try:
            if isinstance(data, ClientIdentification):
                client_id = data
            else:
                client_id = ClientIdentification()
                client_id.ParseFromString(data)

            signed_drm_certificate = SignedDrmCertificate()
            drm_certificate = DrmCertificate()

            signed_drm_certificate.ParseFromString(client_id.token)
            drm_certificate.ParseFromString(signed_drm_certificate.drm_certificate)

            public_key = drm_certificate.public_key
            key = RSA.importKey(public_key)

            if key.n not in self.client_id:
                self.logger.debug('Receive client id: \n\n%s\n', json.dumps(self.__client_info(client_id), indent=2))
            self.client_id[key.n] = client_id
        except Exception as e:
            self.logger.debug('Failed to set client ID: %s', e)

    def export(self, parent: Path, wvd: bool = False) -> bool:
        """
        Exports the client ID and private key to disk.

        Args:
            parent (Path): The parent directory to export the files to.
            wvd (bool): Whether to export WVD files.

        Returns:
            bool: True if any keys were exported, otherwise False.
        """
        keys = set(self.client_id.keys()) & set(self.private_key.keys())
        for k in keys:
            client_info = self.__client_info(self.client_id[k])
            # https://github.com/devine-dl/pywidevine/blob/master/pywidevine/main.py#L211
            device = Device(
                client_id=self.client_id[k].SerializeToString(),
                private_key=self.private_key[k].exportKey('PEM'),
                type_=DeviceTypes.ANDROID,
                security_level=3,
                flags=None
            )

            # https://github.com/hyugogirubato/KeyDive/issues/14#issuecomment-2146958022
            parent = sanitize(parent / client_info['company_name'] / client_info['model_name'] / str(device.system_id) / str(k)[:10])
            parent.mkdir(parents=True, exist_ok=True)

            path_id_bin = parent / 'client_id.bin'
            path_id_bin.write_bytes(data=device.client_id.SerializeToString())
            self.logger.info('Exported client ID: %s', path_id_bin)

            path_key_bin = parent / 'private_key.pem'
            path_key_bin.write_bytes(data=device.private_key.exportKey('PEM'))
            self.logger.info('Exported private key: %s', path_key_bin)

            if wvd:
                wvd_bin = device.dumps()

                name = f"{client_info['company_name']} {client_info['model_name']}"
                if client_info.get('widevine_cdm_version'):
                    name += f" {client_info['widevine_cdm_version']}"
                name += f" {crc32(wvd_bin).to_bytes(4, 'big').hex()}"
                name = unidecode(name.strip().lower().replace(' ', '_'))
                path_wvd = parent / f'{name}_{device.system_id}_l{device.security_level}.wvd'

                path_wvd.write_bytes(data=wvd_bin)
                self.logger.info('Exported WVD: %s', path_wvd)

        return len(keys) > 0


__all__ = ('Cdm',)
