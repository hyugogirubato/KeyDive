import base64
import json
import logging

from typing import Union
from zlib import crc32
from unidecode import unidecode
from pathlib import Path

from pathvalidate import sanitize_filepath, sanitize_filename
from Cryptodome.PublicKey import RSA
from Cryptodome.PublicKey.RSA import RsaKey
from pywidevine.device import Device, DeviceTypes
from pywidevine.license_protocol_pb2 import (
    SignedMessage, LicenseRequest, ClientIdentification, SignedDrmCertificate, DrmCertificate,
    EncryptedClientIdentification)

from keydive.constants import OEM_CRYPTO_API
from keydive.keybox import Keybox


class Cdm:
    """
    The Cdm class manages CDM-related operations, such as setting challenge data,
    extracting and storing private keys, and exporting device information.
    """

    def __init__(self, keybox: bool = False):
        """
        Initializes the Cdm object, setting up a logger and containers for client IDs and private keys.

        Parameters:
            keybox (bool, optional): Initializes a Keybox instance for secure key management.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        # https://github.com/devine-dl/pywidevine
        self.client_id: dict[int, ClientIdentification] = {}
        self.private_key: dict[int, RsaKey] = {}

        # Optionally initialize a Keybox instance for secure key management if 'keybox' is True
        self.keybox = Keybox() if keybox else None

    @staticmethod
    def __client_info(client_id: ClientIdentification) -> dict:
        """
        Converts client identification information to a dictionary.

        Parameters:
            client_id (ClientIdentification): The client identification.

        Returns:
            dict: A dictionary of client information.
        """
        return {e.name: e.value for e in client_id.client_info}

    @staticmethod
    def __encrypted_client_info(encrypted_client_id: EncryptedClientIdentification) -> dict:
        """
        Converts encrypted client identification information to a dictionary.

        Parameters:
            encrypted_client_id (EncryptedClientIdentification): The encrypted client identification.

        Returns:
            dict: A dictionary of encrypted client information.
        """
        content = {
            "providerId": encrypted_client_id.provider_id,
            "serviceCertificateSerialNumber": encrypted_client_id.service_certificate_serial_number,
            "encryptedClientId": encrypted_client_id.encrypted_client_id,
            "encryptedClientIdIv": encrypted_client_id.encrypted_client_id_iv,
            "encryptedPrivacyKey": encrypted_client_id.encrypted_privacy_key
        }
        return {
            k: base64.b64encode(v).decode("utf-8") if isinstance(v, bytes) else v
            for k, v in content.items()
        }

    def set_challenge(self, data: Union[Path, bytes]) -> None:
        """
        Sets the challenge data by extracting device information and client ID.

        Parameters:
            data (Union[Path, bytes]): Challenge data as a file path or raw bytes.

        Raises:
            FileNotFoundError: If the file path doesn't exist.
            Exception: Logs any other exceptions that occur.
        """
        try:
            # Check if the data is a Path object, indicating it's a file path
            if isinstance(data, Path):
                data = data.read_bytes()

            # Parse the signed message from the data
            signed_message = SignedMessage()
            signed_message.ParseFromString(data)

            # Parse the license request from the signed message
            license_request = LicenseRequest()
            license_request.ParseFromString(signed_message.msg)

            # Extract the encrypted client ID, if available
            # https://integration.widevine.com/diagnostics
            encrypted_client_id: EncryptedClientIdentification = license_request.encrypted_client_id
            if encrypted_client_id.SerializeToString():
                # If encrypted, log the encrypted client ID and indicate encryption
                self.logger.info("Receive encrypted client id: \n\n%s\n", json.dumps(self.__encrypted_client_info(encrypted_client_id), indent=2))
                self.logger.warning("The client ID of the challenge is encrypted")
            else:
                # If unencrypted, extract and set the client ID
                client_id: ClientIdentification = license_request.client_id
                self.set_client_id(data=client_id)

        except FileNotFoundError as e:
            raise FileNotFoundError(f"Challenge file not found: {data}") from e
        except Exception as e:
            self.logger.debug("Failed to set challenge data: %s", e)

    def set_private_key(self, data: Union[Path, bytes], name: str = None) -> None:
        """
        Sets the private key from the provided data.

        Parameters:
            data (Union[Path, bytes]): The private key data, either as a file path or byte data.
            name (str, optional): Function name for verification against known functions.

        Raises:
            FileNotFoundError: If the file path doesn't exist.
            Exception: Logs any other exceptions that occur.
        """
        try:
            # Check if the data is a Path object, indicating it's a file path
            if isinstance(data, Path):
                data = data.read_bytes()

            # Import the private key using the RSA module
            key = RSA.import_key(data)

            # Log the private key if it's not already in the dictionary
            if key.n not in self.private_key:
                self.logger.info("Receive private key: \n\n%s\n", key.exportKey("PEM").decode("utf-8"))

                # If a function name is provided, verify it against known functions
                if name and name not in OEM_CRYPTO_API:
                    self.logger.warning("The function '%s' does not belong to the referenced functions. Communicate it to the developer to improve the tool.",name)

            # Store the private key in the dictionary, using the modulus (key.n) as the key
            self.private_key[key.n] = key
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Private key file not found: {data}") from e
        except Exception as e:
            self.logger.debug("Failed to set private key: %s", e)

    def set_client_id(self, data: Union[ClientIdentification, bytes]) -> None:
        """
        Sets the client ID from the provided data.

        Parameters:
            data (Union[ClientIdentification, bytes]): The client ID data.
        """
        try:
            # Check if the provided data is already a `ClientIdentification` object
            if isinstance(data, ClientIdentification):
                client_id = data
            else:
                # Deserialize the byte data into a `ClientIdentification` object
                client_id = ClientIdentification()
                client_id.ParseFromString(data)

            # Initialize objects for parsing the DRM certificate and signed certificate
            signed_drm_certificate = SignedDrmCertificate()
            drm_certificate = DrmCertificate()

            # Parse the signed DRM certificate from the client ID token
            signed_drm_certificate.ParseFromString(client_id.token)
            drm_certificate.ParseFromString(signed_drm_certificate.drm_certificate)

            # Extract the public key from the DRM certificate
            public_key = drm_certificate.public_key
            key = RSA.importKey(public_key)

            # Check if this public key has already been recorded and log the client ID info
            if key.n not in self.client_id:
                self.logger.info("Receive client id: \n\n%s\n", json.dumps(self.__client_info(client_id), indent=2))

            # Store the client ID in the client_id dictionary, using the public key modulus (`key.n`) as the key
            self.client_id[key.n] = client_id
        except Exception as e:
            self.logger.debug("Failed to set client ID: %s", e)

    def set_device_id(self, data: bytes) -> None:
        """
        Sets the device ID in the keybox.

        Parameters:
            data (bytes): The device ID to be stored in the keybox.
        """
        if self.keybox:
            self.keybox.set_device_id(data=data)

    def set_keybox(self, data: bytes) -> None:
        """
        Sets the keybox data.

        Parameters:
            data (bytes): The keybox data to be set.
        """
        if self.keybox:
            self.keybox.set_keybox(data=data)

    def export(self, parent: Path, wvd: bool = False) -> bool:
        """
        Exports client ID, private key, and optionally WVD files to disk.

        Parameters:
            parent (Path): Directory to export the files to.
            wvd (bool, optional): Whether to export WVD files. Defaults to False.

        Returns:
            bool: True if any keys were exported, otherwise False.
        """
        # Find the intersection of client IDs and private keys
        keys = self.client_id.keys() & self.private_key.keys()

        for k in keys:
            # Retrieve client information based on the client ID
            client_info = self.__client_info(self.client_id[k])

            # https://github.com/devine-dl/pywidevine/blob/master/pywidevine/main.py#L211
            device = Device(
                client_id=self.client_id[k].SerializeToString(),
                private_key=self.private_key[k].exportKey("PEM"),
                type_=DeviceTypes.ANDROID,
                security_level=3,
                flags=None
            )

            # Generate a sanitized file path for exporting the data
            # https://github.com/hyugogirubato/KeyDive/issues/14#issuecomment-2146958022
            parent = sanitize_filepath(parent / client_info["company_name"] / client_info["model_name"] / str(device.system_id) / str(k)[:10])
            parent.mkdir(parents=True, exist_ok=True)

            # Export the client ID to a binary file
            path_id_bin = parent / "client_id.bin"
            path_id_bin.write_bytes(data=device.client_id.SerializeToString())
            self.logger.info("Exported client ID: %s", path_id_bin)

            # Export the private key to a PEM file
            path_key_bin = parent / "private_key.pem"
            path_key_bin.write_bytes(data=device.private_key.exportKey("PEM"))
            self.logger.info("Exported private key: %s", path_key_bin)

            # If the WVD option is enabled, export the WVD file
            if wvd:
                # Serialize the device to WVD format
                wvd_bin = device.dumps()

                # Generate a unique name for the WVD file using client and device details
                name = f"{client_info['company_name']} {client_info['model_name']}"
                if client_info.get("widevine_cdm_version"):
                    name += f" {client_info['widevine_cdm_version']}"
                name += f" {crc32(wvd_bin).to_bytes(4, 'big').hex()}"
                name = unidecode(name.strip().lower().replace(" ", "_"))
                path_wvd = parent / sanitize_filename(f"{name}_{device.system_id}_l{device.security_level}.wvd")

                # Export the WVD file to disk
                path_wvd.write_bytes(data=wvd_bin)
                self.logger.info("Exported WVD: %s", path_wvd)

            # If keybox is available and hasn't been exported, issue a warning
            if self.keybox and not self.keybox.export(parent=parent.parent):
                self.logger.warning("The keybox has not been intercepted or decrypted")

        # Return True if any keys were exported, otherwise return False
        return len(keys) > 0


__all__ = ("Cdm",)
