import re

from typing import Union, Dict
from pathlib import Path
from zlib import crc32

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate
from asn1crypto.core import Integer

from keydive.drm import KEYBOX_MAX_CLEAR_API
from keydive.drm.device import Device, DeviceTypes
from keydive.drm.modules.client import get_client_info
from keydive.drm.modules.provisioning import Provisioning
from keydive.utils import unidec
from keydive.drm.protocol.license_pb2 import DrmCertificate, SignedDrmCertificate


def CryptoSession_ExtractSystemIdFromOemCert(cert: Certificate) -> int:
    """
    Extracts the Widevine System ID from an OEM X.509 certificate.

    The System ID is expected to be embedded as a custom extension within the certificate,
    identified by the `kWidevineSystemIdExtensionOid`. The extension contains an ASN.1-encoded
    integer, which this function decodes and returns.

    Args:
        cert (Certificate): An X.509 certificate expected to include the Widevine System ID
                            as a custom extension.

    Returns:
        int: The decoded Widevine System ID.

    Raises:
        ValueError: If the certificate does not contain the Widevine System ID extension.
    """
    kWidevineSystemIdExtensionOid = '1.3.6.1.4.1.11129.4.1.1'

    # Iterate through all extensions in the certificate to locate the custom Widevine System ID
    for ext in cert.extensions:
        # Match against the known OID for the Widevine System ID
        if ext.oid.dotted_string == kWidevineSystemIdExtensionOid:
            # The extension value contains a DER-encoded ASN.1 INTEGER
            # Decode it using asn1crypto's Integer class and return its integer representation
            return int(Integer.load(ext.value.value))

    # If no matching extension was found, raise a meaningful error
    raise ValueError('The certificate does not contain a Widevine System ID extension.')


def CryptoSession_GetSecurityLevel(data: Union[Certificate, str]) -> int:
    """
    Determines the Widevine security level (L1, L2, L3) from a certificate or a string.

    The security level is inferred by looking for specific substrings in either:
    - The subject of an X.509 certificate (e.g., containing "_L1_")
    - A plain string (e.g., containing "Level1")

    Args:
        data (Union[Certificate, str]): An X.509 certificate or a descriptive string.

    Returns:
        int: Security level as an integer (1 = L1, 2 = L2, 3 = L3).
             Defaults to level 3 if no recognizable pattern is found.
    """
    if isinstance(data, Certificate):
        # Extract the certificate's subject string in a standardized format
        data = data.subject.rfc4514_string()
        pattern = '_L{}_'
    else:
        pattern = 'Level{}'

    # Scan for each level from 1 to 3 in the input string using the appropriate pattern
    # If no match is found, assume the default security level is 3 (L3 - software-based)
    return next((l for l in range(1, 4) if pattern.format(l) in data), 3)


class Cdm(Provisioning):
    """
    Content Decryption Module (CDM) helper class for managing DRM provisioning
    and cryptographic assets such as keys, certificates, and client identity
    objects used in Widevine provisioning.

    This class supports initialization of internal caches and maps for managing
    OEM-provided certificates, keyboxes, and session-specific cryptographic data.
    """

    def __init__(self, sdk: int, disabler: bool = True):
        """
        Initializes the CDM instance with the specified SDK version and optional L1 disabler control.

        Sets up internal caches for keys, certificates, and client identity structures,
        which are typically used during Widevine provisioning workflows.

        Args:
            sdk (int): The Android SDK version (used to determine feature compatibility or restrictions).
            disabler (bool, optional): If True, applies logic related to L1 disabling behavior. Defaults to True.
        """
        super().__init__()
        self.sdk = sdk
        self.disabler = disabler

    def __resolve(self) -> Dict[int, dict]:
        """
        Consolidates and organizes device-related information into a structured dictionary.

        This method collects client IDs, private keys, OEM certificates, and keyboxes,
        grouping them by their system ID. It builds a comprehensive mapping containing:
        - The file system path derived from client info (company and model names),
        - The security level of the device (defaulting to level 3 if unknown),
        - Lists of associated device keys,
        - Linked keybox identifiers,
        - Certificates associated with each system ID.

        The collected information is primarily used for managing device security contexts
        such as DRM key provisioning and secure storage.

        Returns:
            dict[int, dict]: Mapping of system IDs to dictionaries with device information.

        Notes:
            - If no client info is available, the returned dictionary may be empty.
            - Items are updated in multiple passes: first by client ID, then by certificates, and finally by keyboxes.
            - Handles missing or incomplete data gracefully by skipping problematic entries.
        """
        items = {}
        path = None  # Will hold the base path for device records derived from client info

        # Process all client IDs and their associated private keys
        for key, client_id in self._client_id.items():
            client_info = get_client_info(client_id)

            # Parse DRM certificate from the client token protobuf data
            signed_drm_certificate = SignedDrmCertificate()
            signed_drm_certificate.ParseFromString(client_id.token)

            drm_certificate = DrmCertificate()
            drm_certificate.ParseFromString(signed_drm_certificate.drm_certificate)

            # Extract system ID and security level from client ID
            system_id = drm_certificate.system_id
            level = CryptoSession_GetSecurityLevel(client_info.get('oem_crypto_build_information') or '')

            # Derive a filesystem path from client info on the first iteration
            if not path:
                path = Path() / unidec(client_info['company_name']) / unidec(client_info['model_name'])

            # Attempt to find the private key matching the current client key
            private_key = next((v for k, v in self._private_key.items() if k == key), None)

            # Initialize or retrieve existing record for this system ID
            item = items.get(system_id, {
                'path': path,
                'level': level,  # Default security level
                'device': [],  # List of device keys associated
                'keybox': None,  # Associated keybox ID
                'certificate': None  # Associated certificate ID
            })

            # Add the client key to the device list if private key exists and not already added
            if private_key and key not in item['device']:
                item['device'].append(key)
            items[system_id] = item

        # If no path was established from client IDs, return early with what we have
        if not path:
            return items

        # Add OEM device certificates to the records
        for key, certs in self._certificate.items():
            intermediate_cert = certs[1]  # Typically the intermediate cert in chain

            # Extract system ID and security level from certificate
            system_id = CryptoSession_ExtractSystemIdFromOemCert(intermediate_cert)
            level = CryptoSession_GetSecurityLevel(intermediate_cert)

            # Find matching private key for this certificate key
            private_key = next((v for k, v in self._private_key.items() if k == key), None)

            # Initialize or retrieve record for this system ID
            item = items.get(system_id, {
                'path': path,
                'level': 3,
                'device': [],
                'keybox': None,
                'certificate': None
            })
            item['level'] = level

            # Assign the certificate key if private key exists and certificate is not already set
            if private_key and item['certificate'] != key:
                item['certificate'] = key
            items[system_id] = item

        # Add keybox entries to the records
        for key, keybox in self._keybox.items():
            try:
                # Verify keybox completeness by serializing (throws if invalid)
                keybox.SerializeToString()

                # Extract system ID from keybox info, if available
                keybox_info = keybox.keybox_info
                system_id = keybox_info.get('system_id')

                if system_id:
                    # Determine security level based on SDK version and keybox state
                    level = 1 if self.sdk > KEYBOX_MAX_CLEAR_API else 3

                    # Initialize or retrieve record for this system ID
                    item = items.get(system_id, {
                        'path': path,
                        'level': level,
                        'device': [],
                        'keybox': None,
                        'certificate': None
                    })
                else:
                    # If system ID is missing, pick the first level 3 record as fallback
                    system_id, item = next((k, v) for k, v in items.items() if v['level'] == 3)

                # Link the keybox to the record if not already assigned
                if item['keybox'] != key:
                    item['keybox'] = key
                items[system_id] = item
            except (AssertionError, StopIteration):
                # Skip incomplete or invalid keybox entries silently
                pass

        return items

    def export(self, wvd: bool = False, keybox: bool = False) -> Dict[Path, bytes]:
        """
        Export device credentials and optionally serialize them into .wvd and keybox formats.

        This function collects all device-related data such as client IDs, private keys,
        OEM certificates, and keyboxes, then prepares them for export by organizing
        them into files mapped by file system paths.

        Args:
            wvd (bool): If True, export device credentials in the pywidevine .wvd format,
                        enabling compatibility with the pywidevine toolset.
            keybox (bool): If True, include OEM certificates and keybox binary data in the export.

        Returns:
            dict[Path, bytes]: A dictionary mapping file paths (as Path objects) to their corresponding
                              binary content (as bytes), ready to be written to disk.

        Notes:
            - File paths are constructed hierarchically based on company name, model name, system ID, and modulus.
            - The WVD file names include company/model information and a CRC32 hash for uniqueness.
            - OEM certificates and keyboxes are included only if `keybox` is set to True.
            - Private keys are serialized in PEM format without encryption for direct use.
        """
        files = {}

        # Retrieve organized records containing device and certificate info
        records = self.__resolve()

        # Iterate through each device record grouped by system ID
        for system_id, record in records.items():
            # Base directory for this system ID
            parent = record['path'] / str(system_id)

            # Export client IDs and their private keys
            for modulus in record['device']:
                path = parent / str(modulus)[:10]
                client_id = self._client_id[modulus]
                private_key = self._private_key[modulus]

                # Serialize the client ID protobuf to bytes
                client_id_serialized = client_id.SerializeToString()

                # Serialize the private key to PEM format without encryption
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )

                # Save raw client ID and private key files
                files[path / 'client_id.bin'] = client_id_serialized
                files[path / 'private_key.pem'] = private_key_pem

                if wvd:
                    # https://github.com/devine-dl/pywidevine/blob/master/pywidevine/main.py#L211
                    # Build pywidevine Device object for WVD serialization
                    device = Device(
                        type_=DeviceTypes.ANDROID,
                        security_level=record['level'],
                        flags=None,
                        private_key=private_key,
                        client_id=client_id
                    )

                    # Serialize the device to pywidevine-compatible WVD format
                    device_serialized = device.dumps()

                    # Create a descriptive and unique filename based on device info and a CRC32 hash
                    client_info = get_client_info(client_id)
                    name = f"{client_info['company_name']} {client_info['model_name']}"
                    if client_info.get('widevine_cdm_version'):
                        name += f" {client_info['widevine_cdm_version']}"
                    # Append CRC32 hash of serialized device for uniqueness
                    name += f" {crc32(device_serialized).to_bytes(4, 'big').hex()}"
                    # Normalize name to lowercase with underscores
                    name = re.sub(r'\s+', '_', unidec(name).lower())

                    # Store the serialized WVD file with naming convention including system ID and security level
                    files[path / f'{name}_{system_id}_l{device.security_level}.wvd'] = device_serialized

            # Skip keybox and OEM certificate export if flag is False
            if not keybox:
                continue

            # Export keybox binary if available
            keybox = self._keybox.get(record['keybox'])
            if keybox:
                # Choose file suffix based on presence of system_id in keybox info
                suffix = 'bin' if keybox.keybox_info.get('system_id') else 'enc'
                # files[parent / f"keybox_{system_id}_l{record['level']}.{suffix}"] = keybox.SerializeToString()
                files[parent / f'keybox.{suffix}'] = keybox.SerializeToString()

            # Export OEM certificate chain in PEM format if available
            certificate = self._certificate.get(record['certificate'])
            if certificate:
                # files[parent / f"oem_certificate_{system_id}_l{record['level']}.pem"] = b''.join([
                files[parent / 'oem_certificate.pem'] = b''.join([
                    c.public_bytes(encoding=serialization.Encoding.PEM)
                    for c in certificate
                ])

                # Export OEM private key in PEM format
                private_key = self._private_key[record['certificate']]
                # files[parent / f"oem_private_key_{system_id}_l{record['level']}.pem"] = private_key.private_bytes(
                files[parent / 'oem_private_key.pem'] = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )

        return files


__all__ = ('Cdm',)
