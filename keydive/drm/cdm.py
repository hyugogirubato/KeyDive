import json
import logging
import re

from enum import Enum
from json.encoder import encode_basestring_ascii
from typing import Union, Dict, List, Optional
from pathlib import Path
from zlib import crc32

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509 import Certificate
from asn1crypto.core import Integer

from keydive.drm import OEM_CRYPTO_API, KEYBOX_MAX_CLEAR_API
from keydive.drm.device import Device, DeviceTypes
from keydive.drm.keybox import KeyBox
from keydive.utils import dumps, b64enc, b64dec, unidec
from keydive.drm.protocol.license_pb2 import (
    LicenseRequest, SignedMessage, ProvisioningResponse, SignedProvisioningMessage, ClientIdentification,
    EncryptedClientIdentification, DrmCertificate, SignedDrmCertificate
)

kWidevineSystemIdExtensionOid = '1.3.6.1.4.1.11129.4.1.1'


class OEMCrypto_ProvisioningMethod(Enum):
    """
    Enum representing different OEMCrypto provisioning methods.
    """
    ProvisioningError = 0   # Device cannot be provisioned.
    DrmCertificate = 1      # Device has baked-in DRM certificate (level 3 only).
    Keybox = 2              # Device has factory-installed unique keybox.
    OEMCertificate = 3      # Device has factory-installed OEM certificate.


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
    # Iterate through all extensions in the certificate to locate the custom Widevine System ID
    for ext in cert.extensions:
        # Match against the known OID for the Widevine System ID
        if ext.oid.dotted_string == kWidevineSystemIdExtensionOid:
            # The extension value contains a DER-encoded ASN.1 INTEGER
            # Decode it using asn1crypto's Integer class and return its integer representation
            return int(Integer.load(ext.value.value))

    # If no matching extension was found, raise a meaningful error
    raise ValueError('The certificate does not contain a Widevine System ID extension.')


def CryptoSession_GetSecurityLevel(cert: Certificate) -> Optional[int]:
    """
    Determines the Widevine security level (L1, L2, or L3) from the subject field
    of an X.509 certificate.

    The level is inferred by searching for substrings like "_L1_", "_L2_", or "_L3_" in
    the subject string, which typically reflects the provisioning level of the device
    (hardware-backed = L1, software-only = L3, etc).

    Args:
        cert (Certificate): An X.509 certificate whose subject may contain the security level marker.

    Returns:
        Optional[int]: The security level as an integer (1 = L1, 2 = L2, 3 = L3),
                       or None if no level marker is found in the subject.
    """
    # Extract the certificate's subject string in a standardized format
    subject = cert.subject.rfc4514_string()

    # kSecurityLevel (L1, L2, L3, Unknown)
    # Check for known security level markers in the subject string
    return next((level for level in range(1, 4) if f'_L{level}_' in subject), None)


class Cdm:
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
        self.logger = logging.getLogger('Cdm')
        self._sdk = sdk
        self._disabler = disabler

        self._device_aes_key: List[bytes] = []
        self._keybox: Dict[bytes, KeyBox] = {}  # stable_id -> keybox

        self._client_id: Dict[int, ClientIdentification] = {}  # public_key.n -> client_id
        self._certificate: Dict[int, List[Certificate]] = {}  # public_key.n -> oem_certificate
        self._private_key: Dict[int, RSAPrivateKey] = {}  # public_key.n -> private_key

        # Cached ClientIdentification instance representing the device’s current provisioning context
        # This may be reused across multiple requests to avoid re-parsing
        self._provisioning: Optional[ClientIdentification] = None

    @staticmethod
    def __client_info(client_id: ClientIdentification) -> dict:
        """
        Converts a ClientIdentification object into a dictionary containing its core information,
        and optionally includes capability details if logging is set to DEBUG level.

        This is useful for structured logging or inspection of client identity during
        the provisioning process.

        Args:
            client_id (ClientIdentification): The client identification object that contains
                basic client info and optional client capability fields.

        Returns:
            dict: A dictionary of client info fields. If logging is set to DEBUG,
                  a 'capabilities' key is included with detailed capability values.
        """
        # Extract base client_info fields and store them in a dictionary
        infos = {e.name: e.value for e in client_id.client_info}

        # Check the global logger level; only include capabilities in DEBUG mode
        level = logging.getLogger().getEffectiveLevel()
        if level != logging.DEBUG:
            return infos  # Return only core info if not debugging

        capabilities = {}
        # Iterate over all explicitly set fields in client_capabilities
        for field, value in client_id.client_capabilities.ListFields():
            # Handle fields of enum type
            if field.type == field.TYPE_ENUM:
                if field.label == field.LABEL_REPEATED:
                    # Convert each enum value (integer) to its named representation
                    value = [field.enum_type.values_by_number[v].name for v in value]
                else:
                    # Convert single enum value to its name
                    value = field.enum_type.values_by_number[value].name

            # Add the field and its (possibly transformed) value to the capabilities dictionary
            capabilities[field.name] = value

        # Merge basic client info and capabilities into a single dictionary and return
        return {**infos, 'capabilities': capabilities}

    @staticmethod
    def __client_generic(client_id: ClientIdentification) -> ClientIdentification:
        """
        Produces a simplified version of a ClientIdentification object by removing
        select non-essential fields from the `client_info` list. This is useful
        when generating a generic client profile that omits sensitive or dynamic data,
        such as application-specific metadata.

        Args:
            client_id (ClientIdentification): The original, full client identification
                object containing metadata and capabilities.

        Returns:
            ClientIdentification: A new instance with reduced client_info fields, preserving
            core identity and capabilities but omitting values like app name, origin, and cert hash.

        Notes:
            The fields being removed are typically:
            - 'application_name': Identifies the calling app; often dynamic or sensitive.
            - 'origin': Source domain or app origin; may vary per request or client.
            - 'package_certificate_hash_bytes': May be tied to APK signing identity.

        This function ensures that the returned object retains its structure and utility
        while discarding non-critical identifiers that might affect reproducibility or
        comparability across sessions.
        """
        # Define the fields that are considered dynamic or non-essential for generic use
        excluded_fields = {'application_name', 'origin', 'package_certificate_hash_bytes'}

        # Create a filtered list excluding the above fields from client_info
        filtered_client_info = [
            info for info in client_id.client_info
            if info.name not in excluded_fields
        ]

        # Return a new ClientIdentification object with the cleaned client_info list
        return ClientIdentification(
            type=client_id.type,
            token=client_id.token,
            client_info=filtered_client_info,
            # provider_client_token=client_id.provider_client_token,
            # license_counter=client_id.license_counter,
            client_capabilities=client_id.client_capabilities,
            # vmp_data=client_id.vmp_data,
            # device_credentials=client_id.device_credentials
        )

    def set_challenge(self, data: Union[bytes, List[Path]]) -> None:
        """
        Parses a Widevine license challenge to extract and register client identification data.

        This method accepts either raw protobuf bytes representing a SignedMessage or a list
        of file paths containing such data. It supports recursive processing of multiple
        challenge files and handles both encrypted and unencrypted client IDs.

        Args:
            data (Union[bytes, List[Path]]):
                - Raw protobuf data as bytes representing a SignedMessage, or
                - A list of Path objects pointing to files containing SignedMessage data.
        """
        # If input is a list of file paths, process each file individually
        if isinstance(data, list):
            for path in data:
                try:
                    # Read file content as bytes and recursively process it
                    self.set_challenge(data=path.read_bytes())
                except Exception as e:
                    self.logger.error('Could not load challenge from file %s: %s', path, e)

        # Proceed only if data is raw bytes after potential recursive calls
        if not isinstance(data, bytes):
            return

        # https://integration.widevine.com/diagnostics
        try:
            # Parse the SignedMessage protobuf from raw data
            signed_message = SignedMessage()
            signed_message.ParseFromString(data)

            # Extract and parse the embedded LicenseRequest message
            license_request = LicenseRequest()
            license_request.ParseFromString(signed_message.msg)

            # Attempt to extract the encrypted client ID (if present)
            encrypted_client_id: EncryptedClientIdentification = license_request.encrypted_client_id
            if encrypted_client_id.SerializeToString():
                # Encrypted client ID found - log its details for debugging
                """
                self.logger.info(
                    'Received encrypted client ID: \n\n%s\n',
                    dumps({
                        f.name: v for f, v in encrypted_client_id.ListFields()
                    }, beauty=True)
                )
                """
                self.logger.warning('The client ID in this challenge is encrypted and cannot be processed directly.')
            else:
                # Unencrypted client ID is available - register it immediately
                self.set_client_id(data=license_request.client_id)
        except Exception as e:
            # Log any parsing errors at debug level to avoid cluttering standard logs
            self.logger.debug('Unable to register challenge data: %s', e)

    def set_client_id(self, data: Union[ClientIdentification, bytes]) -> None:
        """
        Loads and registers a client ID from either a parsed ClientIdentification object
        or raw protobuf bytes. Handles different client ID token types, such as DRM device
        certificates, keyboxes, and OEM device certificates.

        Args:
            data (Union[ClientIdentification, bytes]):
                Either a ClientIdentification protobuf object or raw protobuf bytes representing it.

        Raises:
            ValueError: If the client type is unsupported or certificate chain length is invalid.
        """
        try:
            # If already a parsed ClientIdentification object, use it directly
            if isinstance(data, ClientIdentification):
                client_id = data
            else:
                # Otherwise, parse the protobuf bytes into a ClientIdentification object
                client_id = ClientIdentification()
                client_id.ParseFromString(data)

            # Cache this client ID for provisioning context usage elsewhere
            self._provisioning = client_id

            # Process based on the token type of the client ID
            if client_id.type == ClientIdentification.TokenType.DRM_DEVICE_CERTIFICATE:
                # Clean unnecessary fields to simplify the client representation
                client_id = self.__client_generic(client_id)

                # Initialize protobuf objects to parse DRM certificates
                signed_drm_certificate = SignedDrmCertificate()
                drm_certificate = DrmCertificate()

                # Parse signed DRM certificate from client token
                signed_drm_certificate.ParseFromString(client_id.token)
                drm_certificate.ParseFromString(signed_drm_certificate.drm_certificate)

                # Load the public key from the DRM certificate (DER format)
                public_key = serialization.load_der_public_key(
                    data=drm_certificate.public_key,
                    backend=default_backend()
                )

                # Extract the RSA modulus as a unique client identifier
                modulus = public_key.public_numbers().n

                # Register new or changed client IDs keyed by modulus
                if modulus not in self._client_id or self._client_id[modulus] != client_id:
                    self.logger.info(
                        'Received client ID: \n\n%s\n',
                        dumps(self.__client_info(client_id), beauty=True)
                    )
                    self._client_id[modulus] = client_id
            elif client_id.type == ClientIdentification.TokenType.KEYBOX:
                # For keybox-based provisioning, register the token as the device ID
                self.set_device_id(client_id.token)
            elif client_id.type == ClientIdentification.TokenType.OEM_DEVICE_CERTIFICATE:
                # Load the certificate chain from DER-encoded PKCS7 token
                certs = pkcs7.load_der_pkcs7_certificates(data=client_id.token)

                # Validate the certificate chain length (expect exactly two certs)
                if len(certs) != 2:
                    raise ValueError(f'Invalid certificate chain length: expected 2, got {len(certs)}')

                # Extract RSA modulus from the intermediate certificate's public key
                modulus = certs[1].public_key().public_numbers().n

                # Register new or updated OEM certificates keyed by modulus
                if modulus not in self._certificate:
                    # openssl asn1parse -inform der -in oem_certificate.der
                    # openssl pkcs7 -inform der -in oem_certificate.der -print_certs -out output.pem
                    self.logger.info(
                        'Received OEM certificate: \n\n%s\n',
                        dumps([{
                            'subject': c.subject.rfc4514_string(),
                            'issuer': c.subject.rfc4514_string(),
                            'serial_number': c.serial_number,
                            'valid_from': c.not_valid_before_utc,
                            'valid_until': c.not_valid_after_utc
                        } for c in certs], beauty=True)
                    )
                    self._certificate[modulus] = certs
            else:
                raise ValueError(f'Unsupported client type: {client_id.type}')
        except Exception as e:
            # Log exceptions at debug level to keep regular logs clean
            self.logger.debug('Unable to register client ID: %s', e)

    def set_private_key(self, data: Union[bytes, List[Path]], name: Optional[str] = None) -> None:
        """
        Registers an OEM private RSA key used for Widevine decryption.
        Supports loading from raw PEM/DER bytes or multiple files containing keys.

        Args:
            data (Union[bytes, List[Path]]):
                Raw private key bytes in PEM or DER format, or a list of file paths to key files.
            name (Optional[str]):
                Optional identifier for the function or implementation related to this key.
        """
        # If input is a list of file paths, process each file recursively
        if isinstance(data, list):
            for path in data:
                try:
                    # Read the file's bytes and call this method again with raw bytes
                    self.set_private_key(data=path.read_bytes(), name=None)
                except Exception as e:
                    self.logger.error('Could not load RSA key from file %s: %s', path, e)

        # If the input is not bytes at this point, do nothing (invalid input)
        if not isinstance(data, bytes):
            return

        try:
            # Attempt to load the private key assuming PEM (Base64 encoded) format first
            try:
                private_key = serialization.load_pem_private_key(
                    data=data,
                    password=None,
                    backend=default_backend()
                )
            except ValueError:
                # If PEM loading fails, try DER (binary) format instead
                private_key = serialization.load_der_private_key(
                    data=data,
                    password=None,
                    backend=default_backend()
                )

            # Extract the RSA modulus (n) from the public key for unique identification
            modulus = private_key.public_key().public_numbers().n

            # Only register the key if this modulus is not already present
            if modulus not in self._private_key:
                self.logger.info(
                    'Received RSA private key: \n\n%s\n',
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    ).decode('utf-8'))
                self._private_key[modulus] = private_key

                # If a name is provided but unrecognized, log a warning for developer attention
                if name and name not in OEM_CRYPTO_API:
                    self.logger.warning(
                        'Unrecognized function name "%s". Please notify the developers to improve this tool.',
                        name
                    )
        except Exception as e:
            # Log loading failures at debug level to avoid cluttering normal logs
            self.logger.debug('Unable to register RSA private key: %s', e)

    def set_keybox(self, data: bytes) -> None:
        """
        Parses and registers a KeyBox structure used for device provisioning.
        The KeyBox contains cryptographic and device-specific data necessary for DRM.

        Args:
            data (bytes): Raw binary data containing the serialized KeyBox protobuf.
        """
        try:
            # Initialize a new KeyBox instance and parse the protobuf data from bytes
            keybox = KeyBox()
            keybox.ParseFromString(data)  # Parse the raw data into the KeyBox object

            # Check if the stable_id is either not present in the dictionary,
            # or if the existing KeyBox with this stable_id does not have a device_id set.
            if keybox.stable_id not in self._keybox or not self._keybox[keybox.stable_id].device_id:
                # Extract keybox metadata info for logging
                infos = keybox.keybox_info
                # Determine label based on presence of system_id in the keybox info
                label = 'keybox' if infos.get('system_id') else 'encrypted keybox'

                self.logger.info(
                    'Received %s: \n\n%s\n',
                    label, dumps(infos, beauty=True)
                )

                # Store or update the internal keybox dictionary using stable_id as the key
                self._keybox[keybox.stable_id] = keybox
        except Exception as e:
            # Log failure details at debug level to avoid noise in normal logs
            self.logger.debug('Unable to register KeyBox data: %s', e)

    def set_stable_id(self, data: bytes) -> None:
        """
        Registers or updates the stable ID for a KeyBox instance.
        The stable ID uniquely identifies a device and acts as the key
        in the internal KeyBox dictionary.

        Args:
            data (bytes): Stable device identifier as raw bytes,
                          used as the unique key to identify the keybox.

        Notes:
            - If a KeyBox already exists with an empty stable_id, it will be reused;
              otherwise, a new KeyBox instance is created.
        """
        try:
            # Only proceed if this stable ID is not already present in the keybox dictionary
            if data not in self._keybox:
                # Retrieve existing KeyBox with empty stable_id or create a new instance
                keybox = self._keybox.get(b'', KeyBox())

                # Assign the provided stable ID to this KeyBox instance
                keybox.stable_id = data

                # Log the stable ID in a human-readable ASCII-safe format
                self.logger.info(
                    'Received stable ID: \n\n%s\n',
                    encode_basestring_ascii(keybox.stable_id.decode('utf-8')))

                # Store or update the KeyBox in the dictionary with stable_id as the key
                self._keybox[keybox.stable_id] = keybox
        except Exception as e:
            # Log exception details at debug level without interrupting flow
            self.logger.debug('Unable to register KeyBox stable ID: %s', e)

    def set_device_id(self, data: bytes) -> None:
        """
        Registers or updates the device ID within a KeyBox instance.
        The device ID is used to uniquely identify a device for cryptographic
        provisioning and licensing purposes.

        Args:
            data (bytes): Raw device identifier bytes, used to associate a device ID
                          with a KeyBox object.

        Notes:
            - If the device ID is already associated with a KeyBox, this method does nothing.
            - If a KeyBox without a device ID exists, it will be reused; otherwise,
              a new KeyBox instance will be created.
        """
        try:
            # Check if this device ID is already registered in any existing KeyBox
            if not any(k for k in self._keybox.values() if k.device_id == data):
                # Find a KeyBox without a device ID to reuse, or create a new KeyBox
                keybox = next((k for k in self._keybox.values() if not k.device_id), KeyBox())

                # Assign the provided device ID to the KeyBox
                keybox.device_id = data

                # Retrieve device-related metadata for logging purposes
                infos = keybox.device_info
                # Choose label based on whether a system_id is present in metadata
                label = 'device ID' if infos.get('system_id') else 'encrypted device ID'
                self.logger.info(
                    'Received %s: \n\n%s\n',
                    label, dumps(infos, beauty=True) if infos else b64enc(keybox.device_id))

                # Store or update the KeyBox in the dictionary using its stable_id as the key
                self._keybox[keybox.stable_id] = keybox
        except Exception as e:
            # Log exceptions with context at debug level without raising
            self.logger.debug('Unable to register KeyBox device ID: %s', e)

    def set_device_aes_key(self, data: Union[bytes, List[str]]) -> None:
        """
        Imports and stores AES device keys used for decrypting protected content.

        This method accepts either a single AES key as raw bytes or a list of strings
        representing AES keys in various formats, including:
        - Hexadecimal strings
        - Base64-encoded strings (standard or URL-safe)
        - File paths pointing to binary key files

        Args:
            data (bytes or List[str]): The AES key(s) to import. Either a single
                                      16-byte AES key (bytes) or a list of strings
                                      representing keys in different encoded forms or file paths.

        Notes:
            - Only keys exactly 16 bytes in length are accepted as valid AES keys.
            - If a list of strings is given, the method tries each parser (hex, base64, file)
              until one succeeds for each entry.
        """
        if isinstance(data, list):
            # Iterate over all string inputs, attempt parsing with multiple strategies
            for value in data:
                for parser in (bytes.fromhex, b64dec, lambda v: Path(v).read_bytes()):
                    try:
                        # Recursively call with successfully decoded raw bytes
                        self.set_device_aes_key(parser(value))
                        break  # Exit parser loop once successful
                    except Exception:
                        # Ignore failures and try next parser
                        pass
                else:
                    # If no parser succeeded, log the failure with the raw input value
                    self.logger.error('Could not import AES key from input: %s', value)

        # From here on, ensure input is raw bytes representing the AES key
        if not isinstance(data, bytes):
            return

        try:
            # Confirm the AES key length matches 16 bytes (AES-128 standard)
            assert len(data) == 16, f'Invalid AES key length: expected 16 bytes, got {len(data)}'

            # Store the valid AES key into internal cache for later use
            self._device_aes_key.append(data)

            # Log success message with the hex-encoded key for clarity
            self.logger.info('Received device AES key: %s', data.hex())
        except Exception as e:
            # Log any exceptions encountered during key validation or storage
            self.logger.debug('Unable to register device AES key: %s', e)

    def set_provisioning_method(self, data: bytes) -> None:
        """
        Determines and logs the provisioning method used by the Content Decryption Module (CDM).

        This method decodes the given byte data to an integer, which maps to an
        OEMCrypto_ProvisioningMethod enumeration value. It helps identify the provisioning
        mechanism in use and logs relevant diagnostic information, especially when L1
        provisioning appears to be disabled improperly.

        Args:
            data (bytes): UTF-8 encoded string representing an integer corresponding to
                          an OEMCrypto_ProvisioningMethod enum value.

        Exception:
            Catches and logs all exceptions encountered during decoding or enum conversion.
        """
        try:
            # Decode bytes to UTF-8 string, convert to int, and map to provisioning method enum
            method = OEMCrypto_ProvisioningMethod(int(data.decode('utf-8')))
            if method == OEMCrypto_ProvisioningMethod.Keybox and self._disabler:
                # Warn user if L1 provisioning is enabled but disabling procedure incomplete
                self.logger.warning(
                    'L1 provisioning deactivation appears incomplete. '
                    'Consider using a web dump or forcibly terminating the process to ensure proper disabling.'
                )
            else:
                # Log the provisioning method name for informational purposes
                self.logger.debug('Receive provisioning method: %s', method.name)
        except Exception as e:
            # Log any errors during decoding or mapping to enum with debug severity
            self.logger.debug('Unable to parse provisioning method: %s', e)

    def set_provisioning_response(self, data: bytes) -> None:
        """
        Parses and applies a provisioning response from the Google Widevine provisioning service.

        Supports both Keybox-based provisioning and Provisioning 3.0 OTA PKI formats.
        This method extracts and decrypts the device RSA private key using known AES session keys,
        which may be retrieved from keyboxes or OEM provisioning keys. It also supports
        setting up the device certificate and updating client identification.

        Args:
            data (bytes): JSON-encoded provisioning response as received from the provisioning server.

        Exception:
            Catches and logs all exceptions raised during parsing, decryption, or client ID setup.
        """
        try:
            # Extract and decode the base64-encoded signed provisioning message from the JSON response
            b64_signed_data = json.loads(data.split(b'\x00')[0])['signedResponse']
            signed_data = b64dec(b64_signed_data, safe=True)

            # Parse the SignedProvisioningMessage protobuf
            signed_response = SignedProvisioningMessage()
            signed_response.ParseFromString(signed_data)

            # Extract the ProvisioningResponse payload embedded in the signed message
            provisioning_response = ProvisioningResponse()
            provisioning_response.ParseFromString(signed_response.message)

            # Gather all known AES session keys from stored keyboxes (OEM Keybox keys)
            session_enc_keys = [k.device_aes_key for k in self._keybox.values() if k.device_aes_key]
            # Optionally, add additional AES keys extracted via reverse engineering/TEE exploit (if any)
            session_enc_keys += self._device_aes_key

            if provisioning_response.wrapping_key:
                # OTA PKI-Based provisioning (Provisioning 3.0)
                self.logger.info(
                    'Received OTA provisioning response: \n\n%s\n',
                    dumps({
                        'signature': {'type': 'RSASSA-PSS', 'data': signed_response.signature},
                        'nonce': provisioning_response.nonce,
                        'wrapping_key': provisioning_response.wrapping_key
                    }, beauty=True)
                )

                # Attempt to decrypt the AES wrapping key using all stored OEM private RSA keys
                for oem_cert_priv_key in self._private_key.values():
                    try:
                        session_enc_key = oem_cert_priv_key.decrypt(
                            ciphertext=provisioning_response.wrapping_key,
                            padding=OAEP(
                                mgf=MGF1(algorithm=SHA1()),
                                algorithm=SHA1(),
                                label=None
                            )
                        )

                        session_enc_keys.append(session_enc_key)
                    except Exception as e:
                        self.logger.debug('Unable to decrypt OTA session key: %s', e)
            else:
                # Keybox-based provisioning (Provisioning 2.0)
                self.logger.info(
                    'Receive Keybox provisioning response: \n\n%s\n',
                    dumps({
                        'signature': {'type': 'HMAC-SHA256', 'data': signed_response.signature},
                        'nonce': provisioning_response.nonce
                    }, beauty=True)
                )

            # Attempt to decrypt the device RSA private key using all gathered AES session keys
            for session_enc_key in session_enc_keys:
                try:
                    # TODO: complete the keybox with the AES key
                    # Initialize AES-CBC cipher with the session key and provided IV
                    cipher = Cipher(
                        algorithm=AES(session_enc_key),
                        mode=CBC(provisioning_response.device_rsa_key_iv),
                        backend=default_backend()
                    )

                    decryptor = cipher.decryptor()
                    dec_padded_data = decryptor.update(provisioning_response.device_rsa_key) + decryptor.finalize()

                    # Remove PKCS7 padding to obtain the original private key bytes
                    unpadder = PKCS7(AES.block_size).unpadder()
                    dec_data = unpadder.update(dec_padded_data) + unpadder.finalize()

                    # Register the decrypted RSA private key internally
                    self.set_private_key(dec_data, None)

                    # Successfully decrypted and stored the RSA key, no need to try further keys
                    # break
                except Exception as e:
                    # If no decryption succeeded, OEM private key remains unset
                    # At this point, OTA provisioning using Provisioning 3.0 (PKI-based) might apply
                    # But this flow assumes Provisioning 2.0 (Keybox-based), so no further action here
                    self.logger.debug('Failed to decrypt RSA private key using AES key: %s', session_enc_key.hex())

            # If a provisioning context exists, update the ClientIdentification with new capabilities and certificates
            if self._provisioning:
                """
                client_capabilities {
                    client_token: true
                    session_token: true
                    max_hdcp_version: HDCP_V2_2
                    oem_crypto_api_version: 15
                    anti_rollback_usage_table: false
                    srm_version: 0
                    can_update_srm: false
                    supported_certificate_key_type: RSA_2048
                    analog_output_capabilities: ANALOG_OUTPUT_NONE
                    can_disable_analog_output: false
                }
                """
                # Update client capabilities with typical fields
                client_capabilities = self._provisioning.client_capabilities
                client_capabilities.session_token = True
                client_capabilities.max_hdcp_version = ClientIdentification.ClientCapabilities.HdcpVersion.HDCP_NONE
                client_capabilities.anti_rollback_usage_table = False
                client_capabilities.can_update_srm = False

                # Construct a new ClientIdentification token with the provisioned device certificate
                client_id = ClientIdentification(
                    type=ClientIdentification.TokenType.DRM_DEVICE_CERTIFICATE,
                    token=provisioning_response.device_certificate,
                    client_info=self._provisioning.client_info,
                    provider_client_token=self._provisioning.provider_client_token,
                    license_counter=self._provisioning.license_counter,
                    client_capabilities=client_capabilities,
                    vmp_data=self._provisioning.vmp_data,
                    device_credentials=self._provisioning.device_credentials
                )

                # Register the updated client identification token
                self.set_client_id(client_id)
        except Exception as e:
            # Log any unexpected error encountered during the provisioning response handling
            self.logger.debug('Unable to process provisioning response: %s', e)

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
            # Parse DRM certificate from the client token protobuf data
            signed_drm_certificate = SignedDrmCertificate()
            signed_drm_certificate.ParseFromString(client_id.token)

            drm_certificate = DrmCertificate()
            drm_certificate.ParseFromString(signed_drm_certificate.drm_certificate)

            system_id = drm_certificate.system_id

            # Derive a filesystem path from client info on the first iteration
            if not path:
                client_info = self.__client_info(client_id)
                path = Path() / unidec(client_info['company_name']) / unidec(client_info['model_name'])

            # Attempt to find the private key matching the current client key
            private_key = next((v for k, v in self._private_key.items() if k == key), None)

            # Initialize or retrieve existing record for this system ID
            item = items.get(system_id, {
                'path': path,
                'level': 3,  # Default security level
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
            level = CryptoSession_GetSecurityLevel(intermediate_cert) or 3  # Default to level 3 if unknown

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
                    level = 1 if self._sdk > KEYBOX_MAX_CLEAR_API else 3

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
                    client_info = self.__client_info(client_id)
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
