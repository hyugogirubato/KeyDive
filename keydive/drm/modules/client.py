import logging
from pathlib import Path
from typing import Union, List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from keydive.drm.modules.oemcrypto import OEMCrypto
from keydive.drm import OEM_CRYPTO_API
from keydive.utils import dumps
from keydive.drm.protocol.license_pb2 import (
    ClientIdentification, SignedMessage, LicenseRequest, EncryptedClientIdentification, SignedDrmCertificate,
    DrmCertificate)


def get_client_info(client_id: ClientIdentification) -> dict:
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


def get_client_generic(client_id: ClientIdentification) -> ClientIdentification:
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


class Client(OEMCrypto):

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
                client_id = get_client_generic(client_id)

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
                        dumps(get_client_info(client_id), beauty=True)
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
