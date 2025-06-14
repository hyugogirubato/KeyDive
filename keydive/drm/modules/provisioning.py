import json
from enum import Enum

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.padding import PKCS7

from keydive.drm.modules.client import Client
from keydive.drm.protocol.license_pb2 import SignedProvisioningMessage, ProvisioningResponse, ClientIdentification
from keydive.utils import b64dec, dumps


class OEMCrypto_ProvisioningMethod(Enum):
    """
    Enum representing different OEMCrypto provisioning methods.
    """
    ProvisioningError = 0  # Device cannot be provisioned.
    DrmCertificate = 1  # Device has baked-in DRM certificate (level 3 only).
    Keybox = 2  # Device has factory-installed unique keybox.
    OEMCertificate = 3  # Device has factory-installed OEM certificate.


def ContentKeySession_GenerateDerivedKeys(enc_key_base: bytes, key: bytes) -> bytes:
    """
    Derives a single CMAC-based encryption key from the given base key.

    This is a minimal implementation of key derivation used in Widevine's content key session setup.
    It returns only the 'enc' key from the full provisioning/session derivation pipeline.

    Args:
        enc_key_base (bytes): Context string for encryption key derivation (e.g., from provisioning nonce or session context).
        key (bytes): Base AES key (e.g., device AES key or session key).

    Returns:
        bytes: Derived encryption key.
    """
    cipher = cmac.CMAC(
        algorithm=AES(key),
        backend=default_backend()
    )
    cipher.update(b'\x01' + enc_key_base)
    return cipher.finalize()


class Provisioning(Client):

    def __unwrap_rsa_key(self, key: bytes, iv: bytes, enc_data: bytes) -> bytes:
        """
        Attempts to decrypt an RSA private key blob using AES-CBC and PKCS7 unpadding.

        This method is used in Widevine provisioning flows to unwrap the encrypted RSA device key
        from the provisioning response using a derived or session AES key.

        Args:
            key (bytes): The AES key used to decrypt the RSA private key (128/256-bit).
            iv (bytes): Initialization Vector used during the AES encryption.
            enc_data (bytes): Encrypted RSA private key data (typically from the provisioning response).

        Returns:
            bytes: The unwrapped (decrypted) RSA private key if successful, otherwise an empty byte string.
        """
        dec_data = b''
        try:
            # Initialize AES-CBC cipher with the session key and provided IV
            cipher = Cipher(
                algorithm=AES(key),
                mode=CBC(iv),
                backend=default_backend()
            )

            decryptor = cipher.decryptor()
            dec_padded_data = decryptor.update(enc_data) + decryptor.finalize()

            # Remove PKCS7 padding to obtain the original private key bytes
            unpadder = PKCS7(AES.block_size).unpadder()
            dec_data = unpadder.update(dec_padded_data) + unpadder.finalize()
        except Exception as e:
            if key:
                self.logger.debug('Failed to decrypt RSA private key using AES key: %s', key.hex())

        # Return decrypted RSA private key (if successful); otherwise, return empty bytes
        return dec_data

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
            if method == OEMCrypto_ProvisioningMethod.Keybox and self.disabler:
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

            # Derive session encryption keys and map each original AES key to its derived encryption key
            key_pairs = {
                key: ContentKeySession_GenerateDerivedKeys(self._context, key) if self._context else None
                for key in session_enc_keys
            }

            # Attempt to decrypt the device RSA private key using all gathered AES session keys
            for aes_key, derived_key in key_pairs.items():
                iv = provisioning_response.device_rsa_key_iv
                enc_data = provisioning_response.device_rsa_key

                # Attempt to decrypt using the derived key (from ContentKeySession_GenerateDerivedKeys)
                dec_data = self.__unwrap_rsa_key(derived_key, iv, enc_data)
                if dec_data:
                    self.logger.info('Provisioning from AES key derivation: %s', derived_key.hex())

                    # Try to find the corresponding Keybox which doesn't yet have an AES key assigned
                    keybox = next((k for k in self._keybox.values() if k.stable_id and k.device_id and not k.device_aes_key), None)
                    if keybox:
                        # Check if system_id is available to ensure the Keybox is valid and useful
                        if keybox.keybox_info.get('system_id'):
                            # Link this AES key back to the Keybox for future use
                            keybox.device_aes_key = aes_key
                            self.logger.info(
                                'Completed keybox with corresponding AES key:\n\n%s\n',
                                dumps(keybox.keybox_info, beauty=True)
                            )

                            # Update the stored keybox with the completed information
                            self._keybox[keybox.stable_id] = keybox

                    # Set the now-decrypted RSA private key as the active OEM private key
                    self.set_private_key(dec_data, None)

                # Attempt to decrypt the RSA key using the raw session AES key (not derived)
                dec_data = self.__unwrap_rsa_key(aes_key, iv, enc_data)
                if dec_data:
                    self.logger.info('Provisioning from OTA AES key: %s', aes_key.hex())
                    # Set decrypted RSA private key from OTA flow
                    self.set_private_key(dec_data, None)

                # If no decryption succeeded, OEM private key remains unset
                # At this point, OTA provisioning using Provisioning 3.0 (PKI-based) might apply
                # But this flow assumes Provisioning 2.0 (Keybox-based), so no further action here

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
