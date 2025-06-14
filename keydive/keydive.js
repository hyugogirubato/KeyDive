/**
 * Date: 2025-06-14
 * Description: DRM key extraction for research and educational purposes.
 * Source: https://github.com/hyugogirubato/KeyDive
 */

// Placeholder values dynamically replaced at runtime.
const OEM_CRYPTO_API = JSON.parse('${OEM_CRYPTO_API}');
const NATIVE_C_API = JSON.parse('${NATIVE_C_API}');
const SYMBOLS = JSON.parse('${SYMBOLS}');
const DETECT = '${DETECT}' === 'True';
const DISABLER = '${DISABLER}' === 'True';
const UNENCRYPT = '${UNENCRYPT}' === 'True';


// Logging levels to synchronize with Python's logging module.
const Level = {
    NOTSET: 0,
    DEBUG: 10,
    INFO: 20,
    // WARN: WARNING,
    WARNING: 30,
    ERROR: 40,
    // FATAL: CRITICAL,
    CRITICAL: 50
};

// Backward compatibility with the modern equivalent implemented since frida 17
// https://frida.re/news/2025/05/17/frida-17-0-0-released/
/*
readS8 = readShort
readU8 = readUShort
readS16 = readInt
readU16 = readUInt
readS32 = readFloat
readU32 = readDouble

console.log(hexdump(address, {
    offset: 0,
    length: 128,
    header: true,
    ansi: true
}));
 */
Memory = typeof Memory === 'undefined' ? {} : Memory;
Memory.readByteArray ??= (address, length) => address.readByteArray(length);
Memory.readPointer ??= (address) => address.readPointer();
Memory.readU16 ??= (address) => address.readU16();

Memory.readStdString = function (address) {
    // https://learnfrida.info/intermediate_usage/#stdstring
    // Read string size (2 bytes) at offset pointerSize
    const size = Memory.readU16(address.add(Process.pointerSize));

    // Check if string is using Small String Optimization (SSO)
    const LSB = address.readU8() & 1;
    if (LSB === 0) {
        // https://codeshare.frida.re/@oleavr/read-std-string/
        // SSO: data is stored inline starting at address + 1
        return Memory.readByteArray(address.add(1), size);
    } else {
        // Non-SSO: pointer to data is stored at address
        return Memory.readByteArray(address.add(Process.pointerSize * 2).readPointer(), size);
    }
}

Memory.readStdVector = function (address) {
    // https://learnfrida.info/intermediate_usage/#stdvector
    // Read the vector size (2 bytes) at offset pointerSize
    let size = Memory.readU16(address.add(Process.pointerSize));

    // Read pointer to the start of the vector data (at offset 0)
    const data = Memory.readByteArray(address.readPointer(), size);
    /*
    const buffer = new Uint8Array(data);

    // Trim trailing null bytes (0x00) from the end
    while (size > 0 && buffer[size - 1] === 0x00) {
        size--;
    }

    // Return the trimmed buffer
    return buffer.slice(0, size);
     */
    return data;
}

// Utility for encoding strings into byte arrays (UTF-8).
// https://gist.github.com/Yaffle/5458286#file-textencodertextdecoder-js
class TextEncoder {

    encode(string) {
        const octets = [];
        let i = 0;
        while (i < string.length) {
            const codePoint = string.codePointAt(i);
            let c = 0;
            let bits = 0;
            if (codePoint <= 0x007F) {
                c = 0;
                bits = 0x00;
            } else if (codePoint <= 0x07FF) {
                c = 6;
                bits = 0xC0;
            } else if (codePoint <= 0xFFFF) {
                c = 12;
                bits = 0xE0;
            } else if (codePoint <= 0x1FFFFF) {
                c = 18;
                bits = 0xF0;
            }
            octets.push(bits | (codePoint >> c));
            while (c >= 6) {
                c -= 6;
                octets.push(0x80 | ((codePoint >> c) & 0x3F));
            }
            i += codePoint >= 0x10000 ? 2 : 1;
        }
        return octets;
    }
}

// Simplified log function to handle messages and encode them for transport.
const print = (level, message) => {
    message = message instanceof Object ? JSON.stringify(message) : message;
    message = message ? new TextEncoder().encode(message) : message;
    send(level, message);
}

const getVersion = () => Frida.version;


// @Utils
function getLibraries() {
    // https://github.com/hyugogirubato/KeyDive/issues/14#issuecomment-2146788792
    try {
        return Process.enumerateModules();
    } catch (e) {
        print(Level.CRITICAL, e.message);
        return [];
    }
}

function getLibrary(name) {
    return getLibraries().find(l => l.name === name);
}

function getFunctions(library, dynamic = false) {
    try {
        // https://frida.re/news/2025/01/09/frida-16-6-0-released/
        const functions = dynamic
            ? library.enumerateSymbols().map(item => ({
                type: item.type,
                name: item.name,
                address:
                item.address
            })) : [];

        return functions.concat(library.enumerateExports());
    } catch (e) {
        print(Level.CRITICAL, e.message);
        return [];
    }
}

function getDerLength(buffer) {
    let pos = 1; // Skip the tag byte (usually 0x30 for SEQUENCE)

    let lengthByte = buffer[pos++]; // Read length descriptor

    if (lengthByte < 0x80) {
        // Short form: length is in this byte
        return pos + lengthByte;
    }

    // Long form: next N bytes encode the length
    const numLenBytes = lengthByte & 0x7F;

    if (numLenBytes + pos > buffer.length) {
        throw new Error('DER length bytes exceed buffer size');
    }

    let lengthValue = 0;
    for (let i = 0; i < numLenBytes; i++) {
        lengthValue = (lengthValue << 8) + buffer[pos++]; // Accumulate length
    }

    // Total length = current pos (after length bytes) + value length
    return pos + lengthValue;
}

function readDerKey(address, size) {
    // Read initial bytes from memory
    const data = Memory.readByteArray(address, size);
    const buffer = new Uint8Array(data);

    const tag = buffer[0]; // Usually 0x30 for SEQUENCE

    // Check if tag indicates a DER SEQUENCE
    if (tag !== 0x30) return;

    try {
        // Adjust size based on DER length field
        size = getDerLength(buffer); // ASN.1 DER
    } catch (e) {
        // Ignore error, keep initial size
    }

    // Return the DER key slice
    return buffer.slice(0, size);
}

function disableLibrary(name) {
    // Disables all functions in the specified library by replacing their implementations.
    const library = getLibrary(name);
    if (library) {
        // https://github.com/hyugogirubato/KeyDive/issues/23#issuecomment-2230374415
        const functions = getFunctions(library, false);
        const disabled = new Set();

        functions.forEach(({name: funcName, address: funcAddr, type}) => {
            if (type !== 'function' || disabled.has(funcAddr)) return;

            try {
                Interceptor.replace(funcAddr, new NativeCallback(() => ptr(0), 'pointer', []));
                disabled.add(funcAddr);
            } catch (e) {
                print(Level.DEBUG, `${e.message} for ${funcName}`);
            }
        });

        print(Level.INFO, `Library ${library.name} (${library.path}) has been disabled`);
    } else {
        print(Level.DEBUG, `Library ${name} was not found`);
    }
}


// @Libraries
function Properties_UsePrivacyMode(address) {
    /*
    wvcdm::Properties::UsePrivacyMode

    Args:
        args[1]: const CdmSessionId& session_id
    Return:
        retval: bool
     */
    Interceptor.replace(address, new NativeCallback(() => 0, 'bool', []));

    Interceptor.attach(address, {
        onEnter: function (args) {
            print(Level.DEBUG, '[+] onEnter: Properties::UsePrivacyMode');
        },
        onLeave: function (retval) {
            print(Level.DEBUG, '[-] onLeave: Properties::UsePrivacyMode');
        }
    });
}

function Properties_GetCdmClientPropertySet(address) {
    /*
    wvcdm::Properties::GetCdmClientPropertySet

    Args:
        args[1]: const CdmSessionId& session_id
    Return:
        retval: wvcdm::CdmClientPropertySet*
     */
    Interceptor.replace(address, new NativeCallback(() => ptr(0), 'pointer', []));

    Interceptor.attach(address, {
        onEnter: function (args) {
            print(Level.DEBUG, '[+] onEnter: Properties::GetCdmClientPropertySet');
        },
        onLeave: function (retval) {
            print(Level.DEBUG, '[-] onLeave: Properties::GetCdmClientPropertySet');
        }
    });
}

function CdmLicense_PrepareKeyRequest(address) {
    /*
    wvcdm::CdmLicense::PrepareKeyRequest

    Args:
        args[1]: const InitializationData& init_data
        args[2]: const std::string& client_token
        args[3]: CdmLicenseType license_type
        args[4]: const CdmAppParameterMap& app_parameters
        args[5]: CdmKeyMessage* signed_request
        args[6]: std::string* server_url
     Return:
        retval: wvcdm::CdmResponseType
     */
    Interceptor.attach(address, {
        onEnter: function (args) {
            print(Level.DEBUG, '[+] onEnter: CdmLicense::PrepareKeyRequest');

            // https://github.com/hyugogirubato/KeyDive/issues/13#issue-2327487249
            this.params = [];
            for (let i = 0; i < 8; i++) {
                this.params.push(args[i]);
            }
        },
        onLeave: function (retval) {
            print(Level.DEBUG, '[-] onLeave: CdmLicense::PrepareKeyRequest');
            let dumped = false;

            // Extract and dump the relevant arguments
            for (let i = 0; i < this.params.length; i++) {
                // Extract the signed_request data (CdmKeyMessage*)
                try {
                    const signedRequestData = Memory.readStdString(this.params[i]);
                    if (signedRequestData) {
                        dumped = true;
                        send('challenge', signedRequestData);
                    }
                } catch (e) {
                    // print(Level.WARNING, `Failed to extract signed_request data from args[${i}]`);
                }
            }
            !dumped && print(Level.ERROR, 'Failed to dump challenge data');
        }
    });
}

function CdmEngine_GenerateKeyRequest(address) {
    /*
    wvcdm::CdmEngine::GenerateKeyRequest

    Args:
        args[1]: const CdmSessionId& session_id
        args[2]: const CdmKeySetId& key_set_id
        args[3]: const InitializationData& init_data
        args[4]: const CdmLicenseType license_type
        args[5]: CdmAppParameterMap& app_parameters
        args[6]: CdmKeyRequest* key_request
     Return:
        retval: wvcdm::CdmResponseType
     */
    Interceptor.attach(address, {
        onEnter: function (args) {
            print(Level.DEBUG, '[+] onEnter: CdmEngine::GenerateKeyRequest');

            // https://github.com/hyugogirubato/KeyDive/issues/13#issue-2327487249
            this.params = [];
            for (let i = 0; i < 8; i++) {
                this.params.push(args[i]);
            }
        },
        onLeave: function (retval) {
            print(Level.DEBUG, '[-] onLeave: CdmEngine::GenerateKeyRequest');
            let dumped = false;

            // Extract and dump the relevant arguments
            for (let i = 0; i < this.params.length; i++) {
                // Extract the signed_request data (CdmKeyMessage*)
                try {
                    const signedRequestData = Memory.readStdString(this.params[i]);
                    if (signedRequestData) {
                        dumped = true;
                        send('challenge', signedRequestData);
                    }
                } catch (e) {
                    // print(Level.WARNING, `Failed to extract signed_request data from args[${i}]`);
                }
            }
            !dumped && print(Level.ERROR, 'Failed to dump challenge data');
        }
    });
}

function AesCbcKey_Encrypt(address) {
    /*
    wvcdm::AesCbcKey::Encrypt

    Args:
        args[1]: const std::string& in
        args[2]: std::string* out
        args[3]: std::string* iv
    Return:
        retval: bool
    */
    Interceptor.attach(address, {
        onEnter: function (args) {
            const inData = Memory.readStdString(args[1]);
            if (inData) {
                print(Level.DEBUG, '[*] AesCbcKey::Encrypt');
                send('client_id', inData);
            }
        }
    });
}

function FileSystem_Read(address) {
    /*
    wvoec3::OEMCrypto_Level3AndroidFileSystem::Read

    Args:
        args[1]: const char *filename
        args[2]: void *buffer
        args[3]: size_t size
    Return:
        retval: ssize_t
     */
    Interceptor.attach(address, {
        onEnter: function (args) {
            const bufferPtr = args[2];
            const size = args[3].toInt32();
            const data = Memory.readByteArray(bufferPtr, size);

            // Check if the size matches known keybox sizes (128 or 132 bytes)
            if ([128, 132].includes(size) && data) {
                print(Level.DEBUG, '[*] FileSystem::Read');
                send('keybox', data);
            }
        }
    });
}

function File_Read(address) {
    /*
    wvcdm::File::Read

    Args:
        args[1]: char* buffer
        args[2]: size_t bytes
    Return:
        retval: ssize_t
     */
    /*
    _x1c36

    Args:
        args[0]: std::string* filename
        args[1]: char* buffer
        args[2]: size_t bytes
    Return:
        retval: ssize_t
     */
    Interceptor.attach(address, {
        onEnter: function (args) {
            const bufferPtr = args[1];
            const size = args[2].toInt32();
            const data = Memory.readByteArray(bufferPtr, size);

            // Check if the size matches known keybox sizes (128 or 132 bytes)
            if ([128, 132].includes(size) && data) {
                print(Level.DEBUG, '[*] File::Read');
                send('keybox', data);
            }
        }
    });
}

function RunningCRC(address) {
    /*
    wvoec::wvrunningcrc32

    Args:
        args[0]: const uint8_t* p_begin
        args[1]: int i_count
        args[2]: uint32_t i_crc
    Return:
        retval: uint32_t
     */
    Interceptor.attach(address, {
        onEnter: function (args) {
            const size = args[1].toInt32();
            const data = Memory.readByteArray(args[0], 128);

            // Check if size matches keybox length excluding 4-byte magic/tag fields
            if (size === 124 && data) {
                print(Level.DEBUG, '[*] RunningCRC');
                send('keybox', data);
            }
        }
    });
}

function OEMCrypto_GetDeviceID(address) {
    /*
    wvcdm::OEMCrypto_GetDeviceID

    Args:
        args[0]: uint8_t* deviceID
        args[1]: size_t* idLength
        args[2]: SecurityLevel level
    Return:
        retval: OEMCryptoResult
     */
    Interceptor.attach(address, {
        onEnter: function (args) {
            this.deviceIdPtr = args[0];
            this.idLengthPtr = args[1];
        },
        onLeave: function (retval) {
            const idLength = Memory.readPointer(this.idLengthPtr).toInt32();
            const deviceIdData = Memory.readByteArray(this.deviceIdPtr, idLength);

            if (deviceIdData) {
                print(Level.DEBUG, '[*] OEMCrypto_GetDeviceID');
                send('stable_id', deviceIdData);
            }
        }
    });
}

function OEMCrypto_GetKeyData(address) {
    /*
    wvcdm::OEMCrypto_GetKeyData

    Args:
        args[0]: uint8_t* keyData
        args[1]: size_t* keyDataLength
        args[2]: SecurityLevel level
    Return:
        retval: OEMCryptoResult
     */
    Interceptor.attach(address, {
        onEnter: function (args) {
            this.keyDataPtr = args[0];
            this.keyDataLengthPtr = args[1];
        },
        onLeave: function (retval) {
            const keyDataLength = Memory.readPointer(this.keyDataLengthPtr).toInt32();
            const keyData = Memory.readByteArray(this.keyDataPtr, keyDataLength);

            if (keyData) {
                print(Level.DEBUG, '[*] OEMCrypto_GetKeyData');
                send('device_id', keyData);
            }
        }
    });
}

function OEMCrypto_ProvisioningMethod(address) {
    /*
    wvcdm::OEMCrypto_GetProvisioningMethod

    Args:
        args[0]: SecurityLevel level
    Return:
        retval: OEMCrypto_ProvisioningMethod
     */
    Interceptor.attach(address, {
        onLeave: function (retval) {
            // https://github.com/fox0618/dumper/blob/main/Helpers/script.js#L784
            print(Level.DEBUG, '[*] OEMCrypto_ProvisioningMethod');
            send('provisioning_method', new TextEncoder().encode(`${retval.toInt32()}`));
        }
    });
}

function OEMCrypto_GenerateDerivedKeys(address) {
    /*
    wvcdm::OEMCrypto_GenerateDerivedKeys

    Args:
        args[0]: OEMCrypto_SESSION session
        args[1]: const uint8_t* mac_key_context
        args[2]: uint32_t mac_key_context_length
        args[3]: const uint8_t* enc_key_context,
        args[4]: uint32_t enc_key_context_length
    Return:
        retval: OEMCryptoResult
    */
    Interceptor.attach(address, {
        onEnter: function (args) {
            print(Level.DEBUG, '[*] OEMCrypto_GenerateDerivedKeys');
            // https://github.com/Avalonswanderer/widevinel3_Android_PoC/blob/main/PoCs/content_key_recovery.py#L103C55-L103C72

            // const macKeyContext = Memory.readByteArray(args[1], args[2].toInt32());
            // console.log('macKeyContext:', macKeyContext);
            /*
            macKeyContext:            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
            00000000  41 55 54 48 45 4e 54 49 43 41 54 49 4f 4e 00 12  AUTHENTICATION..
            00000010  04 0a d5 8e c0 1a 04 08 00 12 00 2a 98 06 0a 0c  ...........*....
            00000020  77 69 64 65 76 69 6e 65 2e 63 6f 6d 12 10 51 43  widevine.com..QC
            00000030  4f e2 a4 4c 76 3b cc 2c 82 6a 2d 6e f9 a7 1a e0  O..Lv;.,.j-n....
            */

            const encKeyContext = Memory.readByteArray(args[3], args[4].toInt32());
            // console.log('encKeyContext:', encKeyContext);
            /*
            encKeyContext:            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
            00000000  45 4e 43 52 59 50 54 49 4f 4e 00 12 04 0a d5 8e  ENCRYPTION......
            00000010  c0 1a 04 08 00 12 00 2a 98 06 0a 0c 77 69 64 65  .......*....wide
            00000020  76 69 6e 65 2e 63 6f 6d 12 10 51 43 4f e2 a4 4c  vine.com..QCO..L
            00000030  76 3b cc 2c 82 6a 2d 6e f9 a7 1a e0 03 ec 2a c5  v;.,.j-n......*.
            */
            if (encKeyContext) {
                send('encryption_context', encKeyContext);
            }
        }
    });
}

function OEMCrypto_DeriveKeysFromSessionKey(address) {
    /*
    wvcdm::OEMCrypto_DeriveKeysFromSessionKey

    Args:
        args[0]: OEMCrypto_SESSION session
        args[1]: const uint8_t* enc_session_key
        args[2]: size_t enc_session_key_length
        args[3]: const uint8_t* mac_key_context
        args[4]: size_t mac_key_context_length
        args[5]: const uint8_t* enc_key_context
        args[6]: size_t enc_key_context_length
    Return:
        retval: OEMCryptoResult
    */
    Interceptor.attach(address, {
        onEnter: function (args) {
            print(Level.DEBUG, '[+] onEnter: OEMCrypto_DeriveKeysFromSessionKey');
            const encSessionKey = Memory.readByteArray(args[1], args[2].toInt32());
            const macKeyContext = Memory.readByteArray(args[3], args[4].toInt32());
            const encKeyContext = Memory.readByteArray(args[5], args[6].toInt32());

            // console.log('encSessionKey:', encSessionKey);
            /*
            encSessionKey:            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
            00000000  c4 9d ef cf 5f 0b 98 9c 03 46 93 89 14 8f 08 e2  ...._....F......
            00000010  12 da 13 39 ad 31 75 f7 b5 32 94 ee 2f 7f bf 6a  ...9.1u..2../..j
            00000020  d7 45 c0 50 22 9a 6c 36 76 a7 78 d8 9f 76 b5 45  .E.P".l6v.x..v.E
            00000030  f3 5c 6f 25 91 08 cf de a3 d9 90 08 cb e1 d4 55  .\o%...........U
            */

            // console.log('macKeyContext:', macKeyContext);
            /*
            macKeyContext:            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
            00000000  41 55 54 48 45 4e 54 49 43 41 54 49 4f 4e 00 0a  AUTHENTICATION..
            00000010  c3 0f 08 01 12 aa 0b 0a ed 03 08 02 12 20 8d a4  ............. ..
            00000020  21 77 04 fb 58 ff d6 58 80 8c d2 32 b5 81 01 5a  !w..X..X...2...Z
            00000030  6a d6 97 29 97 51 ac 92 95 de 81 fe b3 13 18 f7  j..).Q..........
            */
            // console.log('encKeyContext:', encKeyContext);
            /*
            encKeyContext:            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
            00000000  45 4e 43 52 59 50 54 49 4f 4e 00 0a c3 0f 08 01  ENCRYPTION......
            00000010  12 aa 0b 0a ed 03 08 02 12 20 8d a4 21 77 04 fb  ......... ..!w..
            00000020  58 ff d6 58 80 8c d2 32 b5 81 01 5a 6a d6 97 29  X..X...2...Zj..)
            00000030  97 51 ac 92 95 de 81 fe b3 13 18 f7 f6 ad c1 06  .Q..............
            */
        },
        onLeave: function (retval) {
            print(Level.DEBUG, '[-] onLeave: OEMCrypto_DeriveKeysFromSessionKey');
        }
    });
}

function WVDrmPlugin_provideProvisionResponse(address) {
    /*
    wvdrm::WVDrmPlugin::provideProvisionResponse

    Args:
        args[1]: const Vector<uint8_t>& response
        args[2]: Vector<uint8_t>& certificate,
        args[3]: Vector<uint8_t>& wrapped_key
    Return:
        retval: wvcdm::CdmResponseType
    */
    Interceptor.attach(address, {
        onEnter: function (args) {
            print(Level.DEBUG, '[*] WVDrmPlugin::provideProvisionResponse');
            let dumped = false;

            // Extract and dump the relevant arguments
            for (let i = 0; i < 4; i++) {
                try {
                    const responseData = Memory.readStdVector(args[i]);
                    if (responseData) {
                        dumped = true;
                        send('provisioning_response', responseData);
                    }
                } catch (e) {
                    // print(Level.WARNING, `Failed to extract provisioning response data from args[${i}]`);
                }
            }
            !dumped && print(Level.ERROR, 'Failed to dump provisioning response data');
        }
    });
}

function Level3_RewrapDeviceRSAKey30(address, name) {
    /*
    wvcdm::Level3_RewrapDeviceRSAKey30

    Args:
        args[1]: OEMCrypto_SESSION session
        args[2]: const uint32_t* nonce
        args[3]: const uint8_t* encrypted_message_key
        args[4]: size_t encrypted_message_key_length
        args[5]: const uint8_t* enc_rsa_key
        args[6]: size_t enc_rsa_key_length
        args[7]: const uint8_t* enc_rsa_key_iv
        args[8]: uint8_t* wrapped_rsa_key
        args[9]: size_t* wrapped_rsa_key_length
    Return:
        retval: OEMCryptoResult
    */
    Interceptor.attach(address, {
        onEnter: function (args) {
            const bufferPtr = args[5];
            const sizePtr = args[6];

            if (!(sizePtr.isNull() || bufferPtr.isNull())) {
                // Check if this is a pointer to a buffer
                if (bufferPtr < 0x10000) return;

                // Check if the size matches a potential 2048 or 4096-bit RSA private key (range 1190-2350)
                const size = sizePtr.toInt32();
                if (size < 1000 || size > 2400) return;

                const bufferData = readDerKey(bufferPtr, size);
                if (bufferData) {
                    print(Level.DEBUG, `[*] Level3_RewrapDeviceRSAKey30: ${name}`);
                    send({'private_key': name}, bufferData);
                }
            }
        }
    });
}


// @Hooks
const hookLibrary = (name, dynamic) => {
    // https://github.com/poxyran/misc/blob/master/frida-enumerate-imports.py
    let library = getLibrary(name);
    if (!library) return false;

    let functions;
    if (Object.keys(SYMBOLS).length) {
        // https://github.com/hyugogirubato/KeyDive/issues/13#issuecomment-2143741896
        functions = Object.entries(SYMBOLS).map(([key, value]) => ({
            type: 'function',
            name: value,
            address: library.base.add(ptr(key))
        }));
    } else {
        // https://github.com/hyugogirubato/KeyDive/issues/50
        functions = getFunctions(library, dynamic);
    }

    functions = functions.filter(f => !NATIVE_C_API.includes(f.name));
    let targets = DETECT ? functions.filter(f => OEM_CRYPTO_API.includes(f.name)).map(f => f.name) : [];

    const required = new Set();
    const hooked = new Set();
    functions.forEach(({name: funcName, address: funcAddr, type}) => {
        if (type !== 'function' || required.has(funcAddr)) return;

        try {
            // Interception of client ID via challenge or in clear text
            if (['AesCbcKey', 'Encrypt'].every(n => funcName.includes(n))) {
                AesCbcKey_Encrypt(funcAddr);
                required.add(funcAddr);
            // Calling this method is further down in the challenge request execution flow
            // Using the GenerateKeyRequest function at a higher level
            //} else if (['CdmLicense', 'PrepareKeyRequest'].every(n => funcName.includes(n))) {
            //    CdmLicense_PrepareKeyRequest(funcAddr);
            //    required.add(funcAddr);
            } else if (['CdmEngine', 'GenerateKeyRequest'].every(n => funcName.includes(n))) {
                CdmEngine_GenerateKeyRequest(funcAddr);
                required.add(funcAddr);

            // Full and block keybox interception
            } else if (['FileSystem', 'Read'].every(n => funcName.includes(n))) {
                FileSystem_Read(funcAddr);
            } else if (['File', 'Read'].every(n => funcName.includes(n)) || funcName.includes('_x1c36')) {
                File_Read(funcAddr);
            } else if (['runningcrc'].every(n => funcName.includes(n))) {
                // https://github.com/Avalonswanderer/widevinel3_Android_PoC/blob/main/PoCs/recover_l3keybox.py#L50
                RunningCRC(funcAddr);
            } else if (['_oecc07', '_lcc07'].some(n => funcName.includes(n))) {
                OEMCrypto_GetDeviceID(funcAddr);
            } else if (['_oecc04', '_lcc04'].some(n => funcName.includes(n))) {
                OEMCrypto_GetKeyData(funcAddr);
            // TODO: Check the keybox implementation on SDK 36
            // TODO: Interception of the certificate's private key
            // Call OEMCrypto_GetOEMPublicCertificate before OEMCrypto_LoadDRMPrivateKey

                // Provisioning Interception
            } else if (['_oecc49', '_lcc49'].some(n => funcName.includes(n))) {
                OEMCrypto_ProvisioningMethod(funcAddr);
            } else if (['_oecc12', '_lcc12', '_oecc95', '_lcc95'].some(n => funcName.includes(n))) {
                // Key derivation via keybox for L1 provisioning
                OEMCrypto_GenerateDerivedKeys(funcAddr);
            //} else if (['_oecc21', '_lcc21'].some(n => funcName.includes(n))) {
            //    Key derivation via session key for license request
            //    OEMCrypto_DeriveKeysFromSessionKey(funcAddr);
            } else if (['WVDrmPlugin', 'provideProvisionResponse'].every(n => funcName.includes(n))) {
                WVDrmPlugin_provideProvisionResponse(funcAddr);

            // Disable encrypted client id for license request (deprecated)
            } else if (UNENCRYPT && ['Properties', 'GetCdmClientPropertySet'].every(n => funcName.includes(n))) {
                Properties_GetCdmClientPropertySet(funcAddr);
            } else if (UNENCRYPT && ['Properties', 'UsePrivacyMode'].every(n => funcName.includes(n))) {
                // Calling this function usually returns a boolean handled by the GetCdmClientPropertySet subcall
                // Replacing this function is quite unstable, causing library crashes
                Properties_UsePrivacyMode(funcAddr);

            // OEM private key interruption from obfuscated functions
            } else if (targets.includes(funcName) || (!targets.length && funcName.match(/^[a-z]+$/))) {
                Level3_RewrapDeviceRSAKey30(funcAddr, funcName);
                required.add(funcAddr);
            } else {
                return;
            }

            hooked.add(funcAddr);
            print(Level.DEBUG, `Hooked (${funcAddr}): ${funcName}`);
        } catch (e) {
            print(Level.ERROR, `${e.message} for ${funcName}`);
        }
    });

    if (required.size < 3) {
        print(Level.CRITICAL, 'Insufficient functions hooked');
        return false;
    }

    if (DISABLER) {
        // TODO: Disable old L1 libraries? (https://github.com/wvdumper/dumper/blob/main/Helpers/Scanner.py#L23)
        // https://github.com/hzy132/liboemcryptodisabler/blob/master/customize.sh#L33
        disableLibrary('liboemcrypto.so');
    }

    return true;
}

// RPC interfaces exposed to external calls.
rpc.exports = {
    getversion: getVersion,
    getlibraries: getLibraries,
    hooklibrary: hookLibrary
};
