/**
 * Date: 2024-10-27
 * Description: DRM key extraction for research and educational purposes.
 * Source: https://github.com/hyugogirubato/KeyDive
 */

// Placeholder values dynamically replaced at runtime.
const OEM_CRYPTO_API = JSON.parse('${OEM_CRYPTO_API}');
const NATIVE_C_API = JSON.parse('${NATIVE_C_API}');
const SYMBOLS = JSON.parse('${SYMBOLS}');
const SKIP = '${SKIP}' === 'True';


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

// Utility for encoding strings into byte arrays (UTF-8).
// https://gist.github.com/Yaffle/5458286#file-textencodertextdecoder-js
function TextEncoder() {
}

TextEncoder.prototype.encode = function (string) {
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
};

// Simplified log function to handle messages and encode them for transport.
const print = (level, message) => {
    message = message instanceof Object ? JSON.stringify(message) : message;
    message = message ? new TextEncoder().encode(message) : message;
    send(level, message);
}


// @Utils
const getLibraries = (name) => {
    // https://github.com/hyugogirubato/KeyDive/issues/14#issuecomment-2146788792
    try {
        const libraries = Process.enumerateModules();
        return libraries.filter(l => l.name.includes(name));
    } catch (e) {
        print(Level.CRITICAL, e.message);
        return [];
    }
};

const getLibrary = (name) => {
    const libraries = getLibraries(name);
    return libraries.length === 1 ? libraries[0] : undefined;
}

const getFunctions = (library) => {
    try {
        return library.enumerateExports();
    } catch (e) {
        print(Level.CRITICAL, e.message);
        return [];
    }
}

const disableLibrary = (name) => {
    // Disables all functions in the specified library by replacing their implementations.
    const library = getLibrary(name);
    if (library) {
        // https://github.com/hyugogirubato/KeyDive/issues/23#issuecomment-2230374415
        const functions = getFunctions(library);
        const disabled = [];

        functions.forEach(func => {
            const {name: funcName, address: funcAddr} = func;
            if (func.type !== 'function' || disabled.includes(funcAddr)) return;

            try {
                Interceptor.replace(funcAddr, new NativeCallback(function () {
                    return 0;
                }, 'int', []));

                disabled.push(funcAddr);
            } catch (e) {
                print(Level.DEBUG, `${e.message} for ${funcName}`);
            }
        });
        print(Level.INFO, `Library ${library.name} (${library.path}) has been disabled`);
    } else {
        print(Level.INFO, `Library ${name} was not found`);
    }
}


// @Libraries
const UsePrivacyMode = (address) => {
    // wvcdm::Properties::UsePrivacyMode
    Interceptor.replace(address, new NativeCallback(function () {
        return 0;
    }, 'int', []));

    Interceptor.attach(address, {
        onEnter: function (args) {
            print(Level.DEBUG, '[+] onEnter: UsePrivacyMode');
        },
        onLeave: function (retval) {
            print(Level.DEBUG, '[-] onLeave: UsePrivacyMode');
        }
    });
}

const GetCdmClientPropertySet = (address) => {
    // wvcdm::Properties::GetCdmClientPropertySet
    Interceptor.replace(address, new NativeCallback(function () {
        return 0;
    }, 'int', []));

    Interceptor.attach(address, {
        onEnter: function (args) {
            print(Level.DEBUG, '[+] onEnter: GetCdmClientPropertySet');
        },
        onLeave: function (retval) {
            print(Level.DEBUG, '[-] onLeave: GetCdmClientPropertySet');
        }
    });
}

const PrepareKeyRequest = (address) => {
    // wvcdm::CdmLicense::PrepareKeyRequest
    Interceptor.attach(address, {
        onEnter: function (args) {
            print(Level.DEBUG, '[+] onEnter: PrepareKeyRequest');

            // https://github.com/hyugogirubato/KeyDive/issues/13#issue-2327487249
            this.params = [];
            for (let i = 0; i < 7; i++) {
                this.params.push(args[i]);
            }
        },
        onLeave: function (retval) {
            print(Level.DEBUG, '[-] onLeave: PrepareKeyRequest');
            let dumped = false;

            for (let i = 0; i < this.params.length; i++) {
                try {
                    const param = ptr(this.params[i]);
                    const size = Memory.readUInt(param.add(Process.pointerSize));
                    const data = Memory.readByteArray(param.add(Process.pointerSize * 2).readPointer(), size);
                    if (data) {
                        dumped = true;
                        send('challenge', data);
                    }
                } catch (e) {
                    // print(Level.WARNING, `Failed to dump data for arg ${i}`);
                }
            }
            !dumped && print(Level.ERROR, 'Failed to dump challenge.');
        }
    });
}

const LoadDeviceRSAKey = (address, name) => {
    // wvdash::OEMCrypto::LoadDeviceRSAKey
    Interceptor.attach(address, {
        onEnter: function (args) {
            if (!args[6].isNull()) {
                const size = args[6].toInt32();
                if (size >= 1000 && size <= 2000 && !args[5].isNull()) {
                    const buffer = args[5].readByteArray(size);
                    const bytes = new Uint8Array(buffer);
                    // Check for DER encoding markers for the beginning of a private key (MII).
                    if (bytes[0] === 0x30 && bytes[1] === 0x82) {
                        let key = bytes;
                        try {
                            // Fixing key size
                            const binaryString = String.fromCharCode.apply(null, bytes);
                            const keyLength = getKeyLength(binaryString); // ASN.1 DER
                            key = bytes.slice(0, keyLength);
                        } catch (e) {
                            print(Level.ERROR, `${e.message} (${address})`);
                        }
                        print(Level.DEBUG, `[*] LoadDeviceRSAKey: ${name}`);
                        send({'private_key': name}, key);
                    }
                }
            }
        },
        onLeave: function (retval) {
            // print(Level.DEBUG, `[-] onLeave: ${name}`);
        }
    });
}

const getKeyLength = (key) => {
    // Skip the initial tag
    let pos = 1;
    // Extract length byte, ignoring the long-form indicator bit
    let lengthByte = key.charCodeAt(pos++) & 0x7F;
    // If lengthByte indicates a short form, return early.
    /*
    if (lengthByte < 0x80) {
        return pos + lengthByte;
    }
     */

    // For long-form, calculate the length value.
    let lengthValue = 0;
    while (lengthByte--) {
        lengthValue = (lengthValue << 8) + key.charCodeAt(pos++);
    }
    return pos + lengthValue;
}

const GetDeviceID = (address, name) => {
    // wvdash::OEMCrypto::GetDeviceID
    Interceptor.attach(address, {
        onEnter: function (args) {
            // print(Level.DEBUG, '[+] onEnter: GetDeviceID');
            this.data = args[0];
            this.size = args[1];
        },
        onLeave: function (retval) {
            // print(Level.DEBUG, '[-] onLeave: GetDeviceID');
            try {
                const size = Memory.readPointer(this.size).toInt32();
                const data = Memory.readByteArray(this.data, size);

                print(Level.DEBUG, `[*] GetDeviceID: ${name}`);
                send('device_id', data);
            } catch (e) {
                // print(Level.ERROR, `Failed to dump device ID.`);
            }
        }
    });
}


const memcpy = (address) => {
    // libc::memcpy
    Interceptor.attach(address, {
        onEnter: function (args) {
            // Convert size argument from hexadecimal to integer
            const size = parseInt(args[2], 16);

            // Check if the size matches known keybox sizes (128 or 132 bytes)
            if ([128, 132].includes(size)) {
                const data = Memory.readByteArray(args[1], size);

                // Define the target bytes for "kbox"
                const targetBytes = [0x6b, 0x62, 0x6f, 0x78]; // "kbox" in hex

                // Function to check if target bytes are present
                function containsTargetBytes(buffer, target) {
                    const dataArray = Array.from(new Uint8Array(buffer));
                    for (let i = 0; i <= dataArray.length - target.length; i++) {
                        if (target.every((byte, index) => dataArray[i + index] === byte)) {
                            return true;
                        }
                    }
                    return false;
                }

                // Check if "kbox" is present in the data
                if (data && containsTargetBytes(data, targetBytes)) {
                    print(Level.DEBUG, `[*] Keybox: memcpy`);
                    send('keybox', data);
                }
            }
        },
        onLeave: function (retval) {
            // print(Level.DEBUG, `[-] onLeave: memcpy`);
        }
    });
}


// @Hooks
const hookLibrary = (name) => {
    // https://github.com/poxyran/misc/blob/master/frida-enumerate-imports.py
    let library = getLibrary(name);
    if (!library) return false;

    let functions;
    if (SYMBOLS.length) {
        // https://github.com/hyugogirubato/KeyDive/issues/13#issuecomment-2143741896
        functions = SYMBOLS.map(s => ({
            type: s.type,
            name: s.name,
            address: library.base.add(s.address)
        }));
    } else {
        functions = getFunctions(library);
    }

    functions = functions.filter(f => !NATIVE_C_API.includes(f.name));
    let targets = SKIP ? [] : functions.filter(f => OEM_CRYPTO_API.includes(f.name)).map(f => f.name);
    const hooked = [];

    functions.forEach(func => {
        const {name: funcName, address: funcAddr} = func;
        if (func.type !== 'function' || hooked.includes(funcAddr)) return;

        try {
            if (funcName.includes('UsePrivacyMode')) {
                UsePrivacyMode(funcAddr);
            } else if (funcName.includes('GetCdmClientPropertySet')) {
                GetCdmClientPropertySet(funcAddr);
            } else if (funcName.includes('PrepareKeyRequest')) {
                PrepareKeyRequest(funcAddr);
            } else if (funcName.includes('lcc07') || funcName.includes('oecc07') || funcName.includes('getOemcryptoDeviceId')) {
                GetDeviceID(funcAddr, funcName);
            } else if (targets.includes(funcName) || (!targets.length && funcName.match(/^[a-z]+$/))) {
                LoadDeviceRSAKey(funcAddr, funcName);
            } else {
                /*
                    1. wvcdm::CdmEngine::GetProvisioningRequest
                    2. wvcdm::ClientIdentification::GetProvisioningTokenType
                    3. wvcdm::CryptoSession::GetProvisioningToken
                       1. wvcdm::CryptoSession::GetTokenFromOemCert
                       2. wvcdm::CryptoSession::GetTokenFromKeybox
                 */
                // print(Level.WARNING, `Hooked (${funcAddr}): ${funcName}`);
                return;
            }

            hooked.push(funcAddr);
            print(Level.DEBUG, `Hooked (${funcAddr}): ${funcName}`);
        } catch (e) {
            print(Level.ERROR, `${e.message} for ${funcName}`);
        }
    });

    if (hooked.length < 3) {
        print(Level.CRITICAL, 'Insufficient functions hooked.');
        return false;
    }

    // Keybox (experimental)
    library = getLibrary('libc.so');
    targets = getFunctions(library).find(func => func.name === 'memcpy' && func.type === 'function');
    if (targets) {
        try {
            memcpy(targets.address);
            print(Level.DEBUG, `Hooked (${targets.address}): ${targets.name}`);
        } catch (e) {
            print(Level.ERROR, `${e.message} for ${targets.name}`);
        }
    }

    // https://github.com/hzy132/liboemcryptodisabler/blob/master/customize.sh#L33
    disableLibrary('liboemcrypto.so');
    return true;
}

// RPC interfaces exposed to external calls.
rpc.exports = {
    getlibrary: getLibrary,
    hooklibrary: hookLibrary
};
