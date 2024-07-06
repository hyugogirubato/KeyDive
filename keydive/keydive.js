/**
 * Date: 2024-06-30
 * Description: DRM key extraction for research and educational purposes.
 * Source: https://github.com/hyugogirubato/KeyDive
 */

// Placeholder values dynamically replaced at runtime.
const OEM_CRYPTO_API = JSON.parse('${OEM_CRYPTO_API}');
const NATIVE_C_API = JSON.parse('${NATIVE_C_API}');
const SYMBOLS = JSON.parse('${SYMBOLS}');


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
            for (let i = 0; i < 6; i++) {
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

const GetCertificatePrivateKey = (address, name) => {
    // wvcdm::CryptoSession::GetCertificatePrivateKey
    Interceptor.attach(address, {
        onEnter: function (args) {
            if (!args[6].isNull()) {
                const size = args[6].toInt32();
                if (size >= 1000 && size <= 2000 && !args[5].isNull()) {
                    const buffer = args[5].readByteArray(size);
                    const bytes = new Uint8Array(buffer);
                    // Check for DER encoding markers for the beginning of a private key (MII).
                    if (bytes[0] === 0x30 && bytes[1] === 0x82) {
                        /*
                        let key = bytes;
                        try {
                            // Fixing key size
                            const binaryString = String.fromCharCode.apply(null, bytes);
                            const keyLength = getKeyLength(binaryString); // ASN.1 DER
                            key = bytes.slice(0, keyLength);
                        } catch (e) {
                            print(Level.ERROR, `${e.message} (${address})`);
                        }
                         */
                        print(Level.DEBUG, `[*] GetCertificatePrivateKey: ${name}`);
                        !OEM_CRYPTO_API.includes(name) && print(Level.WARNING, `The function "${name}" does not belong to the referenced functions. Communicate it to the developer to improve the tool.`);
                        send('private_key', bytes);
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

const GetDeviceId = (address, name) => {
    // wvcdm::Properties::GetCdmClientPropertySet
    Interceptor.attach(address, {
        onEnter: function (args) {
            print(Level.DEBUG, '[+] onEnter: getOemcryptoDeviceId');
            this.data = args[0];
            this.size = args[1];
        },
        onLeave: function (retval) {
            print(Level.DEBUG, '[-] onLeave: getOemcryptoDeviceId');
            try {
                const size = Memory.readPointer(this.size).toInt32();
                const data = Memory.readByteArray(this.data, size);
                data && send('client_id', data);
            } catch (e) {
                print(Level.ERROR, `Failed to dump device Id.`);
            }
        }
    });
}


// @Hooks
const hookLibrary = (name) => {
    // https://github.com/poxyran/misc/blob/master/frida-enumerate-imports.py
    const library = getLibrary(name);
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
    const targets = functions.filter(f => OEM_CRYPTO_API.includes(f.name)).map(f => f.name);
    let hooked = 0;

    functions.forEach(func => {
        if (func.type !== 'function') return;
        const {name: funcName, address: funcAddr} = func;

        try {
            if (funcName.includes('UsePrivacyMode')) {
                UsePrivacyMode(funcAddr);
            } else if (funcName.includes('GetCdmClientPropertySet')) {
                GetCdmClientPropertySet(funcAddr);
            } else if (funcName.includes('PrepareKeyRequest')) {
                PrepareKeyRequest(funcAddr);
            } else if (funcName.includes('getOemcryptoDeviceId')) {
                GetDeviceId(funcAddr);
            } else if (targets.includes(funcName) || (!targets.length && funcName.match(/^[a-z]+$/))) {
                GetCertificatePrivateKey(funcAddr, funcName);
            } else {
                return;
            }

            hooked++;
            print(Level.DEBUG, `Hooked (${funcAddr}): ${funcName}`);
        } catch (e) {
            print(Level.ERROR, `${e.message} for ${funcName}`);
        }
    });

    if (hooked < 3) {
        print(Level.CRITICAL, 'Insufficient functions hooked.');
        return false;
    }

    return true;
}

// RPC interfaces exposed to external calls.
rpc.exports = {
    getlibrary: getLibrary,
    hooklibrary: hookLibrary
};
