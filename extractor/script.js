/**
 * KeyDive: Widevine L3 Extractor for Android Devices
 * Enhances DRM key extraction for research and educational purposes.
 * Source: https://github.com/hyugogirubato/KeyDive
 */

const SDK_API = '${SDK_API}'; // Dynamically replaced with the actual SDK API level.
const OEM_CRYPTO_API = [
    // Mapping of function names across different API levels (obfuscated names may vary).
    'rnmsglvj', 'polorucp', 'kqzqahjq', 'pldrclfq', 'kgaitijd',
    'cwkfcplc', 'crhqcdet', 'ulns', 'dnvffnze', 'ygjiljer',
    'qbjxtubz', 'qkfrcjtw', 'rbhjspoh'
    // Add more as needed for different versions.
];


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

// Utility for encoding strings into byte arrays.
// https://gist.github.com/Yaffle/5458286#file-textencodertextdecoder-js
function TextEncoder() {}
TextEncoder.prototype.encode = function (string) {
    let octets = [];
    let i = 0;
    while (i < string.length) {
        let codePoint = string.codePointAt(i);
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

const print = (level, message) => {
    message = typeof message === 'object' ? JSON.stringify(message) : message;
    send(level, new TextEncoder().encode(message));
}

// Identifies and returns the specified library.
const getLibrary = (name) => Process.getModuleByName(name);

// Hooks into specified functions within a library, aiming to extract keys and disable privacy mode.
const hookLibrary = (name) => {
    // https://github.com/poxyran/misc/blob/master/frida-enumerate-imports.py
    const library = getLibrary(name);
    const functions = [...library.enumerateExports(), ...library.enumerateImports()];
    const targetFunction = functions.find(func => OEM_CRYPTO_API.includes(func.name));

    let hookedCount = 0;
    functions.forEach((func) => {
        const funcName = func.name;
        const funcAddr = func.address;

        try {
            let funcHooked = true;
            if (funcName.includes('UsePrivacyMode')) {
                disablePrivacyMode(funcAddr);
            } else if (funcName.includes('PrepareKeyRequest')) {
                prepareKeyRequest(funcAddr);
            } else if (targetFunction === func || (!targetFunction && funcName.match(/^[a-z]+$/))) {
                getPrivateKey(funcAddr);
            } else {
                funcHooked = false;
            }

            if (funcHooked) {
                hookedCount++;
                print(Level.DEBUG, `Hooked (${funcAddr}): ${funcName}`);
            }
        } catch (e) {
            print(Level.ERROR, `${funcName} (${funcAddr}): ${e.message}`);
        }
    });

    if (hookedCount < 3) {
        print(Level.ERROR, 'Insufficient functions hooked');
        return false;
    }
    return true;
}

const disablePrivacyMode = (address) => {
    Interceptor.attach(ptr(address), {
        onLeave: function (retval) {
            retval.replace(ptr(0));
        }
    });
}

const prepareKeyRequest = (address) => {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            let index;
            if ([23, 31, 32, 33].includes(SDK_API)) {
                index = 5;
            } else if ([24, 25, 26, 27, 28, 29, 30].includes(SDK_API)) {
                index = 4;
            } else {
                index = 5; // Default index assignment
                print(Level.WARNING, 'SDK API not implemented');
                print(Level.WARNING, `Defaulting to args[${index}] for PrepareKeyRequest`);
            }
            this.ret = args[index];
        },
        onLeave: function () {
            if (this.ret) {
                const size = Memory.readU32(ptr(this.ret).add(Process.pointerSize));
                const data = Memory.readByteArray(this.ret.add(Process.pointerSize * 2).readPointer(), size);
                send('device_info', data);
            }
        }
    });
}

const getPrivateKey = (address) => {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            if (!args[6].isNull()) {
                const size = args[6].toInt32();
                if (size >= 1000 && size <= 2000 && !args[5].isNull()) {
                    const buffer = args[5].readByteArray(size);
                    const bytes = new Uint8Array(buffer);
                    // Check for DER encoding markers for the beginning of a private key (MII).
                    if (bytes[0] === 0x30 && bytes[1] === 0x82) {
                        try {
                            // Attempt to extract and send the private key.
                            const binaryString = a2bs(bytes);
                            const keyLength = getKeyLength(binaryString); // ASN.1 DER
                            const key = bytes.slice(0, keyLength);
                            print(Level.DEBUG, `Function getPrivateKey() at ${address}`);
                            send('private_key', key);
                        } catch (e) {
                            print(Level.ERROR, `${e.message} (${address})`);
                        }
                    }
                }
            }
        }
    });
}

const a2bs = (bytes) => Array.from(bytes).map(byte => String.fromCharCode(byte)).join('');

const getKeyLength = (key) => {
    let pos = 1; // Skip the initial tag
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
    for (let i = 0; i < lengthByte; i++) {
        lengthValue = (lengthValue << 8) + key.charCodeAt(pos++);
    }
    return pos + Math.abs(lengthValue);
}


// Exposing functions for RPC calls.
rpc.exports = {
    getlibrary: getLibrary,
    hooklibrary: hookLibrary
};