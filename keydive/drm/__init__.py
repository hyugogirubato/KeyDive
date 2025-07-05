from keydive.adb.vendor import Vendor

# Maximum clear API level for Keybox
# https://cs.android.com/android/platform/superproject/+/android14-qpr3-release:trusty/user/app/sample/hwcrypto/keybox/keybox.c
KEYBOX_MAX_CLEAR_API = 28

# https://cs.android.com/search?q=oemcrypto&sq=&ss=android%2Fplatform%2Fsuperproject
OEM_CRYPTO_API = (
    # Mapping of function names across different API levels (obfuscated names may vary).
    'rnmsglvj', 'polorucp', 'kqzqahjq', 'pldrclfq', 'kgaitijd', 'cwkfcplc', 'crhqcdet', 'ulns', 'dnvffnze', 'ygjiljer',
    'qbjxtubz', 'qkfrcjtw', 'rbhjspoh', 'zgtjmxko', 'igrqajte', 'ofskesua', 'qllcoacg', 'pukctkiv', 'ehdqmfmd',
    'xftzvkwx', 'gndskkuk', 'wcggmnnx', 'kaatohcz', 'ktmgdchz', 'jkcwonus', 'ehmduqyt', 'vewtuecx', 'mxrbzntq',
    'isyowgmp', 'flzfkhbc', 'rtgejgqb', 'sxxprljw', 'ebxjbtxl', 'pcmtpkrj', 'uegpdzus', 'ncmqbmbc', 'faokrmio'
    # Add more as needed for different versions.
)

# https://developers.google.com/widevine
CDM_FUNCTIONS = (
    'UsePrivacyMode',
    'GetCdmClientPropertySet',
    'PrepareKeyRequest',
    'AesCbcKey',
    'Read', '_x1c36',
    'runningcrc',
    '_oecc07', '_lcc07',
    '_oecc04', '_lcc04',
    '_oecc49', '_lcc49',
    '_oecc12', '_lcc12', '_oecc95', '_lcc95',
    #'_oecc21', '_lcc21',
    'GenerateDerivedKeys'
)

# https://developer.android.com/tools/releases/platforms
CDM_VENDOR_API = (
    Vendor('mediaserver', 22, (11, '1.0'), 'libwvdrmengine.so'),
    Vendor('mediadrmserver', 24, (11, '1.0'), 'libwvdrmengine.so'),
    Vendor('android.hardware.drm@1.0-service.widevine', 26, (13, '5.1.0'), 'libwvhidl.so'),
    Vendor('android.hardware.drm@1.1-service.widevine', 28, (14, '14.0.0'), 'libwvhidl.so'),
    Vendor('android.hardware.drm@1.2-service.widevine', 29, (15, '15.0.0'), 'libwvhidl.so'),
    Vendor('android.hardware.drm@1.3-service.widevine', 30, (16, '16.0.0'), 'libwvhidl.so'),
    Vendor('android.hardware.drm@1.4-service.widevine', 31, (16, '16.1.0'), 'libwvhidl.so'),
    Vendor('android.hardware.drm-service.widevine', 33, (17, '17.0.0'), 'libwvaidl.so'),
    Vendor('android.hardware.drm-service.widevine', 34, (18, '18.0.0'), 'android.hardware.drm-service.widevine')
)

# https://github.com/kaltura/kaltura-device-info-android/blob/master/app/src/main/java/com/kaltura/kalturadeviceinfo/Collector.java#L317
CDM_PROPERTIES = {
    'CompanyName': 'ro.product.manufacturer',
    'ModelName': 'ro.product.model',
    'ArchitectureName': 'ro.product.cpu.abi',
    'DeviceName': 'ro.product.device',
    'ProductName': 'ro.product.name',
    'BuildInfo': 'ro.build.fingerprint'
}
