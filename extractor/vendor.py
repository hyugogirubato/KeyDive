from __future__ import annotations

import logging

logger = logging.getLogger('Vendor')


class Vendor:
    """
    Represents Widevine DRM Vendor details for different Android SDK versions.
    """
    # https://developer.android.com/tools/releases/platforms
    SDK_VERSIONS = {
        # 34: (18, '18.0.0', 'android.hardware.drm-service.widevine-v17', 'android.hardware.drm-service.widevine-v17'),
        34: (18, '18.0.0', 'android.hardware.drm-service.widevine', 'android.hardware.drm-service.widevine'),
        33: (17, '17.0.0', 'android.hardware.drm-service.widevine', 'libwvaidl.so'),
        32: (16, '16.1.0', 'android.hardware.drm@1.4-service.widevine', 'libwvhidl.so'),
        31: (16, '16.1.0', 'android.hardware.drm@1.4-service.widevine', 'libwvhidl.so'),
        30: (16, '16.0.0', 'android.hardware.drm@1.3-service.widevine', 'libwvhidl.so'),
        29: (15, '15.0.0', 'android.hardware.drm@1.2-service.widevine', 'libwvhidl.so'),
        28: (14, '14.0.0', 'android.hardware.drm@1.1-service.widevine', 'libwvhidl.so'),
        27: (13, '5.1.0', 'android.hardware.drm@1.0-service.widevine', 'libwvhidl.so'),
        26: (13, '1.0', 'android.hardware.drm@1.0-service.widevine', 'libwvhidl.so'),
        25: (11, '1.0', 'mediadrmserver', 'libwvdrmengine.so'),
        24: (11, '1.0', 'mediadrmserver', 'libwvdrmengine.so'),
        23: (11, '1.0', 'mediaserver', 'libwvdrmengine.so')
    }
    SDK_MAX = max(SDK_VERSIONS.keys())

    def __init__(self, oem: int, version: str, process: str, library: str):
        """
        Initialize a Vendor instance.

        :param oem: OEM Crypto API level.
        :param version: Widevine CDM version.
        :param process: The process name associated with the Widevine DRM.
        :param library: The library file name used by the DRM process.
        """
        self.oem = oem
        self.version = version
        self.process = process
        self.library = library

    @classmethod
    def from_sdk_api(cls, sdk_api: int) -> Vendor:
        """
        Creates a Vendor instance based on the Android SDK API level.

        :param sdk_api: Android SDK API level.
        :return: A Vendor instance with DRM details.
        """
        assert sdk_api > 22, 'Widevine not implemented for SDK <= 22'

        vendor_details = cls.SDK_VERSIONS.get(sdk_api)
        if not vendor_details:
            vendor_details = cls.SDK_VERSIONS[cls.SDK_MAX]
            logger.warning('CMD version is not yet implemented')
            logger.warning('Using closest supported CDM version: %s', vendor_details[1])
        else:
            logger.info('CDM version: %s' % vendor_details[1])
        logger.info('OEM Crypto API: %s' % vendor_details[0])
        return cls(*vendor_details)
