import argparse
import logging
import subprocess
import time

import coloredlogs
from pathlib import Path

import extractor
from extractor.cdm import Cdm

coloredlogs.install(
    fmt='%(asctime)s [%(levelname).1s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.DEBUG)

if __name__ == '__main__':
    logger = logging.getLogger('KeyDive')

    # Parse command line arguments for device ID
    parser = argparse.ArgumentParser(description='Extract Widevine L3 keys from an Android device.')
    parser.add_argument('-d', '--device', required=False, type=str, help='Target Android device ID.')
    parser.add_argument('-f', '--functions', required=False, type=Path, help='Path to Ghidra XML functions file.')
    parser.add_argument('--force', required=False, action='store_true', help='Force using the default vendor (skipping analysis).')

    args = parser.parse_args()

    try:
        logger.info('Version: %s', extractor.__version__)

        # Ensure the ADB server is running
        exitcode, _ = subprocess.getstatusoutput('adb start-server')
        if exitcode != 0:
            raise EnvironmentError('ADB is not recognized as an environment variable, see https://github.com/hyugogirubato/KeyDive/blob/main/docs/PACKAGE.md#adb-android-debug-bridge')

        # Initialize the CDM handler with the specified or default device
        cdm = Cdm(device=args.device, functions=args.functions, force=args.force)

        # Attempt to locate and identify the Widevine process on the target device
        pid = cdm.enumerate_processes().get(cdm.vendor.process)
        if not pid:
            raise EnvironmentError('Widevine process not found on the device')
        logger.info('Process: %s (%s)', pid, cdm.vendor.process)

        # Hook into the identified process for DRM key extraction
        if not cdm.hook_process(pid=pid):
            raise Exception('Failed to hook into the Widevine process')
        logger.info('Successfully hooked. To test, play a DRM-protected video: https://bitmovin.com/demos/drm')

        # Keep script running while extracting keys
        while cdm.running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.critical(e)
    logger.info('Exiting')
