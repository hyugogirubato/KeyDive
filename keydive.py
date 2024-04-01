import argparse
import logging
import subprocess
import time

import coloredlogs
from _frida import Process
from pathlib import Path

from extractor.cdm import Cdm

coloredlogs.install(
    fmt='%(asctime)s [%(levelname).1s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.DEBUG)

if __name__ == '__main__':
    logger = logging.getLogger('KeyDive')

    # Parse command line arguments for device ID
    parser = argparse.ArgumentParser(description='Extract Widevine L3 keys from an Android device.')
    parser.add_argument('--device', required=False, type=str, help='Target Android device ID.')
    parser.add_argument('--functions', required=False, type=Path, help='Ghidra XML functions file.')
    args = parser.parse_args()

    try:
        # Start ADB server
        exitcode, _ = subprocess.getstatusoutput('adb start-server')
        if exitcode != 0:
            raise EnvironmentError('ADB is not recognized as an environment variable')

        # Initialize CDM handler with given device
        cdm = Cdm(device=args.device, functions=args.functions)

        # Find Widevine process on the device
        process: Process = next((p for p in cdm.device.enumerate_processes() if cdm.vendor.process == p.name), None)
        if not process:
            raise Exception('Failed to find Widevine process')
        logger.info('Process: %s (%s)', process.pid, process.name)

        # Hook into the process to extract DRM keys
        if not cdm.hook_process(process):
            raise Exception('Failed to hook into the process')
        logger.info('Successfully hooked. To test, play a DRM-protected video: https://bitmovin.com/demos/drm')

        # Keep script running while extracting keys
        while cdm.running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.critical(e)
    logger.info('Exiting')
