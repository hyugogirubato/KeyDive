import argparse
import logging
import subprocess
import time
from datetime import datetime
from pathlib import Path

import coloredlogs

import keydive
from keydive.cdm import Cdm
from keydive.constants import CDM_VENDOR_API
from keydive.core import Core


def configure_logging(path: Path, verbose: bool) -> Path:
    """
    Configures logging for the application.

    Args:
        path (Path, optional): The path for log files.
        verbose (bool): Whether to enable verbose logging.

    Returns:
        Path: The path of log file.
    """
    # Get the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Clear any existing handlers (optional, to avoid duplicate logs if reconfiguring)
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    file_path = None
    if path:
        if path.is_file():
            path = path.parent

        path.mkdir(parents=True, exist_ok=True)

        # Create a file handler
        file_path = path / ('keydive_%s.log' % datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        file_path = file_path.resolve(strict=False)
        file_handler = logging.FileHandler(file_path)
        file_handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            fmt='%(asctime)s [%(levelname).1s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)

        # Add the file handler to the root logger
        root_logger.addHandler(file_handler)

    # Configure coloredlogs for console output
    coloredlogs.install(
        fmt='%(asctime)s [%(levelname).1s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.DEBUG if verbose else logging.INFO,
        logger=root_logger
    )
    return file_path


def main() -> None:
    parser = argparse.ArgumentParser(description='Extract Widevine L3 keys from an Android device.')

    # Global options
    opt_global = parser.add_argument_group('Global options')
    opt_global.add_argument('-d', '--device', required=False, type=str, metavar='<id>', help='Specify the target Android device ID to connect with via ADB.')
    opt_global.add_argument('-v', '--verbose', required=False, action='store_true', help='Enable verbose logging for detailed debug output.')
    opt_global.add_argument('-l', '--log', required=False, type=Path, metavar='<dir>', help='Directory to store log files.')
    opt_global.add_argument('--delay', required=False, type=float, metavar='<delay>', default=1, help='Delay (in seconds) between process checks in the watcher.')
    opt_global.add_argument('--version', required=False, action='store_true', help='Display KeyDive version information.')

    # Cdm options
    opt_cdm = parser.add_argument_group('Cdm options')
    opt_cdm.add_argument('-a', '--auto', required=False, action='store_true', help='Automatically open Bitmovin\'s demo.')
    opt_cdm.add_argument('-c', '--challenge', required=False, type=Path, metavar='<file>', help='Path to unencrypted challenge for extracting client ID.')
    opt_cdm.add_argument('-w', '--wvd', required=False, action='store_true', help='Generate a pywidevine WVD device file.')
    opt_cdm.add_argument('-o', '--output', required=False, type=Path, default=Path('device'), metavar='<dir>', help='Output directory path for extracted data.')
    opt_cdm.add_argument('-f', '--functions', required=False, type=Path, metavar='<file>', help='Path to Ghidra XML functions file.')
    args = parser.parse_args()

    if args.version:
        print(f'KeyDive {keydive.__version__}')
        exit(0)

    # Configure logging
    log_path = configure_logging(path=args.log, verbose=args.verbose)
    logger = logging.getLogger('KeyDive')
    logger.info('Version: %s', keydive.__version__)

    try:
        # Start the ADB server if not already running
        sp = subprocess.run(['adb', 'start-server'], capture_output=True)
        if sp.returncode != 0:
            raise EnvironmentError('ADB is not recognized as an environment variable, refer to https://github.com/hyugogirubato/KeyDive/blob/main/docs/PACKAGE.md#adb-android-debug-bridge')

        # Initialize Cdm instance
        cdm = Cdm()
        if args.challenge:
            cdm.set_challenge(data=args.challenge)

        # Initialize Core instance for interacting with the device
        core = Core(cdm=cdm, device=args.device, functions=args.functions)

        # Map process keys to their compatible CDM vendors
        cdm_vendor = {}
        for key, vendors in CDM_VENDOR_API.items():
            for vendor in vendors:
                # Check if vendor's SDK matches the core's SDK or the previous version
                if vendor.sdk in (core.sdk_api, core.sdk_api - 1):
                    cdm_vendor.setdefault(key, []).append(vendor)

        if not cdm_vendor:
            raise NotImplementedError('SDK version is not supported.')

        # Process watcher loop
        logger.info('Watcher delay: %ss' % args.delay)
        current = None
        while core.running:
            # https://github.com/hyugogirubato/KeyDive/issues/14#issuecomment-2146788792
            processes = {
                key: (name, pid)
                for name, pid in core.enumerate_processes().items()
                for key in cdm_vendor.keys() if key in name
            }

            if not processes:
                raise EnvironmentError('Unable to detect Widevine, refer to https://github.com/hyugogirubato/KeyDive/blob/main/docs/PACKAGE.md#drm-info')

            # Check if the current process has changed
            if current:
                if current not in [v[1] for v in processes.values()]:
                    logger.warning('Widevine process has changed')
                    current = None
                elif cdm.export(args.output, args.wvd):
                    raise KeyboardInterrupt

            # If current process not found, attempt to hook into the detected processes
            if not current:
                logger.debug('Analysing...')

                for key, (name, pid) in processes.items():
                    if current:
                        break
                    for vendor in cdm_vendor[key]:
                        if core.hook_process(pid=pid, vendor=vendor):
                            logger.info('Process: %s (%s)', pid, name)
                            current = pid
                            break
                        elif not core.running:
                            raise KeyboardInterrupt

                if current:
                    logger.info('Successfully hooked.')
                    if args.auto:
                        logger.info('Starting DRM player launch process...')
                        sp = subprocess.run(['adb', '-s', str(core.device.id), 'shell', 'am', 'start', '-a', 'android.intent.action.VIEW', '-d', 'https://bitmovin.com/demos/drm'], capture_output=True)
                        if sp.returncode != 0:
                            logger.error('Error launching DRM player: %s' % sp.stdout.decode('utf-8').strip())
                else:
                    logger.warning('Widevine library not found, searching...')

            # Delay before next iteration
            time.sleep(args.delay)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.critical(e, exc_info=args.verbose)

    # Final logging and exit
    if log_path:
        logger.info('Log file: %s' % log_path)
    logger.info('Exiting')


if __name__ == '__main__':
    main()
