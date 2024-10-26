import argparse
import logging
import time

from datetime import datetime
from pathlib import Path

import coloredlogs

import keydive

from keydive.adb import ADB
from keydive.cdm import Cdm
from keydive.constants import CDM_VENDOR_API, DRM_PLAYER
from keydive.core import Core


def configure_logging(path: Path = None, verbose: bool = False) -> Path:
    """
    Configures logging for the application.

    Args:
        path (Path, optional): The directory to store log files.
        verbose (bool, optional): Flag to enable detailed debug logging.

    Returns:
        Path: The path of log file.
    """
    # Set up the root logger with the desired logging level
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Clear any existing handlers (optional, to avoid duplicate logs if reconfiguring)
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    file_path = None
    if path:
        # Ensure the log directory exists
        if path.is_file():
            path = path.parent
        path.mkdir(parents=True, exist_ok=True)

        # Create a file handler
        file_path = path / ('keydive_%s.log' % datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        file_path = file_path.resolve(strict=False)
        file_handler = logging.FileHandler(file_path)
        file_handler.setLevel(logging.DEBUG)

        # Set log formatting
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
    """
    Main entry point for the KeyDive application.

    This application extracts Widevine L3 keys from an Android device.
    It supports device management via ADB and allows hooking into Widevine processes.
    """
    parser = argparse.ArgumentParser(description='Extract Widevine L3 keys from an Android device.')

    # Global arguments for the application
    group_global = parser.add_argument_group('Global')
    group_global.add_argument('-d', '--device', required=False, type=str, metavar='<id>', help='Specify the target Android device ID for ADB connection.')
    group_global.add_argument('-v', '--verbose', required=False, action='store_true', help='Enable verbose logging for detailed debug output.')
    group_global.add_argument('-l', '--log', required=False, type=Path, metavar='<dir>', help='Directory to store log files.')
    group_global.add_argument('--delay', required=False, type=float, metavar='<delay>', default=1, help='Delay (in seconds) between process checks.')
    group_global.add_argument('--version', required=False, action='store_true', help='Display KeyDive version information.')

    # Arguments specific to the CDM (Content Decryption Module)
    group_cdm = parser.add_argument_group('Cdm')
    group_cdm.add_argument('-o', '--output', required=False, type=Path, default=Path('device'), metavar='<dir>', help='Output directory for extracted data.')
    group_cdm.add_argument('-w', '--wvd', required=False, action='store_true', help='Generate a pywidevine WVD device file.')
    group_cdm.add_argument('-s', '--skip', required=False, action='store_true', help='Skip auto-detection of the private function.')
    group_cdm.add_argument('-a', '--auto', required=False, action='store_true', help='Automatically start the Bitmovin web player.')
    group_cdm.add_argument('-p', '--player', required=False, action='store_true', help='Install and start the Kaltura app automatically.')

    # Advanced options
    group_advanced = parser.add_argument_group('Advanced')
    group_advanced.add_argument('-f', '--functions', required=False, type=Path, metavar='<file>', help='Path to Ghidra XML functions file.')
    # group_advanced.add_argument('-k', '--keybox', required=False, action='store_true', help='Export keybox if available.')
    group_advanced.add_argument('--challenge', required=False, type=Path, metavar='<file>', help='Path to unencrypted challenge for extracting client ID.')
    group_advanced.add_argument('--private-key', required=False, type=Path, metavar='<file>', help='Path to private key for extracting client ID.')

    args = parser.parse_args()

    if args.version:
        print(f'KeyDive {keydive.__version__}')
        exit(0)

    # Configure logging
    log_path = configure_logging(path=args.log, verbose=args.verbose)
    logger = logging.getLogger('KeyDive')
    logger.info('Version: %s', keydive.__version__)

    try:
        # Connect to the specified Android device
        adb = ADB(device=args.device)

        # Initialize Cdm instance
        cdm = Cdm()
        if args.challenge:
            cdm.set_challenge(data=args.challenge)
        if args.private_key:
            cdm.set_private_key(data=args.private_key, name=None)

        # Initialize Core instance for interacting with the device
        core = Core(adb=adb, cdm=cdm, functions=args.functions, skip=args.skip)

        # Process watcher loop
        logger.info('Watcher delay: %ss' % args.delay)
        current = None  # Variable to track the current Widevine process
        while core.running:
            # Check if for current process data has been exported
            if current and cdm.export(args.output, args.wvd):
                raise KeyboardInterrupt  # Stop if export is complete

            # https://github.com/hyugogirubato/KeyDive/issues/14#issuecomment-2146788792
            # Get the currently running Widevine processes
            processes = {
                key: (name, pid)
                for name, pid in adb.enumerate_processes().items()
                for key in CDM_VENDOR_API.keys()
                if key in name or key.replace('-service', '-service-lazy') in name
            }

            if not processes:
                raise EnvironmentError('Unable to detect Widevine, refer to https://github.com/hyugogirubato/KeyDive/blob/main/docs/PACKAGE.md#drm-info')

            # Check if the current process has changed
            if current and current not in [v[1] for v in processes.values()]:
                logger.warning('Widevine process has changed')
                current = None

            # If current process not found, attempt to hook into the detected processes
            if not current:
                logger.debug('Analysing...')

                for key, (name, pid) in processes.items():
                    if current:
                        break
                    for vendor in CDM_VENDOR_API[key]:
                        if core.hook_process(pid=pid, vendor=vendor):
                            logger.info('Process: %s (%s)', pid, name)
                            current = pid
                            break
                        elif not core.running:
                            raise KeyboardInterrupt

                # Setup actions based on user arguments
                if current:
                    logger.info('Successfully hooked')
                    if args.player:
                        package = DRM_PLAYER['package']

                        # Check if the application is already installed
                        if not package in adb.list_applications(user=True, system=False):
                            logger.debug('Application %s not found. Installing...', package)
                            if not adb.install_application(path=DRM_PLAYER['path'], url=DRM_PLAYER['url']):
                                logger.error('Failed to install application')
                                continue  # Skip starting the application if installation failed

                        # Start the application
                        logger.info('Starting application: %s', package)
                        adb.start_application(package)
                    elif args.auto:
                        logger.info('Opening the Bitmovin web player...')
                        adb.open_url('https://bitmovin.com/demos/drm')

                    logger.info('Setup completed')
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
