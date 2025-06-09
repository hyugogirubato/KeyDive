import logging

from pathlib import Path
from argparse import ArgumentParser

from rich_argparse import RichHelpFormatter

import keydive
from keydive.core import Core
from keydive.utils import configure_logging


def main() -> None:
    parser = ArgumentParser(
        description='Extract Widevine CDM components from an Android device.',
        formatter_class=RichHelpFormatter)

    global_group = parser.add_argument_group('Global Options')
    global_group.add_argument('-s', '--serial', type=str, metavar='<serial>', help='ADB serial number of the target Android device.')
    global_group.add_argument('-d', '--delay', type=float, metavar='<delay>', default=1.0, help='Delay in seconds between process status checks. (default: 1.0)')
    global_group.add_argument('-v', '--verbose', action='store_true', help='Enable detailed logging for debugging.')
    global_group.add_argument('-l', '--log', type=Path, metavar='<dir>', help='Directory to save log files.')
    global_group.add_argument('-V', '--version', action='store_true', help='Show tool version and exit.')

    cdm_group = parser.add_argument_group('CDM Extraction')
    cdm_group.add_argument('-o', '--output', type=Path, default='device', metavar='<dir>', help='Directory to store extracted CDM files. (default: ./device)')
    cdm_group.add_argument('-w', '--wvd', action='store_true', help='Export data in pywidevine-compatible WVD format.')
    cdm_group.add_argument('-k', '--keybox', action='store_true', help='Export Widevine keybox if available on the device.')
    cdm_group.add_argument('-a', '--auto', choices=['web', 'player'], metavar='<type>', help='Automatically launch a DRM playback test. ("web" or "player")')

    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument('--no-detect', action='store_false', help='Disable automatic detection of OEM private key function.')
    advanced_group.add_argument('--no-disabler', action='store_false', help='Disable liboemcrypto-disabler module (patches memory protection).')
    advanced_group.add_argument('--no-stop', action='store_false', help='Do not stop once minimum CDM data is intercepted.')
    advanced_group.add_argument('--unencrypt', action='store_true', help='Force the license challenge to keep client ID data unencrypted.')
    advanced_group.add_argument('--symbols', type=Path, metavar='<symbols>', help='Path to Ghidra-generated XML symbol file for function mapping.')
    advanced_group.add_argument('--challenge', action='append', type=Path, metavar='<challenge>', help='Protobuf challenge file(s) captured via MITM proxy.')
    advanced_group.add_argument('--rsa-key', action='append', type=Path, metavar='<rsa-key>', help='RSA private key(s) in PEM or DER format for client ID decryption.')
    advanced_group.add_argument('--aes-key', action='append', type=str, metavar='<aes-key>', help='AES key(s) in hex, base64, or file form for decrypting keybox data.')

    # Parse command-line arguments
    args = parser.parse_args()

    # Handle version flag early and exit
    if args.version:
        print(f'KeyDive {keydive.__version__}')
        return

    # Set up logging (to file if specified, otherwise stdout)
    log_path = configure_logging(path=args.log, verbose=args.verbose)
    logger = logging.getLogger('keydive')
    logger.info('Version: %s', keydive.__version__)

    try:
        # Initialize core logic with device serial, Ghidra symbols, and feature toggles
        core = Core(
            serial=args.serial,
            symbols=args.symbols,
            detect=args.no_detect,
            disabler=args.no_disabler,
            unencrypt=args.unencrypt
        )

        # Provide challenge files if intercepted (optional, used for verification/analysis)
        core.cdm.set_challenge(data=args.challenge)

        # Provide RSA private keys (PEM or DER format) for client ID decryption
        core.cdm.set_private_key(data=args.rsa_key, name=None)

        # Provide AES key(s) for decrypting the keybox or related data
        core.cdm.set_device_aes_key(data=args.aes_key)

        # Optionally launch a DRM playback test (web-based or player-based)
        if args.auto:
            core.launch(action=args.auto)

        # Begin monitoring the device to extract Widevine CDM data
        # Stops automatically if sufficient data is collected, unless --no-stop is specified
        core.watchdog(output=args.output, delay=args.delay, auto_stop=args.no_stop, wvd=args.wvd, keybox=args.keybox)
    except KeyboardInterrupt:
        # Graceful exit on user interrupt (Ctrl+C)
        pass
    except Exception as e:
        # Log any unhandled exception, include traceback if verbose logging is enabled
        logger.critical(e, exc_info=args.verbose)

    # Log the path to the log file if it was created
    if log_path:
        logger.info('Log file: %s' % log_path)

    logger.info('Exiting')


if __name__ == '__main__':
    main()
