import logging
import time

from typing import Optional, Tuple, Literal
from pathlib import Path

from frida import ServerNotRunningError, ProtocolError
from frida.core import Session, Script
from pathvalidate import sanitize_filepath

from keydive.adb import DRM_PLAYER, DRM_WEB, NATIVE_C_API
from keydive.adb.remote import Remote
from keydive.adb.vendor import Vendor
from keydive.drm import CDM_VENDOR_API, OEM_CRYPTO_API
from keydive.drm.cdm import Cdm
from keydive.utils import xmldec, dumps


class Server:

    def __init__(self, version: str):
        """
        Initialize the Server instance with the provided Frida version string.

        This constructor sets internal flags based on the Frida version,
        particularly to determine support for features introduced in Frida 16.6.0+.

        Args:
            version (str): The version string of the Frida server (e.g., "16.5.3").
        """
        self.logger = logging.getLogger('Server')

        self.version = version
        self.logger.debug('Frida version: %s', self.version)

        # Parse version string and determine feature support
        code = tuple(map(int, version.split('.')))
        self.features = code[0] > 16 or (code[0] == 16 and code[1] >= 6)
        self.logger.debug('Feature support: %s', self.features)

        # Used to prevent repeated user warnings in logs or dialogs
        self.dialog = False


class Core(Remote):

    def __init__(
            self,
            serial: Optional[str] = None,
            timeout: int = 5,
            symbols: Optional[Path] = None,
            detect: bool = True,
            disabler: bool = True,
            unencrypt: bool = False
    ):
        """
        Initialize the Core object, which manages interaction with a remote device
        and handles Widevine CDM (Content Decryption Module) processes.

        This constructor also prepares a Frida script for hooking and sets up
        internal state for later process attachment and monitoring.

        Args:
            serial (Optional[str]): The serial number of the connected Android device.
                                     If None, the first available device will be used.
            timeout (int): Timeout in seconds for establishing the device connection.
            symbols (Optional[Path]): Path to an XML file containing symbol definitions.
            detect (bool): Whether to enable detection logic in the injected Frida script.
            disabler (bool): Whether to enable anti-tamper or anti-debugging disablers
                             in the Frida script.
            unencrypt (bool): If True, forces license challenge data to be sent unencrypted.
        """
        # Initialize base Remote object with optional serial and connection timeout
        super().__init__(serial=serial, timeout=timeout)
        self.logger = logging.getLogger('Core')

        # Indicates whether the watchdog process is actively running
        self._running = False

        # Server instance (initialized later when Frida is attached)
        self._server: Optional[Server] = None

        # Load and prepare the Frida script with optional symbol resolution
        self._script, self._resolved = self.__hook_script(
            detect=detect,
            disabler=disabler,
            path=symbols,
            unencrypt=unencrypt
        )

        # Initialize CDM (Content Decryption Module) interface with SDK and disabler flag
        self.cdm = Cdm(sdk=self.sdk, disabler=disabler)

    def __hook_script(
            self, detect: bool = True,
            disabler: bool = True,
            path: Optional[Path] = None,
            unencrypt: bool = False
    ) -> Tuple[str, bool]:
        """
        Prepares and customizes a JavaScript hook script with runtime configurations and optional symbol resolution.

        This function reads a base JavaScript file (`keydive.js`), injects configurations and API stubs into it,
        and optionally replaces placeholders with resolved symbol names extracted from an XML file describing
        native functions.

        Args:
            detect (bool): Whether to enable the detection logic in the hook script.
            disabler (bool): Whether to enable the disabler logic in the hook script.
            path (Optional[Path]): An optional path to an XML file containing function metadata (e.g., Ghidra-exported data).
                                   If provided, function symbols are parsed and injected into the script.
            unencrypt (bool): If True, configures the hook script to force client ID and related license
                              challenge data to remain unencrypted.

        Returns:
            Tuple[str, bool]: A tuple where:
                - str is the fully prepared hook script as a string.
                - bool indicates whether symbol data was successfully loaded and injected.

        Exception:
            Exceptions raised while reading or parsing the symbol file are caught and logged.
        """
        # Load the base hook JavaScript file
        script = Path(__file__).with_name('keydive.js').read_text(encoding='utf-8')

        symbols = {}
        if path:
            try:
                # Parse the XML file containing function metadata (e.g., Ghidra export)
                content = xmldec(path.read_bytes(), force_list=['FUNCTION', 'STACK_VAR', 'REGISTER_VAR'])
                program = content['PROGRAM']
                addr_base = int(program['@IMAGE_BASE'], 16)
                functions = program['FUNCTIONS']['FUNCTION']

                # Build a dictionary of function address to name mappings
                for f in functions:
                    address = hex(int(f['@ENTRY_POINT'], 16) - addr_base)
                    name = f['@NAME']

                    # Avoid duplicate entries by checking existing symbol names
                    if name not in symbols.values():
                        symbols[address] = name

                self.logger.info('Successfully loaded %d symbol(s) from: %s', len(symbols), path.as_posix())
            except Exception as e:
                # Log the error if symbol import fails, but continue script generation
                self.logger.error('Unable to import symbols from XML: %s', e)

        # Create the placeholder-to-value mapping
        placeholders = {
            '${OEM_CRYPTO_API}': dumps(OEM_CRYPTO_API),
            '${NATIVE_C_API}': dumps(NATIVE_C_API),
            '${SYMBOLS}': dumps(symbols),
            '${DETECT}': str(detect),
            '${DISABLER}': str(disabler),
            '${UNENCRYPT}': str(unencrypt)
        }

        # Replace placeholders in the script with actual data
        for placeholder, value in placeholders.items():
            script = script.replace(placeholder, value, 1)

        # Return the modified script and a flag indicating if symbol injection was successful
        return script, bool(symbols)

    def launch(self, action: Literal['web', 'player'] = 'player') -> None:
        """
        Launches a DRM-enabled player either as a native application or a web-based player.

        Depending on the selected action, this method ensures that the DRM player app is installed and running,
        or opens a predefined DRM test page in the system browser. It performs basic checks for installation,
        process existence, and handles optional installation if needed.

        Args:
            action (Literal['web', 'player']):
                - 'player': Launch the native DRM player app.
                - 'web': Open the web-based DRM player in the default browser.
        """
        if action == 'player':
            # Retrieve the package name and human-readable name of the DRM player
            player_package = DRM_PLAYER['package']
            player_name = DRM_PLAYER['name']

            self.logger.info('Preparing DRM player: %s (%s)', player_name, player_package)

            # Check if the application is already installed
            installed = player_package in self.enumerate_applications(user=True, system=False)
            if installed:
                self.logger.debug('Application is already installed: %s', player_package)
            else:
                self.logger.debug('Application not found: %s. Attempting to install...', player_package)

                # Try to install the app from the specified path or URL
                if not self.install_application(path=DRM_PLAYER['path'], url=DRM_PLAYER['url']):
                    return  # Stop if installation fails
                self.logger.debug('Application installed successfully: %s', player_package)

            # Check if the application is already running
            player_pid = self.enumerate_processes(names=[player_package])
            if player_pid:
                self.logger.warning('Application is already running: %s (%s)', player_name, player_package)
            else:
                # Attempt to start the application
                self.logger.info('Starting application: %s (%s)', player_name, player_package)
                if not self.start_application(player_package):
                    return  # Abort if unable to launch

                # Give the system a moment to register the new process
                time.sleep(1)
                player_pid = self.enumerate_processes(names=[player_package])

            # Log running process info or fallback if PID is unknown
            if player_pid:
                self.logger.debug('Running process: %s (%s)', list(player_pid.keys())[-1], player_package)
            else:
                self.logger.debug('Unable to determine PID (%s).', player_package)

        elif action == 'web':
            # Attempt to open the DRM test URL in the default browser
            self.logger.info('Opening DRM web player in default browser...')
            if not self.open_url(DRM_WEB):
                return

            # Attempt to detect a running browser process
            player_pid = self.enumerate_processes(names=[
                'com.android.chrome',  # Google Chrome
                'com.sec.android.app.sbrowser',  # Samsung Internet
                'org.mozilla.firefox'  # Mozilla Firefox
            ])

            if player_pid:
                self.logger.debug('Running process: %s (%s)', list(player_pid.keys())[-1], list(player_pid.values())[-1])
            else:
                self.logger.debug('No known browser process detected. Consider adding support for your browser.')

    def watchdog(
            self,
            output: Path,
            delay: int = 1,
            auto_stop: bool = True,
            wvd: bool = False,
            keybox: bool = False
    ) -> None:
        """
        Continuously monitor Widevine DRM processes, export device credentials, and save to disk.

        This method acts as a watchdog that periodically scans for Widevine-capable processes,
        attaches hooks to them, and exports relevant DRM credential files to a specified output directory.
        It supports optional exporting in .wvd format and OEM keyboxes.

        Args:
            output (Path): Directory path where extracted files will be saved.
            delay (int, optional): Delay in seconds between each monitoring iteration. Defaults to 1.
            auto_stop (bool, optional): Automatically stop after successful export of client_id.bin. Defaults to True.
            wvd (bool, optional): Enable exporting credentials in .wvd format compatible with pywidevine. Defaults to False.
            keybox (bool, optional): Enable exporting OEM certificates and keyboxes if available. Defaults to False.

        Raises:
            EnvironmentError: Raised if no Widevine DRM process is detected during scanning.
        """
        self.logger.info('Watcher delay: %ss' % delay)
        self._running = True

        extracted = []  # Tracks already exported files to avoid duplicates
        current = None  # Holds the PID of the currently hooked Widevine process

        while self._running:
            # Export device credentials and DRM data files
            files = self.cdm.export(wvd=wvd, keybox=keybox)
            if files:
                for name, data in files.items():
                    # Sanitize file path to ensure valid filesystem names and create directories
                    # https://github.com/hyugogirubato/KeyDive/issues/14#issuecomment-2146958022
                    path = output / sanitize_filepath(name)
                    path.parent.mkdir(parents=True, exist_ok=True)

                    # If the file already exists and is identical, log a warning (only once) and skip
                    if path.is_file() and path.read_bytes() == data:
                        if path not in extracted:
                            self.logger.warning('File already exists: %s', path)
                            extracted.append(path)
                        continue

                    # If exporting a .wvd file, remove any other .wvd files in the same directory
                    if path.suffix == '.wvd' and path.parent.exists():
                        for file in path.parent.glob('*.wvd'):
                            file.unlink()

                    # Write the file
                    self.logger.info('Exporting file: %s', path)
                    path.write_bytes(data)
                    extracted.append(path)

                # If the client ID has been exported and auto-stop is enabled, stop monitoring
                if 'client_id.bin' in dumps(extracted):
                    self._running = not auto_stop

                if not self._running:
                    self.logger.info('Required files exported successfully.')
                    continue

            # Detect Widevine-capable processes running on the device
            processes = sorted(
                [
                    (pid, (name, vendor))
                    for pid, name in self.enumerate_processes().items()
                    for vendor in CDM_VENDOR_API
                    if vendor.min_sdk <= self.sdk and vendor.is_process(name)
                ],
                key=lambda item: item[1][1].min_sdk,
                reverse=True
            )

            if not processes:
                # No DRM process detected, raise error with guidance for the user
                raise EnvironmentError(
                    'No Widevine DRM process detected. '
                    'Refer to: https://github.com/hyugogirubato/KeyDive/blob/main/docs/PACKAGE.md#drm-info'
                )

            # If previously hooked process is no longer running, clear current hook
            if current and current not in [pid for pid, _ in processes]:
                self.logger.warning('Widevine process terminated or replaced')
                current = None

            # If no current hooked process, attempt to hook one from detected processes
            if not current:
                self.logger.debug('Scanning for Widevine processes...')
                for pid, (name, vendor) in processes:
                    self.logger.info('Detected process: %s (%s)', pid, name)
                    if self.__hook_process(pid, vendor):
                        current = pid
                        break

                if current:
                    self.logger.info('Successfully attached hook to process: %s', current)
                else:
                    self.logger.warning('Widevine library not located yet. Retrying...')

            # Sleep before next monitoring iteration to reduce resource usage
            time.sleep(delay)

    def __process_message(self, message: dict, data: bytes) -> None:
        """
        Callback handler for messages sent from the Frida-injected script.

        This function processes various types of messages and data received from the Frida instrumentation layer.
        It routes them to appropriate CDM (Content Decryption Module) handlers or logs them accordingly.

        Args:
            message (dict): The message dictionary sent from the Frida script.
            data (bytes): The associated binary payload, if any.
        """
        logger = logging.getLogger('Script')
        level = message.get('payload')

        if isinstance(level, int):
            # Log text message from script with given severity level
            logger.log(level=level, msg=data.decode('utf-8'))

            # Stop the runner if a critical or fatal error is reported
            if level in (logging.FATAL, logging.CRITICAL):
                self.running = False

        elif isinstance(level, dict) and 'private_key' in level:
            self.cdm.set_private_key(data, level['private_key'])
        elif level == 'challenge':
            self.cdm.set_challenge(data)
        elif level == 'client_id':
            self.cdm.set_client_id(data)
        elif level == 'keybox':
            self.cdm.set_keybox(data)
        elif level == 'stable_id':
            self.cdm.set_stable_id(data)
        elif level == 'device_id':
            self.cdm.set_device_id(data)
        elif level == 'encryption_context':
            self.cdm.set_encryption_context(data)
        elif level == 'provisioning_method':
            self.cdm.set_provisioning_method(data)
        elif level == 'provisioning_response':
            self.cdm.set_provisioning_response(data)
        elif message.get('type') == 'error':
            # Log any script-side errors
            logger.error(message['description'])
        else:
            # Fallback logging for unrecognized messages
            logger.warning(message, data)

    def __hook_process(self, pid: int, vendor: Vendor, timeout: int = 0) -> bool:
        """
        Hooks into a running process using Frida to enable dynamic analysis and instrumentation.

        This method attaches to a process identified by its PID, loads a Frida script for hooking into
        a vendor-specific shared library, and optionally enables symbolic analysis depending on device
        and server capabilities.

        Args:
            pid (int): Process ID of the target application to attach to.
            vendor (Vendor): A Vendor object containing metadata about the expected shared library.
            timeout (int, optional): Time (in seconds) to persist the Frida session. Defaults to 0.

        Returns:
            bool: True if the hook was successful, False otherwise.

        Raises:
            EnvironmentError: If the Frida server is not running on the target device.
        """
        try:
            # Attach to the target process using the specified PID
            # The 'persist_timeout' parameter ensures the session persists for the given duration
            session: Session = self.socket.attach(pid, persist_timeout=timeout)
        except ServerNotRunningError as e:
            # Handle the case where the Frida server is not running on the device
            raise EnvironmentError('Frida server is not running on the device.') from e
        except ProtocolError as e:
            # Handle the case where the Frida python version is different from the server version
            raise EnvironmentError('Frida python version is different from the server version.') from e
        except Exception as e:
            # Catch and log all other errors that occur during session attachment
            self.logger.error('Could not attach to process %s: %s', pid, e)
            return False

        # Define cleanup behavior for when the Frida script is destroyed
        def __process_destroyed() -> None:
            session.detach()

        # Create and load the Frida script for dynamic analysis
        script: Script = session.create_script(self._script)
        script.on('message', self.__process_message)  # Set message handler
        script.on('destroyed', __process_destroyed)  # Set destruction handler
        script.load()

        # Fetch Frida server metadata (e.g., version) and store it if not already set
        if not self._server:
            self._server = Server(script.exports_sync.getversion())

        # Retrieve the list of loaded libraries in the target process
        libraries = script.exports_sync.getlibraries()
        library = vendor.get_library(libraries)

        if library:
            # Log details about the matching library
            self.logger.info('Library found: %s (%s)', library['name'], library['path'])

            # Provide context-aware warnings about symbol resolution options
            if not self._server.dialog:
                if self._server.features and self._resolved:
                    self.logger.warning('The "--symbols" option is deprecated in Frida 16.6.0 and newer.')
                elif not self._server.features and vendor.min_oem[0] < 18 and self._resolved:
                    self.logger.warning('The "--symbols" option is deprecated for OEM API versions below 18.')
                elif not self._server.features and vendor.min_oem[0] > 17 and not self._resolved:
                    self.logger.warning(
                        'For OEM API > 17, the "--symbols" option is required. '
                        'Refer to: https://github.com/hyugogirubato/KeyDive/blob/main/docs/FUNCTIONS.md'
                    )

            # Determine whether to enable dynamic symbol resolution based on server and vendor context
            dynamic = self._server.features and vendor.min_oem[0] > 17 and not self._resolved

            # Attempt to hook into the identified library with or without dynamic symbols
            status = script.exports_sync.hooklibrary(library['name'], dynamic)
            if not (self._server.dialog or status or self._resolved) and self.sdk > 33:
                # https://github.com/hyugogirubato/KeyDive/issues/60
                self.logger.warning('Detection without symbols failed, try again with the "--symbols" option.')

            self._server.dialog = True
            return status

        # If the expected library was not found, clean up and notify the user
        script.unload()
        self.logger.warning('Expected library not found: %s' % vendor.library)
        return False


__all__ = ('Core',)
