import base64
import json
import logging

from datetime import datetime
from pathlib import Path
from typing import Union, Optional
from uuid import UUID

import coloredlogs
import xmltodict

from unidecode import unidecode


def unidec(data: str) -> str:
    """
    Normalizes a string by removing diacritics and accents using ASCII transliteration.

    Args:
        data (str): The input string to normalize.

    Returns:
        str: The transliterated and stripped version of the input string.
    """
    return unidecode(data).strip()


def b64enc(data: Union[bytes, str], safe: bool = False) -> str:
    """
    Encodes data to Base64 format.

    Args:
        data (bytes or str): The data to encode.
        safe (bool): Use URL-safe encoding if True.

    Returns:
        str: Base64-encoded string.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return (base64.urlsafe_b64encode(data) if safe else base64.b64encode(data)).decode('utf-8')


def b64dec(data: str, safe: bool = False) -> bytes:
    """
    Decodes Base64-encoded string to bytes.

    Args:
        data (str): Base64-encoded string.
        safe (bool): Use URL-safe decoding if True.

    Returns:
        bytes: Decoded byte data.
    """
    # Fix missing padding
    data = data + '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data) if safe else base64.b64decode(data)


def xmldec(data: Union[bytes, str], force_list: Optional[list] = None) -> dict:
    """
    Parses XML string or bytes into a dictionary.

    Args:
        data (str or bytes): The XML data to parse.
        force_list (list, optional): Tags to always parse as lists.

    Returns:
        dict: Parsed XML structure.
    """
    return xmltodict.parse(data, force_list=set(force_list or []))


def dumps(data: Union[dict, list], beauty: bool = False) -> str:
    """
    Serializes a Python object into JSON, handling binary, nested, and custom types.

    Args:
        data (dict or list): The data to serialize.
        beauty (bool): If True, formats JSON with indentation for readability.

    Returns:
        str: A JSON-formatted string.
    """

    def __string(value):
        # Recursively process lists
        if isinstance(value, list):
            return [__string(v) for v in value]

        # Recursively process dictionaries
        elif isinstance(value, dict):
            return {__string(k): __string(v) for k, v in value.items()}

        # Handle byte values (e.g., raw data, encoded JSON, binary keys)
        elif isinstance(value, bytes):
            if value:
                # Try decoding as JSON
                try:
                    return __string(json.loads(value))
                except ValueError:
                    pass

                # Try decoding as UTF-8 string
                try:
                    return value.decode('utf-8')
                except UnicodeDecodeError:
                    pass

                # Handle specific known binary formats (e.g., 16-byte AES keys)
                if len(value) == 16:
                    return value.hex()

                # Fallback: encode to base64 string for general binary data
                return b64enc(value)

            # Return None for empty bytes
            return None

        # Recurse again for nested structures
        elif isinstance(value, (dict, list)):
            return __string(value)

        # Convert known non-serializable types to string
        elif isinstance(value, (UUID, datetime, Path)):
            return str(value)

        # If value is a string, try parsing it as JSON
        elif isinstance(value, str):
            try:
                return __string(json.loads(value))
            except ValueError:
                pass

        # Return all other values unchanged
        return value

    # Perform final JSON serialization with optional pretty-printing
    return json.dumps(
        __string(data),
        indent=2 if beauty else None,
        separators=None if beauty else (',', ':')  # Compact output if not pretty
    )


def configure_logging(path: Optional[Path] = None, verbose: bool = False) -> Optional[Path]:
    """
    Configures logging to file and console with optional verbosity.

    Args:
        path (Path, optional): Directory to save the log file.
        verbose (bool): Enable debug-level logging if True.

    Returns:
        Path or None: Path to log file if created, otherwise None.
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
    # 'black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white'
    coloredlogs.install(
        fmt='%(asctime)s [%(levelname).1s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.DEBUG if verbose else logging.INFO,
        logger=root_logger,
        field_styles={
            'asctime': {'color': 'green'},  # timestamp
            'hostname': {'color': 'magenta'},
            'levelname': {'bold': True, 'color': 'blue'},  # level e.g., [I]
            'name': {'color': 'magenta'},  # logger name
            'programname': {'color': 'cyan'},
            'message': {'color': 'white'}  # message text
        },
        level_styles={
            'debug': {'color': 'cyan'},
            'info': {'color': 'white'},
            'warning': {'color': 'yellow'},
            'error': {'color': 'red'},
            'critical': {'bold': True, 'color': 'red'}
        }
    )

    return file_path
