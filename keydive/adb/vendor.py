import re

from typing import List, Optional, Tuple


class Vendor:
    """
    Represents a vendor-specific configuration including process name, minimum SDK version,
    OEM versioning information, and the name of a related native library.

    This class is used to identify vendor-specific behaviors on Android devices and provides
    regex-based helpers for pattern matching against processes and libraries.
    """

    def __init__(
            self,
            process: str,
            min_sdk: int,
            min_oem: Tuple[int, str],
            library: str
    ):
        """
        Initializes a Vendor instance with identifying details.

        Args:
            process (str): The name of the process to identify for the vendor (can be pattern-based).
            min_sdk (int): The minimum required Android SDK version for compatibility.
            min_oem (Tuple[int, str]): Tuple defining the minimum OEM version, e.g., (version_code, version_name).
            library (str): The shared library name or pattern used by the vendor.

        """
        self.process = process
        self.min_sdk = min_sdk
        self.min_oem = min_oem
        self.library = library

    def __repr__(self) -> str:
        """
        Generates a string representation of the current instance for debugging purposes.

        This method is primarily used to help developers understand the state of the object
        during logging or interactive debugging by displaying all attribute names and values
        in a clean, readable format.

        Returns:
            str: A string showing the class name and its instance variables with their values.
        """
        # Construct a formatted string with the class name and a list of key=value pairs from the instance's attributes
        return '{name}({items})'.format(
            name=self.__class__.__name__,
            items=', '.join([f'{k}={repr(v)}' for k, v in self.__dict__.items()])
        )

    @staticmethod
    def __pattern(value: str) -> str:
        """
        Converts a given string into a regex-compatible pattern that allows for matching
        flexible naming conventions found in Android service or library identifiers.

        This is particularly useful when dealing with variant suffixes (e.g., `-lazy`, version tags),
        or optional annotations (e.g., `@<version>` in `.so` or `.widevine` modules).

        Args:
            value (str): The base string (e.g., filename or service name) to convert into a regex pattern.

        Returns:
            str: A regex pattern that can be used to match common variants of the input string.
        """
        return (value
                .replace('-service', r'-service(?:-lazy)?')
                .replace('.widevine', r'.widevine(?:@\S+)?')
                .replace('.so', r'(?:@\S+)?.so')
                .replace('.', r'\.'))

    def is_process(self, value: str) -> bool:
        """
        Determines whether the provided process name matches the expected vendor-specific process pattern.

        This is useful when trying to detect or hook into a known target process,
        especially when its name can include runtime-specific suffixes (e.g., versioned .so files or services).

        Args:
            value (str): The name of the process to evaluate.

        Returns:
            bool: True if the process name matches the generated pattern; otherwise, False.
        """
        # Generate a regex pattern from the expected process name
        pattern = self.__pattern(self.process)

        # Check if the input value matches the regex pattern
        return bool(re.match(pattern, value))

    def get_library(self, values: List[dict]) -> Optional[dict]:
        """
        Retrieves the first matching library dictionary from a provided list based on a dynamically generated regex pattern.

        This method is useful when trying to identify a target library in a list of shared objects (e.g., `.so` files),
        especially when the exact name may include version tags or runtime decorations (e.g., `libxyz@1.2.so`).

        Args:
            values (List[dict]): A list of dictionaries, each expected to contain a 'name' key with the library's filename.

        Returns:
            Optional[dict]: The first dictionary whose 'name' matches the expected regex pattern; returns None if no match is found.
        """
        # Create a regex pattern based on the expected library name, allowing flexibility for suffixes or variants
        pattern = self.__pattern(self.library)

        # Iterate through the list and return the first dictionary with a matching 'name'
        return next((v for v in values if re.match(pattern, v['name'])), None)


__all__ = ('Vendor',)
