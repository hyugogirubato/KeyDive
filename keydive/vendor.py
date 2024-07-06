class Vendor:
    """
    Represents a Vendor with OEM, version, and name attributes.
    """

    def __init__(self, oem: int, version: str, name: str):
        """
        Initializes a Vendor instance.

        Args:
            oem (int): The OEM identifier.
            version (str): The version of the vendor.
            name (str): The name of the vendor.
        """
        self.oem = oem
        self.version = version
        self.name = name

    def __repr__(self) -> str:
        """
        Returns a string representation of the Vendor instance.

        Returns:
            str: String representation of the Vendor instance.
        """
        return '{name}({items})'.format(
            name=self.__class__.__name__,
            items=', '.join([f'{k}={repr(v)}' for k, v in self.__dict__.items()])
        )


__all__ = ('Vendor',)
