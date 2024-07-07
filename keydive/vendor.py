class Vendor:
    """
    Represents a Vendor with SDK, OEM, version, and name attributes.
    """

    def __init__(self, sdk: int, oem: int, version: str, name: str):
        """
        Initializes a Vendor instance.

        Args:
            sdk (int): Minimum SDK version required.
            oem (int): OEM identifier.
            version (str): Version of the vendor.
            name (str): Name of the vendor.
        """
        self.sdk = sdk
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
