class Vendor:
    """
    Represents a Vendor with SDK, OEM, version, and name attributes.
    """

    def __init__(self, sdk: int, oem: int, version: str, pattern: str):
        """
        Initializes a Vendor instance.

        Parameters:
            sdk (int): Minimum SDK version required by the vendor.
            oem (int): OEM identifier for the vendor.
            version (str): Version of the vendor.
            pattern (str): Name pattern of the vendor.
        """
        self.sdk = sdk
        self.oem = oem
        self.version = version
        self.pattern = pattern

    def __repr__(self) -> str:
        """
        Returns a string representation of the Vendor instance.

        Returns:
            str:  String representation of the Vendor instance with its attributes.
        """
        return "{name}({items})".format(
            name=self.__class__.__name__,
            items=", ".join([f"{k}={repr(v)}" for k, v in self.__dict__.items()])
        )


__all__ = ("Vendor",)
