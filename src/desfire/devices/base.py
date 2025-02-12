import abc


class Device:
    """Abstract base class which uses underlying device communication channel."""

    @abc.abstractmethod
    def transceive(self, bytes: list[int]) -> list[int]:
        """
        Send in APDU request and wait for the response.

        Args:
            bytes (list[int]): Outgoing bytes as list of bytes or byte array

        Returns:
            list[int]: List of bytes or byte array from the device.
        """
        raise NotImplementedError("Base class must implement")
