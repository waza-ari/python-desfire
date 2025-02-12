# Try importing pyscard
try:
    from smartcard.Exceptions import CardConnectionException
    from smartcard.pcsc.PCSCCardConnection import translateprotocolheader
    from smartcard.scard import SCardGetErrorMessage, SCardTransmit
except ImportError:
    _has_pyscard = False
else:
    _has_pyscard = True

from ..exceptions import DESFireException
from .base import Device


class PCSCDevice(Device):
    """DESFire protocol wrapper for pyscard interface."""

    def __init__(self, card_connection):
        """
        :card_connection: :py:class:`smartcard.pcsc.PCSCCardConnection.PCSCCardConnection` instance.
        Call ``card_connection.connect()`` before calling any DESFire APIs.
        """

        if not _has_pyscard:
            raise ImportError("pyscard is required for using PCSCDevice")

        self.card_connection = card_connection

    def transceive(self, bytes: list[int]) -> list[int]:
        """
        Send in APDU request and wait for the response.

        Args:
            bytes (list[int]): Outgoing bytes as list of bytes or byte array

        Returns:
            list[int]: List of bytes or byte array from the device.
        """
        if not self.card_connection.hcard:
            raise DESFireException(f"Tried to transit to non-open connection: {self.card_connection}")

        protocol = self.card_connection.getProtocol()
        pcscprotocolheader = translateprotocolheader(protocol)

        # http://pyscard.sourceforge.net/epydoc/smartcard.scard.scard-module.html#SCardTransmit
        hresult, response = SCardTransmit(self.card_connection.hcard, pcscprotocolheader, bytes)

        if hresult != 0:
            raise CardConnectionException(
                f"Failed to transmit with protocol {str(pcscprotocolheader)}." + SCardGetErrorMessage(hresult)
            )
        return response
