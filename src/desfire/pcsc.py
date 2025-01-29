from smartcard.Exceptions import CardConnectionException
from smartcard.pcsc.PCSCCardConnection import translateprotocolheader
from smartcard.scard import SCardGetErrorMessage, SCardTransmit


class PCSCNotConnected(Exception):
    """Tried to transmit to non-open connection."""


class Device:
    """Abstract base class which uses underlying device communication channel."""

    def transceive(self, bytes):
        """Send in APDU request and wait for the response.
        :param bytes: Outgoing bytes as list of bytes or byte array
        :return: List of bytes or byte array from the device.
        """
        raise NotImplementedError("Base class must implement")


class PCSCDevice(Device):
    """DESFire protocol wrapper for pyscard interface."""

    def __init__(self, card_connection):
        """
        :card_connection: :py:class:`smartcard.pcsc.PCSCCardConnection.PCSCCardConnection` instance.
        Call ``card_connection.connect()`` before calling any DESFire APIs.
        """
        self.card_connection = card_connection

    def transceive(self, bytes):
        if not self.card_connection.hcard:
            raise PCSCNotConnected(f"Tried to transit to non-open connection: {self.card_connection}")

        protocol = self.card_connection.getProtocol()
        pcscprotocolheader = translateprotocolheader(protocol)

        # http://pyscard.sourceforge.net/epydoc/smartcard.scard.scard-module.html#SCardTransmit
        hresult, response = SCardTransmit(self.card_connection.hcard, pcscprotocolheader, bytes)

        if hresult != 0:
            raise CardConnectionException(
                f"Failed to transmit with protocol {str(pcscprotocolheader)}." + SCardGetErrorMessage(hresult)
            )
        return response


class DummyPCSCDevice(Device):
    """DESFire protocol wrapper for pyscard interface."""

    def __init__(self):
        """
        :card_connection: :py:class:`smartcard.pcsc.PCSCCardConnection.PCSCCardConnection` instance.
        Call ``card_connection.connect()`` before calling any DESFire APIs.
        """
        self.response = {}

    def addResponse(self, send, resp):
        toadd = [0]
        toadd += [bytearray.fromhex(a) for a in resp]
        self.response[bytes(bytearray.fromhex(send))] = toadd

    def transceive(self, send):
        self.response[bytes(send)][0] += 1
        return list(self.response[bytes(send)][self.response[bytes(send)][0]])
