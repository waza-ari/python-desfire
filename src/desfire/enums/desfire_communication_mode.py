from enum import Enum


class DESFireCommunicationMode(Enum):
    """
    TX: CMAC needs to be calculated to update the IV, but CMAC is not appended
    RX: No impact
    """

    PLAIN = 0x00

    """
    TX: CMAC needs to be calculated to update the IV, and CMAC is appended
    RX: CMAC is attached to the data and needs to be verified
    """
    CMAC = 0x01

    """
    TX: CRC creation + data encryption
    RX: Data decryption + CRC verification
    """
    ENCRYPTED = 0x03
