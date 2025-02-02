from enum import Enum


class DESFireCommunicationMode(Enum):
    PLAIN = 0x00
    """
    - **TX**: CMAC needs to be calculated to update the IV, but CMAC is not appended
    - **RX**: No impact
    """

    CMAC = 0x01
    """
    - **TX**: CMAC needs to be calculated to update the IV, and CMAC is appended
    - **RX**: CMAC is attached to the data and needs to be verified
    """

    ENCRYPTED = 0x03
    """
    - **TX**: CRC creation + data encryption
    - **RX**: Data decryption + CRC verification
    """
