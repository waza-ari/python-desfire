from enum import Enum


class DESFireKeyType(Enum):
    """
    The DESfire cards support different keys.
    """

    """
    DES authentication or 3DES authentication with 2 keys.

    Authentication Commands:
        - DES: AUTHENTICATE_LEGACY
        - 3DES: AUTHENTICATE_ISO
    Keysize:
        - DES: 8 bytes
        - 3DES: 16 bytes
    Cipherblock size: 8 bytes
    Ciphermod:
        - DES: DES.new(key, DES.MODE_CBC, iv)
        - 3DES: DES3.new(key, DES3.MODE_CBC, iv)
    """
    DF_KEY_2K3DES = 0x00

    """
    3DES authentication with 3 keys.

    Authentication Commands: AUTHENTICATE_ISO
    Keysize: 24 bytes
    Block size: 8 bytes
    Ciphermod: DES3.new(key, DES3.MODE_CBC, iv)
    """
    DF_KEY_3K3DES = 0x40

    """
    AES authentication.

    Authentication Commands: AUTHENTICATE_AES
    Keysize: 16 bytes
    Block size: 16 bytes
    Ciphermod: AES.new(key, AES.MODE_CBC, iv)
    """
    DF_KEY_AES = 0x80
    DF_KEY_INVALID = 0xFF
