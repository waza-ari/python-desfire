import logging

from smartcard.util import toHexString

from desfire.schemas import KeySettings

from .cmac import CMAC
from .enums import DESFireKeyType
from .exceptions import DESFireException
from .util import CRC32, get_ciphermod, get_list, xor_lists

logger = logging.getLogger(__name__)


class DESFireKey:
    """
    DESFire key object that is used for encryption and CMAC calculation.
    """

    key_type: DESFireKeyType
    key_bytes: bytes | None = None
    key_size: int = 0
    cipher_block_size: int | None = None
    cmac: CMAC | None = None

    # Global IV for this key, used for cipher operations and CMAC calculation
    iv: list[int]
    iv0: list[int]

    def __init__(self, settings: KeySettings, key_data: list[int] | str | bytearray | int | bytes | None = None):
        """
        Initializes the DESFire key object with the given settings and key data.

        Args:
            settings (KeySettings): Key settings object, can be obtained from the card.
            key_data (list[int] | str | bytearray | int | bytes | None, optional):
                Key data to be set. Will be parsed using the get_list function. Defaults to None.

        Raises:
            DESFireException: If invalid key type is set or key data is not provided.
        """
        if not settings.key_type:
            raise DESFireException("Key type must be set!")
        self.key_type = settings.key_type
        if key_data:
            self.set_key(key_data)
        self.cipher_init()

    # Internal methods
    def _set_key_size(self, key_size: int):
        self.cipher_block_size = key_size
        self.key_size = key_size
        self.iv0 = [0] * key_size

    def set_iv(self, iv: list[int]):
        print("Setting IV to", toHexString(iv))
        self.iv = iv

    def cipher_init(self):
        """
        Initializes the cipher object for this key depending on the chosen key type
        """

        # If the key size is not set, we assume it is 8 bytes
        if self.key_size == 0:
            self._set_key_size(8 if not self.key_bytes else len(self.key_bytes))

        # Depending on the key type, set cipher related variables
        if self.key_type == DESFireKeyType.DF_KEY_AES:
            self._set_key_size(16)
            self.cipher_block_size = 16
        elif self.key_type == DESFireKeyType.DF_KEY_2K3DES:
            # DES is used
            if self.key_size == 8:
                self.cipher_block_size = 8
            # 2DES is used (3DES with 2 keys only)
            elif self.key_size == 16:
                self.cipher_block_size = 8
            else:
                raise DESFireException("Key length error! When using 2K3DES, the key must be 8 or 16 bytes long.")
        elif self.key_type == DESFireKeyType.DF_KEY_3K3DES:
            assert self.key_size == 24
            self.cipher_block_size = 8
        else:
            raise DESFireException("Unknown key type!")

        # Initialize the key to a default value if it is not set
        if self.key_bytes is None:
            self.key_bytes = b"\00" * self.key_size
        if self.cipher_block_size is None:
            self.cipher_block_size = self.key_size

        # Clear IV to default value (all zeros)
        self.clear_iv()

    def clear_iv(self):
        """
        Resets the IV to all zero bytes.
        """
        self.set_iv(self.iv0.copy())

    def get_key(self) -> bytes:
        """
        Returns the key as a byte array.

        Returns:
            bytes: Key data as a byte array.
        """
        assert self.key_bytes is not None
        return self.key_bytes

    def set_key(self, key: list[int] | str | bytearray | int | bytes):
        """
        Sets the key to the given value. Will be passed using the get_list function.

        Args:
            key (list[int] | str | bytearray | int | bytes): Key data as a list of integers,
                a string of HEX characters, a byte array or an integer.
        """
        self.key_bytes = bytes(get_list(key))
        self._set_key_size(len(self.key_bytes))

    def encrypt(self, data: list[int]) -> list[int]:
        """
        Encrypts the given data with the key and returns the encrypted data as a list of integers.
        """
        cipher = get_ciphermod(self.key_type, self.get_key(), bytes(self.iv))
        return list(bytearray(cipher.encrypt(bytes(data))))

    def decrypt(self, dataEnc: list[int]) -> list[int]:
        """
        Decrypts the given data with the key and returns the decrypted data as a list of integers.
        """
        cipher = get_ciphermod(self.key_type, self.get_key(), bytes(self.iv))
        logger.debug(f"Decrypting data: {toHexString(dataEnc)} using key type {self.key_type.name}")
        block = cipher.decrypt(bytes(dataEnc))
        return list(bytearray(block))

    def generate_cmac(self):
        """
        Generates the two subkeys mu8_Cmac1 and mu8_Cmac2 that are used for CMAC calulation with the session key
        Should be called after setting the key.
        """
        self.cmac = CMAC(self.key_bytes, key_type=self.key_type)

    def calculate_cmac(self, data: list[int], pre_padded: bool = False) -> list[int]:
        """
        Calculate the CMAC of a sequence of bytes. Will update the IV.

        If already padded externally, the pre_padded flag should be set to True to indicate
        that k2 should be used for XOR even though no padding happens within this function.
        """
        assert self.cmac is not None
        assert self.cipher_block_size is not None

        # Calculate the CMAC
        ndata = data.copy()
        padded: bool = pre_padded

        if len(ndata) % self.cipher_block_size:
            # Padding is needed, PAD the data with 0x80, 0x00* until the last block and XOR the last block with K2
            ndata += [self.cmac.PADDING_CONSTANT] + [0x00] * (
                self.cipher_block_size - len(ndata) % self.cipher_block_size - 1
            )
            padded = True

        # XOR the last block with k1 or k2, depending on the padding
        key_to_use = self.cmac.k2 if padded else self.cmac.k1
        xor_data = ndata[0 : -self.cipher_block_size] + xor_lists(ndata[-self.cipher_block_size :], key_to_use)

        # Encrypt the padded data
        ret = self.encrypt(xor_data)

        # Update the IV with the last block of the encrypted data
        self.set_iv(ret[-self.cipher_block_size :])
        return ret[-self.cipher_block_size :]

    def encrypt_msg(self, data: list[int], disable_crc: bool = False, offset: int = 1) -> list[int]:
        """
        Encrypts a message that is to be sent to the card.
        """
        assert self.cipher_block_size

        # Calculate the CRC32 checksum if needed
        if not disable_crc:
            data += CRC32(data)

        # Pad the data to the next block size
        data += [0x00] * (-(len(data) - offset) % self.cipher_block_size)

        # Encrypt the data
        ret = data[0:offset] + self.encrypt(data[offset:])
        return ret
