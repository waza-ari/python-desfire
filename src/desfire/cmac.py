import logging

from Crypto.Util.py3compat import bchr

from .enums import DESFireKeyType
from .util import get_ciphermod, shift_bytes

logger = logging.getLogger(__name__)


class CMAC:
    """
    This class implements CMAC (Cipher-based MAC) following the NIST SP 800-38B specification.
    """

    PADDING_CONSTANT = 0x80

    def __init__(self, key: bytes, key_type: DESFireKeyType):
        """
        Initialize the CMAC object with a key and a cipher module.
        """

        logger.debug("Initializing CMAC with provided key. Calculating K1 and K2.")

        self._key = key
        cipher = get_ciphermod(key_type, key, bchr(0) * len(key))
        self._bs = cipher.block_size

        # Section 5.3 of NIST SP 800 38B
        if self._bs == 8:
            const_Rb = 0x1B
        elif self._bs == 16:
            const_Rb = 0x87
        else:
            logger.error(f"CMAC requires a cipher with a block size of 8 or 16 bytes, not {self._bs}")
            raise TypeError(f"CMAC requires a cipher with a block size of 8 or 16 bytes, not {self._bs}")

        # Encrypt a block of zeros with IV of zeros and the session key
        l = cipher.encrypt(bchr(0) * self._bs)
        if int(l[0]) & 0x80:
            self._k1 = shift_bytes(l, const_Rb)
        else:
            self._k1 = shift_bytes(l)
        if int(self._k1[0]) & 0x80:
            self._k2 = shift_bytes(self._k1, const_Rb)
        else:
            self._k2 = shift_bytes(self._k1)

    @property
    def k1(self) -> list[int]:
        return list(self._k1)

    @property
    def k2(self) -> list[int]:
        return list(self._k2)
