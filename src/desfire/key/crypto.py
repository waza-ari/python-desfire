from Crypto.Cipher import AES, DES, DES3

from ..enums.desfire_keytype import DESFireKeyType


class CipherFactory:
    @classmethod
    def get_ciphermod(cls, key_type: DESFireKeyType, key: bytes, iv: bytes):
        """
        Returns the cipher module for the given key type.
        """
        if key_type == DESFireKeyType.DF_KEY_AES:
            assert len(key) == 16
            return AES.new(key, AES.MODE_CBC, iv)
        elif key_type == DESFireKeyType.DF_KEY_3K3DES or (key_type == DESFireKeyType.DF_KEY_2K3DES and len(key) == 16):
            return DES3.new(key, DES3.MODE_CBC, iv)
        elif key_type == DESFireKeyType.DF_KEY_2K3DES and len(key) == 8:
            return DES.new(key, DES.MODE_CBC, iv)
        else:
            raise ValueError("Unknown key type")
