import zlib
from typing import Literal

from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.number import bytes_to_long, long_to_bytes

from .enums import DESFireKeyType


def get_int(data: int | str | bytearray | bytes, byteorder: Literal["little", "big"] = "big") -> int:
    """
    Convert a bytearray, hex string or int to an integer.
    """
    if isinstance(data, int):
        return data
    elif isinstance(data, str):
        return int.from_bytes(bytearray.fromhex(data))
    elif isinstance(data, bytearray) or isinstance(data, bytes):
        return int.from_bytes(data, byteorder=byteorder)


def get_list(
    data: list[int] | str | bytearray | int | bytes, byte_size: int = 2, byteorder: Literal["little", "big"] = "big"
) -> list[int]:
    """
    Utility method to simplify the conversion of data to a list of integers.
    Each entry in the list represents one byte of the input data.
    Convert a bytearray, hex string or int to a list of integers.

    Args:
        data (str | bytearray | int | bytes): Input that should be converted to a list of integers.
        byte_size (int, optional): Needed when input data is of type `int`.
            Guarantees that the list that is returned has this length.
        byteorder (Literal[&quot;little&quot;, &quot;big&quot;], optional): Needed when input data is of type `int`.
            Specifies the byte order that should be used when converting the integer to a list of integers.

    Tip: Parsing Crypto Keys
        This method is particularly useful when parsing keys that are represented as hex strings.

    Returns:
        A list of integers (each entry representing one byte).
    """
    if isinstance(data, list):
        # Already a list. Verify that each entry is an integer between 0 and 255.
        assert all(0 <= x <= 255 for x in data)
        return data
    if isinstance(data, str):
        return list(bytearray.fromhex(data))
    elif isinstance(data, bytearray) or isinstance(data, bytes):
        return list(data)
    elif isinstance(data, int):
        return list(data.to_bytes(byte_size, byteorder=byteorder))
    return data


def CRC32(data: list[int]) -> list[int]:
    """
    Calculates a JAMCRC checksum of the given data.

    See https://stackoverflow.com/a/58861664/1627106
    """
    checksum = int("0b" + "1" * 32, 2) - zlib.crc32(bytes(data))
    return get_list(checksum, byte_size=4, byteorder="little")


def shift_bytes(bs: bytes, xor_lsb: int = 0) -> bytes:
    """
    Shifts the bytes to the left by one bit and xors the least significant bit with the given value.
    """
    num = (bytes_to_long(bs) << 1) ^ xor_lsb
    return long_to_bytes(num, len(bs))[-len(bs) :]


def xor_lists(list1: list[int], list2: list[int]) -> list[int]:
    """
    Takes two lists and performs a bytewise xor on those lists..
    """
    return [a ^ b for a, b in zip(list1, list2)]


def get_ciphermod(key_type: DESFireKeyType, key: bytes, iv: bytes):
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
