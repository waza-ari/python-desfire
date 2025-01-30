import zlib
from typing import Literal

from Crypto.Util.number import bytes_to_long, long_to_bytes


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
    data: str | bytearray | int | bytes, byte_size: int = 2, byteorder: Literal["little", "big"] = "big"
) -> list[int]:  #
    """
    Convert a bytearray, hex string or int to a list of integers.
    """
    if isinstance(data, str):
        return list(bytearray.fromhex(data))
    elif isinstance(data, bytearray) or isinstance(data, bytes):
        return list(data)
    elif isinstance(data, int):
        return list(data.to_bytes(byte_size, byteorder=byteorder))
    return data


def get_bytes(data: str | bytearray | int | bytes, byte_size: int = 2) -> bytes:
    """
    Convert a bytearray, hex string or int to a bytes object.
    """
    if isinstance(data, str):
        return bytes(bytearray.fromhex(data))
    elif isinstance(data, bytearray):
        return bytes(data)
    elif isinstance(data, int):
        return data.to_bytes(byte_size, byteorder="big")
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
