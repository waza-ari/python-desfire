from smartcard.util import toHexString

from .enums import DESFireKeyType
from .key.key import DESFireKey
from .schemas import KeySettings


def diversify_key(key_data: list[int], diversification: list[int], pad_to_32: bool = True) -> list[int]:
    """
    Returns a diversified key based on NXP application note AN10922

    The diversification data is not standardized but it is recommended to include data that is unique to the
    card and the application. For example, the UID of the card, the AID of the application, and the system ID.
    """
    # Pad the diversification data to 32 bytes
    padded: bool = False

    if len(diversification) < 32 and pad_to_32:
        diversification += [0x80] + [0] * (32 - len(diversification) - 1)
        padded = True

    print("Diversification data: ", toHexString(diversification))

    key = DESFireKey(KeySettings(key_type=DESFireKeyType.DF_KEY_AES), bytes(key_data))
    key.generate_cmac()
    key.clear_iv()

    # Calculate the diversified key
    return key.calculate_cmac(diversification, pre_padded=padded)
