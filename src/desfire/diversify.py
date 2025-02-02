import logging

from smartcard.util import toHexString

from .enums import DESFireKeyType
from .key import DESFireKey
from .schemas import KeySettings

logger = logging.getLogger(__name__)


def diversify_key(key_data: list[int], diversification: list[int], pad_to_32: bool = True) -> list[int]:
    """
    Generates a diversified key based on NXP application note AN10922

    The diversification data is not standardized but it is recommended to include data that is unique to the
    card and the application. For example, the UID of the card, the AID of the application, and the system ID.

    Args:
        key_data (list[int]): Original key data that will be diversified.
        diversification (list[int]): Diversification data. Refer to the application note for a recommendation
        pad_to_32 (bool, optional): The NXP application note calls for the diversification data to be padded to
            32 bytes. Depending on the block size of the underlying cipher, this might not be neccessary and
            there may be existing implementations that do not pad the data.


    Returns:
        list[int]: Diversified key data
    """

    logger.debug("Diversifying key using NXP AN10922 method")

    # Pad the diversification data to 32 bytes
    padded: bool = False
    if len(diversification) < 32 and pad_to_32:
        logger.debug("Padding diversification data to 32 bytes")
        diversification += [0x80] + [0] * (32 - len(diversification) - 1)
        padded = True

    logger.debug(f"Diversification data: {toHexString(diversification)}")

    key = DESFireKey(KeySettings(key_type=DESFireKeyType.DF_KEY_AES), bytes(key_data))
    key.generate_cmac()
    key.clear_iv()

    # Calculate the diversified key
    return key.calculate_cmac(diversification, pre_padded=padded)
