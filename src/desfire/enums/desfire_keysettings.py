from enum import Enum


class DESFireKeySettings(Enum):
    # ------------ BITS 0-3 ---------------
    """
    PICC Master Key: Card master Key can be changed, otherwise it is frozen.
    Application Key: Application master key can be changed, otherwise it is frozen.
    """

    KS_ALLOW_CHANGE_MK = 0x01

    """
    PICC Master Key: If this bit is set, GetApplicationIDs, GetKeySettings do not require MK authentication.
    Application Key: If this bit is set, GetFileIDs, GetFileSettings, GetKeySettings do not require MK authentication.
    """
    KS_LISTING_WITHOUT_MK = 0x02

    """
    PICC Master Key: If this bit is set, CreateApplication does not require MK authentication.
    Application Key: If this bit is set, files can be created and deleted without MK authentication.
    """
    KS_CREATE_DELETE_WITHOUT_MK = 0x04

    """
    The key settings are frozen and cannot be changed if this bit is set.
    """
    KS_CONFIGURATION_CHANGEABLE = 0x08

    # ------------ BITS 4-7 (not used for the Card master key) -------------
    # 4 bit in total, giving 16 possible values
    KS_CHANGE_KEY_WITH_MK = 0x00  # A key change requires MK authentication
    KS_CHANGE_KEY_WITH_KEY_1 = 0x10  # A key change requires authentication with key 1
    KS_CHANGE_KEY_WITH_KEY_2 = 0x20  # A key change requires authentication with key 2
    KS_CHANGE_KEY_WITH_KEY_3 = 0x30  # A key change requires authentication with key 3
    KS_CHANGE_KEY_WITH_KEY_4 = 0x40  # A key change requires authentication with key 4
    KS_CHANGE_KEY_WITH_KEY_5 = 0x50  # A key change requires authentication with key 5
    KS_CHANGE_KEY_WITH_KEY_6 = 0x60  # A key change requires authentication with key 6
    KS_CHANGE_KEY_WITH_KEY_7 = 0x70  # A key change requires authentication with key 7
    KS_CHANGE_KEY_WITH_KEY_8 = 0x80  # A key change requires authentication with key 8
    KS_CHANGE_KEY_WITH_KEY_9 = 0x90  # A key change requires authentication with key 9
    KS_CHANGE_KEY_WITH_KEY_A = 0xA0  # A key change requires authentication with key 10
    KS_CHANGE_KEY_WITH_KEY_B = 0xB0  # A key change requires authentication with key 11
    KS_CHANGE_KEY_WITH_KEY_C = 0xC0  # A key change requires authentication with key 12
    KS_CHANGE_KEY_WITH_KEY_D = 0xD0  # A key change requires authentication with key 13
    KS_CHANGE_KEY_WITH_TARGETED_KEY = (
        0xE0  # A key change requires authentication with the same key that is to be changed
    )
    KS_CHANGE_KEY_FROZEN = 0xF0  # All keys except PICC master key are frozen

    # -------------------------------------
    KS_FACTORY_DEFAULT = 0x0F
