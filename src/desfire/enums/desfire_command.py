from enum import Enum


class DESFireCommand(Enum):
    """
    This enum contains all the commands that can be sent to a DESFire card.

    Source: NXP Documentation, https://www.nxp.com/docs/en/application-note/AN12752.pdf
    """

    # Authentication Commands
    AUTHENTICATE_LEGACY = 0x0A  # Not implemented
    AUTHENTICATE_ISO = 0x1A  # Authenticate with 3DES, either with 2 keys (16 bytes) or 3 keys (24 bytes)
    AUTHENTICATE_AES = 0xAA  # Authenticate with AES-128
    AUTHENTICATE_EV2_FIRST = 0x71  # EV2 and EV3 only, Not implemented
    AUTHENTICATE_EV2_NON_FIRST = 0x72  # EV2 and EV3 only,  Not implemented

    # Communication Commands
    ADDITIONAL_FRAME = 0xAF  # Indicating that data did not fit into one frame

    # Card Related Commands
    FREE_MEM = 0x6E  # Not implemented
    FORMAT_PICC = 0xFC
    SET_CONFIGURATION = 0x5C  # Partly implemented, only 0x0501 (change default key)
    GET_VERSION = 0x60
    GET_CARD_UID = 0x51

    # Key Related Commands
    CHANGE_KEY = 0xC4
    CHANGE_KEY_EV2 = 0xC6  # EV2 and EV3 only, Not implemented
    INITIALIZE_KEY_SET = 0x56  # EV2 and EV3 only, Not implemented
    FINALIZE_KEY_SET = 0x57  # EV2 and EV3 only, Not implemented
    ROLL_KEY_SET = 0x55  # EV2 and EV3 only, Not implemented
    GET_KEY_SETTINGS = 0x45
    CHANGE_KEY_SETTINGS = 0x54
    GET_KEY_VERSION = 0x64

    # Application Related Commands
    CREATE_APPLICATION = 0xCA
    DELETE_APPLICATION = 0xDA
    CREATE_DELEGATED_APPLICATION = 0xC9  # EV2 and EV3 only, Not implemented
    SELECT_APPLICATION = 0x5A
    GET_APPLICATION_IDS = 0x6A

    # File Related Commands
    CREATE_STD_DATA_FILE = 0xCD
    CREATE_BACKUP_DATA_FILE = 0xCB  # Not implemented
    CREATE_VALUE_FILE = 0xCC  # Not implemented
    CREATE_LINEAR_RECORD_FILE = 0xC1  # Not implemented
    CREATE_CYCLIC_RECORD_FILE = 0xC0  # Not implemented
    CREATE_TRANSACTION_MAC_FILE = 0xCE  # EV2 and EV3 only, Not implemented
    DELETE_FILE = 0xDF
    GET_FILE_IDS = 0x6F
    GET_ISO_FILE_IDS = 0x61  # Not implemented
    GET_FILE_SETTINGS = 0xF5
    GET_FILE_COUNTERS = 0xF6  # Not implemented
    CHANGE_FILE_SETTINGS = 0x5F  # Not implemented
    READ_DATA = 0xBD  # Can apparently also be 0xAD, not sure about differences
    WRITE_DATA = 0x3D  # Can apparently also be 0x8D, not sure about differences
    GET_VALUE = 0x6C  # Not implemented
    CREDIT = 0x0C  # Not implemented
    DEBIT = 0xDC  # Not implemented
    LIMITED_CREDIT = 0x1C  # Not implemented
    READ_RECORDS = 0xBB  # Not implemented, can apparently also be 0xAB
    WRITE_RECORD = 0x3B  # Not implemented, can apparently also be 0x8B
    UPDATE_RECORD = 0xDB  # Not implemented
    CLEAR_RECORD_FILE = 0xEB  # Not implemented
    COMMIT_TRANSACTION = 0xC7  # Not implemented
    ABORT_TRANSACTION = 0xA7  # Not implemented
    COMMIT_READER_ID = 0xC8  # EV2 and EV3 only, Not implemented

    # ISO Commands
    ISO_SELECT_FILE = 0xA4  # Not implemented
    ISO_READ_BINARY = 0xB0  # Not implemented
    ISO_UPDATE_BINARY = 0xD6  # Not implemented
    ISO_READ_RECORD = 0xB2  # Not implemented
    ISO_APPEND_RECORD = 0xE2  # Not implemented
    ISO_GET_CHALLENGE = 0x84  # Not implemented
    ISO_EXTERNAL_AUTHENTICATE = 0x82  # Not implemented
    ISO_INTERNAL_AUTHENTICATE = 0x88  # Not implemented
    ISO_SELECT_FILE_VC = 0xA4  # EV2 and EV3 only, Not implemented
    ISO_EXTERNAL_AUTHENTICATE_VC = 0x82  # EV2 and EV3 only, Not implemented

    # Unknown Commands (listed in the documentation, but no idea what they're doing)
    GET_DF_NAMES = 0x6D  # EV2 and EV3 only, Not implemented
    GET_DELEGATED_INFO = 0x69  # EV2 and EV3 only, Not implemented
    PREPARE_PC = 0xF0  # EV2 and EV3 only, Not implemented
    PROXIMITY_CHECK = 0xF2  # EV2 and EV3 only, Not implemented
    VERIFY_PC = 0xFD  # EV2 and EV3 only, Not implemented
    READ_SIG = 0x3C  # EV2 and EV3 only, Not implemented
