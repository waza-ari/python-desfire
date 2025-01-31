from enum import Enum


class DESFireCommand(Enum):
    # ------- Desfire legacy instructions --------

    DF_INS_AUTHENTICATE_LEGACY = 0x0A  # Authenticate with legacy DES
    DF_INS_CHANGE_KEY_SETTINGS = 0x54
    DF_INS_GET_KEY_SETTINGS = 0x45
    DF_INS_CHANGE_KEY = 0xC4
    DF_INS_GET_KEY_VERSION = 0x64

    DF_INS_CREATE_APPLICATION = 0xCA
    DF_INS_DELETE_APPLICATION = 0xDA
    DF_INS_GET_APPLICATION_IDS = 0x6A
    DF_INS_SELECT_APPLICATION = 0x5A

    DF_INS_FORMAT_PICC = 0xFC
    DF_INS_GET_VERSION = 0x60

    DF_INS_GET_FILE_IDS = 0x6F
    DF_INS_GET_FILE_SETTINGS = 0xF5
    DF_INS_CHANGE_FILE_SETTINGS = 0x5F
    DF_INS_CREATE_STD_DATA_FILE = 0xCD
    DF_INS_CREATE_BACKUP_DATA_FILE = 0xCB
    DF_INS_CREATE_VALUE_FILE = 0xCC
    DF_INS_CREATE_LINEAR_RECORD_FILE = 0xC1
    DF_INS_CREATE_CYCLIC_RECORD_FILE = 0xC0
    DF_INS_DELETE_FILE = 0xDF

    DF_INS_READ_DATA = 0xBD
    DF_INS_WRITE_DATA = 0x3D
    DF_INS_GET_VALUE = 0x6C
    DF_INS_CREDIT = 0x0C
    DF_INS_DEBIT = 0xDC
    DF_INS_LIMITED_CREDIT = 0x1C
    DF_INS_WRITE_RECORD = 0x3B
    DF_INS_READ_RECORDS = 0xBB
    DF_INS_CLEAR_RECORD_FILE = 0xEB
    DF_COMMIT_TRANSACTION = 0xC7
    DF_INS_ABORT_TRANSACTION = 0xA7

    DF_INS_ADDITIONAL_FRAME = 0xAF  # data did not fit into a frame, another frame will follow

    # -------- Desfire EV1 instructions ----------

    DFEV1_INS_AUTHENTICATE_ISO = 0x1A  # Authenticate with 3DES, either with 2 keys (16 bytes) or 3 keys (24 bytes)
    DFEV1_INS_AUTHENTICATE_AES = 0xAA  # Authenticate with AES-128
    DFEV1_INS_FREE_MEM = 0x6E
    DFEV1_INS_GET_DF_NAMES = 0x6D
    DFEV1_INS_GET_CARD_UID = 0x51
    DFEV1_INS_GET_ISO_FILE_IDS = 0x61
    DFEV1_INS_SET_CONFIGURATION = 0x5C

    # ---------- ISO7816 instructions ------------

    ISO7816_INS_EXTERNAL_AUTHENTICATE = 0x82
    ISO7816_INS_INTERNAL_AUTHENTICATE = 0x88
    ISO7816_INS_APPEND_RECORD = 0xE2
    ISO7816_INS_GET_CHALLENGE = 0x84
    ISO7816_INS_READ_RECORDS = 0xB2
    ISO7816_INS_SELECT_FILE = 0xA4
    ISO7816_INS_READ_BINARY = 0xB0
    ISO7816_INS_UPDATE_BINARY = 0xD6
