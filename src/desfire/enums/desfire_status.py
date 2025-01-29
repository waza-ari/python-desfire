from enum import Enum


class DESFireStatus(Enum):
    ST_Success = 0x00
    ST_NoChanges = 0x0C
    ST_OutOfMemory = 0x0E
    ST_IllegalCommand = 0x1C
    ST_IntegrityError = 0x1E
    ST_KeyDoesNotExist = 0x40
    ST_WrongCommandLen = 0x7E
    ST_PermissionDenied = 0x9D
    ST_IncorrectParam = 0x9E
    ST_AppNotFound = 0xA0
    ST_AppIntegrityError = 0xA1
    ST_AuthentError = 0xAE
    ST_MoreFrames = 0xAF  # data did not fit into a frame, another frame will follow
    ST_LimitExceeded = 0xBE
    ST_CardIntegrityError = 0xC1
    ST_CommandAborted = 0xCA
    ST_CardDisabled = 0xCD
    ST_InvalidApp = 0xCE
    ST_DuplicateAidFiles = 0xDE
    ST_EepromError = 0xEE
    ST_FileNotFound = 0xF0
    ST_FileIntegrityError = 0xF1
