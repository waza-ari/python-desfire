from enum import Enum


class DESFireFileType(Enum):
    MDFT_STANDARD_DATA_FILE = 0x00
    MDFT_BACKUP_DATA_FILE = 0x01  # not implemented
    MDFT_VALUE_FILE_WITH_BACKUP = 0x02  # not implemented
    MDFT_LINEAR_RECORD_FILE_WITH_BACKUP = 0x03  # not implemented
    MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP = 0x04  # not implemented
