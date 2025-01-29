import struct

from ..enums import DESFireCommunicationMode, DESFireFileType
from .permissions import DESFireFilePermissions


class DESFireFileSettings:
    encryption: DESFireCommunicationMode | None = None

    def __init__(self):
        self.FileType = None  # DESFireFileType
        self.Permissions = DESFireFilePermissions()
        # ----------------------------
        # used only for MDFT_STANDARD_DATA_FILE and MDFT_BACKUP_DATA_FILE
        self.FileSize = 0  # uint32_t
        # -----------------------------
        # used only for MDFT_VALUE_FILE_WITH_BACKUP
        self.LowerLimit = None  # uint32_t
        self.UpperLimit = None  # uint32_t
        self.LimitedCreditValue = None
        self.LimitedCreditEnabled = None  # bool
        # -----------------------------
        # used only for MDFT_LINEAR_RECORD_FILE_WITH_BACKUP and MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP
        self.RecordSize = None  # uint32_t
        self.MaxNumberRecords = None  # uint32_t
        self.CurrentNumberRecords = None  # uint32_t

    def parse(self, data):
        self.FileType = DESFireFileType(data[0])
        self.encryption = DESFireCommunicationMode(data[1])
        self.Permissions.unpack(struct.unpack(">H", bytes(data[2:4]))[0])

        if self.FileType == DESFireFileType.MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
            self.RecordSize = struct.unpack("<I", bytes(data[4:6] + [0x00, 0x00]))[0]
            self.MaxNumberRecords = struct.unpack("<I", bytes(data[6:8] + [0x00, 0x00]))[0]
            self.CurrentNumberRecords = struct.unpack("<I", bytes(data[8:10] + [0x00, 0x00]))[0]

        elif self.FileType == DESFireFileType.MDFT_STANDARD_DATA_FILE:
            self.FileSize = self.FileSize = struct.unpack("<I", bytes(data[4:6] + [0x00, 0x00]))[0]

        else:
            # TODO: We can still access common attributes
            # raise NotImplementedError("Please fill in logic for file type {:02X}".format(resp[0]))
            pass

    def __repr__(self):
        temp = " ----- DESFireFileSettings ----\r\n"
        temp += f"File type: {self.FileType.name}\r\n"
        temp += f"Encryption: {self.encryption.name}\r\n"
        temp += f"Permissions: {repr(self.Permissions)}\r\n"
        if self.FileType == DESFireFileType.MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
            temp += "RecordSize: %d\r\n" % (self.RecordSize)  # noqa: UP031
            temp += "MaxNumberRecords: %d\r\n" % (self.MaxNumberRecords)  # noqa: UP031
            temp += "CurrentNumberRecords: %d\r\n" % (self.CurrentNumberRecords)  # noqa: UP031

        elif self.FileType == DESFireFileType.MDFT_STANDARD_DATA_FILE:
            temp += "File size: %d\r\n" % (self.FileSize)  # noqa: UP031

        return temp
