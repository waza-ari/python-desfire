import struct

from ..enums import DESFireCommunicationMode, DESFireFileType
from .file_permissions import FilePermissions


class FileSettings:
    encryption: DESFireCommunicationMode | None = None
    file_type: DESFireFileType | None = None
    permissions: FilePermissions | None = None

    file_size = 0  # used only for MDFT_STANDARD_DATA_FILE and MDFT_BACKUP_DATA_FILE, uint32_t

    def parse(self, data):
        """
        Takes raw data from command 0xF5 (get file settings) and parses it into a FileSettings object.

        Example of a raw data from command 0xF5 (get file settings on a standard data file):
        00 03 00 23 08 00 00
        ^^ ^^ ^^^^^ ^^^^^^^^
        |  |  |     |
        |  |  |     ^ File Size (3 bytes)
        |  |  ^ File Permissions (2 bytes)
        |  ^ Communication / Encryption mode (1 byte)
        ^ File Type (1 byte)

        File permissions are 4 bits each:
        - 0b - 3b: Change Permission key
        - 4b - 7b: Read-Write Permission key
        - 8b - 11b: Write Permission key
        - 12b - 15b: Read Permission key

        There are four other file types that are not implemented yet.
        """

        self.file_type = DESFireFileType(data[0])
        self.encryption = DESFireCommunicationMode(data[1])
        self.permissions = FilePermissions()
        self.permissions.parse(data[2:4])

        if self.file_type == DESFireFileType.MDFT_STANDARD_DATA_FILE:
            # Standard data file, parse file size in bytes. <I is little-endian unsigned int
            self.file_size = struct.unpack("<I", bytes(data[4:7] + [0x00]))[0]
        else:
            # TODO: We currently only support standard data files
            raise NotImplementedError(f"Filetype {data[0]:02X} is currently not supported.")

    def __repr__(self):
        """
        Returns a human readable representation of the file settings.
        """
        temp = " ----- FileSettings ----\r\n"
        temp += f"File type: {self.file_type.name}\r\n"
        temp += f"Encryption: {self.encryption.name}\r\n"
        temp += f"Permissions: {repr(self.permissions)}\r\n"
        if self.file_type == DESFireFileType.MDFT_STANDARD_DATA_FILE:
            temp += f"File size: {self.file_size}\r\n"

        return temp
