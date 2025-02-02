class FilePermissions:
    def __init__(self, read_key: int = 0, write_key: int = 0, read_write_key: int = 0, change_key: int = 0):
        """
        This class represents the permissions of a file on a DESFire card.

        Each permission represents a key number within the application that should be used
        to obtain the corresponding access rights. Each of them is a 4-bit value, where the
        bits are as follows:

        - 0x0 - 0xD   Key number that should be used to obtain the corresponding access rights
        - 0xE         No restrictions (free access)
        - 0xF         No Access allowed
        """
        self.read_access = read_key & 0x0F
        self.write_access = write_key & 0x0F
        self.read_and_write_access = read_write_key & 0x0F
        self.change_access = change_key & 0x0F

    def parse(self, data: list[int]):
        """
        Parse the raw data into a FilePermissions object. Raw data is two bytes, split into 4-bit values.

        Source:
        https://github.com/EsupPortail/esup-nfc-tag-server/blob/295aed8cbcf09323cf859fa5753b5482ce7eee3c/src/main/java/org/esupportail/nfctag/service/desfire/DESFireEV1Service.java#L1889

        - File permissions are (MSB = start):
        - - 0b - 3b: Read-Write key
        - - 4b - 7b: Change permission key
        - - 8b - 11b: Read key
        - - 12b - 15b: Write key

        Example Data: `0x00 0x23`

        ```
        0000 0000 0010 0011
        ^^^^ ^^^^ ^^^^ ^^^^
        RW   C    R    W
        ```
        """
        self.write_access = data[1] & 0x0F
        self.read_access = (data[1] >> 4) & 0x0F
        self.change_access = data[0] & 0x0F
        self.read_and_write_access = (data[0] >> 4) & 0x0F

    def get_permissions(self) -> list[int]:
        """
        Returns the permissions as a list of two bytes.
        """
        return [
            ((self.read_and_write_access & 0x0F) << 4) | (self.change_access & 0x0F),
            ((self.read_access & 0x0F) << 4) | (self.write_access & 0x0F),
        ]

    def __repr__(self):
        """
        Returns a human readable representation of the file permissions.

        TODO: Update this to reflect the actual permissions
        """
        temp = "----- FilePermissions ---\r\n"
        if self.read_access:
            temp += "READ|"
        if self.write_access:
            temp += "WRITE|"
        if self.read_and_write_access:
            temp += "READWRITE|"
        if self.read_and_write_access:
            temp += "CHANGE|"
        return temp
