from ..util import to_hex_string


class CardVersion:
    """
    This class represents the output of the GetVersion command and parses the data into a more readable format.
    """

    def __init__(self, data: list[int]):
        self.raw_bytes: list[int] = data
        self.hardware_vendor_id: int = data[0]
        self.hardware_type: int = data[1]
        self.hardware_sub_type: int = data[2]
        self.hardware_major_version: int = data[3]
        self.hardware_minor_version: int = data[4]
        self.hardware_storage_size: int = data[5]
        self.hardware_protocol: int = data[6]

        self.software_vendor_id: int = data[7]
        self.software_type: int = data[8]
        self.software_sub_type: int = data[9]
        self.software_major_version: int = data[10]
        self.software_minor_version: int = data[11]
        self.software_storage_size: int = data[12]
        self.software_protocol: int = data[13]

        self.uid: list[int] = data[14:21]
        self.batch_no: list[int] = data[21:25]
        self.production_date_cw: int = data[26]
        self.production_date_year: int = data[27]

    def __repr__(self) -> str:
        temp = "--- Desfire Card Details ---\r\n"
        temp += f"Hardware Version: {self.hardware_major_version}.{self.hardware_minor_version}\r\n"
        temp += f"Software Version: {self.software_major_version}.{self.software_minor_version}\r\n"

        # EEPROM size calculation according to NXP documentation,
        # see https://www.nxp.com/docs/en/application-note/AN10833.pdf
        #     formula is in Figure 1 on page 4, lower right corner of the table,
        # .    examples are in the table itself, below some card types, e.g. MIFARE DESFire
        # see also https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf
        #     on page 36, Table 28 and notes below
        #
        # Meaning and encoding of 'hardware_storage_size':
        # Bit 0 (LSB) indicates size encoding method
        # Bit 1..7 are the 'size' value used in the formula below
        #
        # Ultralight Family has bit 0 = 1, e.g. 0x0B (for 48 Byte) or 0x0E (128 Byte)
        # MIFARE DESFire Family has bit 0 = 0, e.g. 0x16: 2K, 0x18: 4K, 0x1A: 8K, 0x1C: 16K, 0x1E: 32K
        #
        # Formula:
        #   if bit 0 = 1, then storageBytes = 2^(size // 2) up to storageBytes = 2^(size // 2 + 1)
        #   if bit 0 = 0, then storageBytes = 2^(size // 2)

        # LSB indicates size encoding method
        if (self.hardware_storage_size & 0x01) == 0x01:  # typical for Ultralight C, and EV1
            temp += (
                f"EEPROM size:      {1 << (self.hardware_storage_size >> 1)} up to "
                f"{1 << ((self.hardware_storage_size >> 1) + 1)} bytes\r\n"
            )
        else:  # typical for DESFire EV1, EV2, and EV3
            temp += f"EEPROM size:      {1 << (self.hardware_storage_size >> 1)} bytes\r\n"
        temp += f"Production:       week {self.production_date_cw:X}, year 20{self.production_date_year:02X}\r\n"
        temp += f"UID no:           {to_hex_string(self.uid)}\r\n"
        temp += f"Batch no:         {to_hex_string(self.batch_no)}\r\n"
        return temp
