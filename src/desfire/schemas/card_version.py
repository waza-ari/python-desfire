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
        temp += f"Hardware Version: {self.hardware_minor_version}.{self.hardware_minor_version}\r\n"
        temp += f"Software Version: {self.software_major_version}.{self.software_minor_version}\r\n"
        temp += f"EEPROM size:      {1 << (self.hardware_storage_size - 1)} bytes\r\n"
        temp += f"Production:       week {self.production_date_cw:X}, year 20{self.production_date_year:02X}\r\n"
        temp += f"UID no:           {to_hex_string(self.uid)}\r\n"
        temp += f"Batch no:         {to_hex_string(self.batch_no)}\r\n"
        return temp
