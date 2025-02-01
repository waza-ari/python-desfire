from smartcard.util import toHexString


class DESFireCardVersion:
    def __init__(self, data):
        self.raw_bytes = data
        self.hardware_vendor_id = data[0]
        self.hardware_type = data[1]
        self.hardware_sub_type = data[2]
        self.hardware_major_version = data[3]
        self.hardware_minor_version = data[4]
        self.hardware_storage_size = data[5]
        self.hardware_protocol = data[6]

        self.software_vendor_id = data[7]
        self.software_type = data[8]
        self.software_sub_type = data[9]
        self.software_major_version = data[10]
        self.software_minor_version = data[11]
        self.software_storage_size = data[12]
        self.software_protocol = data[13]

        self.uid = data[14:21]  # The serial card number
        self.batch_no = data[21:25]  # The batch number
        self.production_date_cw = data[26]  # The production week (BCD)
        self.production_date_year = data[27]  # The production year (BCD)

    def __repr__(self):
        temp = "--- Desfire Card Details ---\r\n"
        temp += f"Hardware Version: {self.hardware_minor_version}.{self.hardware_minor_version}\r\n"
        temp += f"Software Version: {self.software_major_version}.{self.software_minor_version}\r\n"
        temp += f"EEPROM size:      {1 << (self.hardware_storage_size - 1)} bytes\r\n"
        temp += f"Production :       week {self.production_date_cw:X}, year 20{self.production_date_year:02X}\r\n"
        temp += f"UID no  : {toHexString(self.uid)}\r\n"
        temp += f"Batch no: {toHexString(self.batch_no)}\r\n"
        return temp
