from ..util import to_human_readable_hex


class DESFireCardVersion:
    def __init__(self, data):
        self.rawBytes = data
        self.hardwareVendorId = data[0]
        self.hardwareType = data[1]
        self.hardwareSubType = data[2]
        self.hardwareMajVersion = data[3]
        self.hardwareMinVersion = data[4]
        self.hardwareStorageSize = data[5]
        self.hardwareProtocol = data[6]

        self.softwareVendorId = data[7]
        self.softwareType = data[8]
        self.softwareSubType = data[9]
        self.softwareMajVersion = data[10]
        self.softwareMinVersion = data[11]
        self.softwareStorageSize = data[12]
        self.softwareProtocol = data[13]

        self.UID = data[14:21]  # The serial card number
        self.batchNo = data[21:25]  # The batch number
        self.cwProd = data[26]  # The production week (BCD)
        self.yearProd = data[27]  # The production year (BCD)

    def __repr__(self):
        temp = "--- Desfire Card Details ---\r\n"
        temp += f"Hardware Version: {self.hardwareMajVersion}.{self.hardwareMinVersion}\r\n"
        temp += f"Software Version: {self.softwareMajVersion}.{self.softwareMinVersion}\r\n"
        temp += f"EEPROM size:      {1 << (self.hardwareStorageSize - 1)} bytes\r\n"
        temp += f"Production :       week {self.cwProd:X}, year 20{self.yearProd:02X}\r\n"
        temp += f"UID no  : {to_human_readable_hex(self.UID)}\r\n"
        temp += f"Batch no: {to_human_readable_hex(self.batchNo)}\r\n"
        return temp
