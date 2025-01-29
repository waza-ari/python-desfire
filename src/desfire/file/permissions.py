from ..util import get_bytes


class DESFireFilePermissions:
    def __init__(self):
        self.read_access = None
        self.write_access = None
        self.read_and_write_access = None
        self.change_access = None

    def pack(self):
        return (
            (self.read_access << 4)
            | (self.write_access)
            | (self.read_and_write_access << 12)
            | (self.change_access << 8)
        )

    def unpack(self, data):
        data = int.from_bytes(get_bytes(data), byteorder="big")
        self.read_access = bool((data >> 4) & 0x0F)
        self.write_access = bool((data) & 0x0F)
        self.read_and_write_access = bool((data >> 12) & 0x0F)
        self.change_access = bool((data >> 8) & 0x0F)

    def set_perm(self, r, w, rw, c):
        self.read_access = r
        self.write_access = w
        self.read_and_write_access = rw
        self.change_access = c

    def __repr__(self):
        temp = "----- DESFireFilePermissions ---\r\n"
        if self.read_access:
            temp += "READ|"
        if self.write_access:
            temp += "WRITE|"
        if self.read_and_write_access:
            temp += "READWRITE|"
        if self.read_and_write_access:
            temp += "CHANGE|"
        return temp
