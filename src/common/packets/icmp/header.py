from dataclasses import dataclass
from struct import Struct

# TODO: Do in reverse - make the message generate the header
class ICMPHeader:
    FORMAT = Struct('!BBH')
    type: int
    code: int
    # TODO: This is echo stuff only
    msg: ICMPMessage


    @property
    def checksum():
        return 0
    
    def pack(self):
        return self.FORMAT.pack(self.type, self.code, self.checksum) + msg

    def __bytes__(self):
        return self.pack()

    def frombytes(self, buf: bytes) -> ICMPSocket:
        return self.FORMAT.unpack(buf[:self.size()])

    @classmethod
    def size(cls):
        return cls.FORMAT.size()