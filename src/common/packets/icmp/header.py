from dataclasses import dataclass
from struct import Struct


# TODO: Do in reverse - make the message generate the header
from src.common.packets.icmp.message import ICMPMessage


class ICMPHeader:
    FORMAT = Struct('!BBH')
    type: int
    code: int
    msg: ICMPMessage

    @property
    def checksum(self):
        return 0

    def pack(self):
        return self.FORMAT.pack(self.type, self.code, self.checksum) + self.msg

    def __bytes__(self):
        return self.pack()

    @classmethod
    def size(cls):
        return cls.FORMAT.size

    @classmethod
    def frombytes(cls, buf: bytes):
        return ICMPHeader(*(cls.FORMAT.unpack(buf[:cls.size()]) + (ICMPMessage.frombytes([cls.size():]),)))

