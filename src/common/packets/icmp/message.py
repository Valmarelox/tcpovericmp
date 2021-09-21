from dataclasses import dataclass


@dataclass
class ICMPMessage:
    FORMAT = Struct('!HHQ')
    id: int
    seq: int
    timestamp: int
    data: bytes

    @classmethod
    def frombytes(cls, param):
        pass


    @classmethod
    def size(cls):
        return cls.FORMAT.size
