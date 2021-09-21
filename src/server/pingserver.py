from random import randint

from src.common.sockets.icmpsocket import ICMPSocket


class PingServer:
    def __init__(self):
        self._id = None
        self._seq = None
        self._s = ICMPSocket()

    def recvmsg(self) -> bytes:
        res = self._s.recvmsg()

        if self._id is None:
            self._id = res.msg.id
            self._seq = res.msg.seq

        return res.msg.data

    def sendmsg(self, data: bytes):
        pass
