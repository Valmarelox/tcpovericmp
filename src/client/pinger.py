from random import randint

from src.common.sockets.icmpsocket import ICMPSocket


class Pinger:
    def __init__(self, dst_ip: str):
        self._id = randint(1, 2**32-1)
        self._sequence = 0
        self._s = ICMPSocket()

    def sendmsg(self, data: bytes):
        req = ICMPEchoRequest(self._id, self._sequence, data)
        self._s.sendmsg(req)
        self._sequence += 1

    def recvmsg(self) -> bytes:
        res = self._s.recv()
        # We do not check returned sequence numbers for reodring or PL as we trust the underlying TCP layer to handle it
        return res.data
    
    def fileno():
        self._s.fileno()

