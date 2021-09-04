from random import randint


class Pinger:
    def __init__(self, dst_ip: str):
        self._id = randint(1, 2**32-1)
        self._sequence = 0

    def sendmsg(self, data: bytes):
        req = ICMPEchoRequest(self._id, self._sequence, data)
        self._s.send(req)

        self._sequence += 1
        pass

    def recvmsg(self) -> bytes:
        res = self._s.recv()
        
        # TODO: assert seq
        pass
    
    def fileno():
        pass