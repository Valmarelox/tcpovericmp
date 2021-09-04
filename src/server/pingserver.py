
class PingServer:
    def __init__(self):
        self._id = None
        self._seq = None
    def recvmsg(self) -> bytes:
        if self._id is None:
            self._id = id
            self._seq = seq
            
        pass

    def sendmsg(self, data: bytes):
        pass