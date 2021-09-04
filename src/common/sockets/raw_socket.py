from socket import AF_PACKET, SOCK_RAW

class RawSocket:
    def __init__(self, bpf):
        # TODO: can I use pcapy?
        self._s = socket(AF_PACKET, SOCK_RAW)

    def recvmsg(self) -> bytes:
        pass

    def sendmsg(self) -> bytes:
        pass