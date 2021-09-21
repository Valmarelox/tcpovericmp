from socket import socket, AF_INET, SOCK_RAW, IPPROTO_ICMP

from src.common.packets.icmp.header import ICMPHeader


class ICMPSocket:
    def __init__(self, dst_ip: str):
        self._s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        self._s.connect((dst_ip, 0))

    def sendmsg(self, msg: ICMPHeader):
        self._s.send(ICMPHeader.pack())
        pass

    def recvmsg(self) -> ICMPHeader:
        data =  self._s.recv()
        return ICMPHeader.frombytes(data)

    def fileno(self):
        return self._s.fileno()
