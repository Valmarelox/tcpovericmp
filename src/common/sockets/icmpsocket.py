from socket import socket, AF_INET, SOCK_RAW, IPPROTO_ICMP

class ICMPSocket:
    def __init__(self):
        self._s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
    
    def sendmsg(self, msg: ICMPMessage):
        pass

    def recvmsg(self) -> ICMPMessage

    def fileno(self):
        return self._s.fileno()