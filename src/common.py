from asyncio import AbstractEventLoop, Future
from socket import socket, SOL_SOCKET
from typing import Callable, Tuple, Optional
from scapy.arch.bpf.core import compile_filter


class AsyncSocket:
    """
        Wrap a socket object - allowing it to be used with asyncio library
    """

    def __init__(self, loop: AbstractEventLoop, s: socket):
        self._loop = loop
        self._s = s
        self._s.setblocking(False)

    def __del__(self):
        if self._s:
            self._s.close()
            self._s = None

    async def recv(self, nbytes: int):
        return await self._loop.sock_recv(self._s, nbytes)

    async def send(self, data: bytes):
        return await self._loop.sock_sendall(self._s, data)

    async def sendto(self, data, to):
        if to is None:
            return await self.send(data)

        future = self._loop.create_future()
        self._sendto(future, None, data, to)
        return await future

    def _sendto(self, fut: Future, fd, data, to):
        """
            Implementation of sendto which supports async
        """
        if fd is not None:
            self._loop.remove_writer(fd)
        if fut.cancelled():
            return

        try:
            self._s.sendto(data, to)
            fut.set_result(None)
            return
        except (BlockingIOError, InterruptedError):
            self._loop.add_writer(self._s.fileno(), self._sendto, fut, self._s.fileno(), data, to)
        except Exception as e:
            fut.set_exception(e)


    def connect(self, t: Tuple):
        return self._s.connect(t)

    def bind(self, t: Tuple):
        return self._s.bind(t)

    def set_bpf(self, filter: str):
        """
            Set a bpf specified by the textual format in `filter`
        """
        # Set a bpf that blocks all traffic
        self._set_bpf('ip[0] = 0 and vlan 100')
        # Flush the socket of any previous packets
        self._flush_socket()
        # Set the actual bpf
        self._set_bpf(filter)

    def setsockopt(self, level, optname, value):
        return self._s.setsockopt(level, optname, value)

    def _flush_socket(self):
        try:
            while True:
                b = self._s.recv(1)
        except BlockingIOError:
            pass

    def _set_bpf(self, bpf_filter: str):
        # linktype=1 is DLT_EN10MB
        prog = compile_filter(bpf_filter, linktype=1)
        # call SO_ATTACH_FILTER
        self.setsockopt(SOL_SOCKET, 26, prog)

    def __repr__(self):
        return f'<AsyncSocket {self._s.family},{self._s.type},{self._s.proto}>'


TransformResult = Optional[tuple[bytes, Optional[tuple[bytes, int]]]]
TransformFuncType = Callable[[bytes], TransformResult]


async def tunneler(src: AsyncSocket, dst: AsyncSocket, transform: TransformFuncType):
    """
        Read from src, pass to the transform function, send on the dst socket
    """
    while True:
        data = await src.recv(2 ** 16 - 1)  # Max IP Packet size
        if res := transform(data):
            # transmit if transform didn't drop the packet
            await dst.sendto(*res)
