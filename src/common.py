import struct
import subprocess
from asyncio import AbstractEventLoop, Future
from ctypes import create_string_buffer, addressof

from scapy.all import *
from typing import Callable, Tuple
from functools import partial
from socket import socket, SOL_SOCKET
import codecs

def get_bpf(s: str):
    return bpf.core.compile_filter(s, linktype=1)


class AsyncSocket:
    """
        Wrap a socket object - allowing it to be used with asyncio library
    """
    def __init__(self, loop: AbstractEventLoop, s: socket):
        self._loop = loop
        self._s = s
        self._s.setblocking(False)

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
        if fd is not None:
            self._loop.remove_writer(fd)
        if fut.cancelled():
            return

        try:
            try:
                n = self._s.sendto(data, to)
            except OSError:
                print(data, to)
                IP(data).show()
                raise
            fut.set_result(None)
            return
        except (BlockingIOError, InterruptedError):
            n = 0
        except Exception as e:
            fut.set_exception(e)
            return

        self._loop.add_writer(self._s.fileno(), self._sendto, fut, self._s.fileno(), data, to)

    def connect(self, t: Tuple):
        return self._s.connect(t)

    def bind(self, t: Tuple):
        return self._s.bind(t)

    def set_bpf(self, filter: str):
        # Set a bpf that blocks all traffic
        self._set_bpf('ip[0] = 0')
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
        except:
            raise


    def _set_bpf(self, bpf: str):
        prog = get_bpf(bpf)
        # call SO_ATTACH_FILTER
        self._s.setsockopt(SOL_SOCKET, 26, prog)

    def __repr__(self):
        return f'<AsyncSocket {self._s.family},{self._s.type},{self._s.proto}>'


async def tunneler(src: AsyncSocket, dst: AsyncSocket, transform: Callable):
    while True:
        data = await src.recv(2 ** 16 - 1)
        # Don't die on transform fails
        if res := transform(data):
            await dst.sendto(*res)

