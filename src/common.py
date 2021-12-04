import struct
import subprocess
from asyncio import AbstractEventLoop, Future
from ctypes import create_string_buffer, addressof

from scapy.all import *
from typing import Callable, Tuple
from functools import partial
from socket import socket, SOL_SOCKET
import codecs

hexify = partial(codecs.encode, encoding='hex')


# TODO: Namespace with tunneler as default gateway
# TODO: Client that wraps in ICMP properly (including IP Headers)
# TODO: Server that unwraps properly
# TODO: Can I iptables NAT my raw sockets
# TODO: Iptables NAT on server side (using socket marks to release TCP through
# TODO: Do the reverse in the server side (add client code and vise versa)

def get_bpf(filter: str):
    p = subprocess.Popen(["tcpdump", "-ddd", filter], stdout=subprocess.PIPE)
    count = p.stdout.readline().strip()
    opcode_packer = struct.Struct("HBBI")
    for line in p.stdout:
        code, k, jt, jf = (int(x) for x in line.strip().split(b' '))
        yield opcode_packer.pack(code, k, jt, jf)


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
        future = self._loop.create_future()
        self._sendto(future, None, data, to)
        return await future

    def _sendto(self, fut: Future, fd, data, to):
        if fd is not None:
            self._loop.remove_writer(fd)
        if fut.cancelled():
            return

        try:
            n = self._s.sendto(data, to)
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
        self._set_bpf('vlan 100')
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


    def _set_bpf(self, filter: str):
        prog = list(get_bpf(filter))
        prog_buffer = b''.join(prog)
        # Use ctypes to generate the struct required by setsockopt
        b = create_string_buffer(prog_buffer)
        mem_addr = addressof(b)
        fprog = struct.pack('HL', len(prog), mem_addr)
        self._s.setsockopt(SOL_SOCKET, 26, fprog)

    def __repr__(self):
        return f'<AsyncSocket {self._s.family},{self._s.type},{self._s.proto}>'


async def tunneler_to_tcp(src: AsyncSocket, dst: AsyncSocket, transform: Callable):
    while True:
        data = await src.recv(2 ** 16 - 1)
        # Don't die on transform fails
        pkt = transform(data)
        await dst.sendto(bytes(pkt), (pkt[IP].dst, 0))


async def tunneler(src: AsyncSocket, dst: AsyncSocket, transform: Callable):
    while True:
        data = await src.recv(2 ** 16 - 1)
        data = transform(data)
        await dst.send(data)
