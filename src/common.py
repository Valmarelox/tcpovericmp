import asyncio
import struct
import subprocess
from asyncio import AbstractEventLoop
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
    print(f"Got BPF of {int(count)} opcodes")
    opcode_packer = struct.Struct("HBBI")
    for line in p.stdout:
        code, k, jt, jf = (int(x) for x in line.strip().split(b' '))
        yield opcode_packer.pack(code, k, jt, jf)


class AsyncSocket:
    def __init__(self, loop: AbstractEventLoop, s: socket):
        self._loop = loop
        self._s = s
        self._s.setblocking(False)

    async def recv(self, nbytes: int):
        return await self._loop.sock_recv(self._s, nbytes)

    async def send(self, data: bytes):
        return await self._loop.sock_sendall(self._s, data)

    def sendto(self, data, to):
        return self._s.sendto(data, to)

    def connect(self, t: Tuple):
        return self._s.connect(t)

    def bind(self, t: Tuple):
        return self._s.bind(t)

    def set_bpf(self, filter: str):
        # TODO: Less hack
        self._set_bpf('vlan 100')
        try:
            while True:
                b = self._s.recv(1)
        except BlockingIOError:
            pass
        except:
            raise
        self._set_bpf(filter)

    def _set_bpf(self, filter: str):
        # TODO: Flush
        prog = list(get_bpf(filter))
        prog_buffer = b''.join(prog)
        b = create_string_buffer(prog_buffer)
        mem_addr = addressof(b)
        fprog = struct.pack('HL', len(prog), mem_addr)
        self._s.setsockopt(SOL_SOCKET, 26, fprog)

    def __repr__(self):
        return f'<AsyncSocket {self._s.family},{self._s.type},{self._s.proto}>'


async def tunneler_to_tcp(src: AsyncSocket, dst: AsyncSocket, transform: Callable):
    print("Tunneling")
    while True:
        data = await src.recv(2 ** 16 - 1)
        data = transform(data)
        send(IP(data))


async def tunneler(src: AsyncSocket, dst: AsyncSocket, transform: Callable):
    print("Tunneling")
    while True:
        data = await src.recv(2 ** 16 - 1)
        data = transform(data)
        await dst.send(data)


def icmp_unwrapper(data: bytes) -> bytes:
    ihl = data[0] & 0xf
    assert ihl == 5, ihl
    data = data[20 + 8:]
    pkt = IP(data)
    print('Unwrapper', pkt.summary())
    pkt[IP].src = None
    pkt[TCP].chksum = None
    pkt[IP].chksum = None
    data = bytes(pkt)
    print('NONONO', data)
    return data

def icmp_unwrapper1(data: bytes) -> bytes:
    ihl = data[0] & 0xf
    assert ihl == 5, ihl
    data = data[20 + 8:]
    pkt = IP(data)
    print('Unwrapper', pkt.summary())
    print('NONONO', data)
    return data

def icmp_wrapper(data: bytes) -> bytes:
    # TODO: Do proper
    print('Wrapper', IP(data[14:]).summary())
    return struct.pack('!BBHHH', 8, 0, 0, 37, 1) + data[14:]

def icmp_wrapper1(data: bytes) -> bytes:
    # TODO: Do proper
    pkt = IP(data[14:])
    pkt[IP].dst = '1.0.0.2'
    pkt[IP].chksum = None
    pkt[TCP].chksum = None
    print('Wrapper', pkt.summary())
    return struct.pack('!BBHHH', 8, 0, 0, 37, 1) + bytes(pkt)
