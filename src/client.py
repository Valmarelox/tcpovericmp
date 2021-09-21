import asyncio
import struct
from asyncio import DatagramProtocol

from scapy.all import *
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_ICMP, AF_PACKET, IPPROTO_TCP, IPPROTO_RAW

from src.common import AsyncSocket, tunneler, tunneler_to_tcp


def icmp_wrapper(data: bytes) -> bytes:
    # TODO: Do proper
    print('Wrapper', IP(data[14:]).summary())
    return struct.pack('!BBHHH', 8, 0, 0, 37, 1) + data[14:]


def icmp_unwrapper1(data: bytes) -> bytes:
    ihl = data[0] & 0xf
    assert ihl == 5, ihl
    data = data[20 + 8:]
    pkt = IP(data)
    print('Unwrapper', pkt.summary())
    return pkt


async def client():
    loop = asyncio.get_running_loop()
    # TODO: use create_datagram_endpoint with an existing socket
    icmp_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))
    icmp_sock.bind(('2.0.0.2', 0))
    icmp_sock.connect(('2.0.0.1', 0))
    tcp_sniff_sock = AsyncSocket(loop, socket(AF_PACKET, SOCK_RAW, 0x08))
    tcp_sniff_sock.set_bpf('tcp and inbound')
    response_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_RAW))
    tasks = [
        asyncio.create_task(tunneler(tcp_sniff_sock, icmp_sock, icmp_wrapper)),
        asyncio.create_task(tunneler_to_tcp(icmp_sock, response_sock, icmp_unwrapper1))
    ]
    await asyncio.wait(tasks)


async def main():
    await client()


asyncio.run(main(), debug=True)
