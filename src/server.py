import asyncio
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_ICMP, IPPROTO_RAW, IPPROTO_IP, IP_HDRINCL, AF_PACKET, SOL_SOCKET

from src.common import AsyncSocket, tunneler, icmp_unwrapper, icmp_wrapper, tunneler_to_tcp, get_bpf, icmp_wrapper1


async def server():
    loop = asyncio.get_running_loop()
    icmp_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))
    icmp_sock.bind(('2.0.0.1', 0))
    icmp_sock.connect(('2.0.0.2', 0))
    tcp_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_RAW))
    tcp_sock._s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    tcp_sniff_sock = AsyncSocket(loop, socket(AF_PACKET, SOCK_RAW, 0x08))
    tcp_sniff_sock.set_bpf('tcp')
    tasks = [
        asyncio.create_task(tunneler_to_tcp(icmp_sock, tcp_sock, icmp_unwrapper)),
        asyncio.create_task(tunneler(tcp_sniff_sock, icmp_sock, icmp_wrapper1)),
    ]


async def main():
    await server()
    # asyncio.create_task(tunneler(tcp_sock, icmp_sock, None))]

    await asyncio.sleep(3600)


asyncio.run(main(), debug=True)
