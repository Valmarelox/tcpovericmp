import asyncio
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_ICMP, AF_PACKET, IPPROTO_TCP

from src.common import AsyncSocket, tunneler, icmp_wrapper, tunneler_to_tcp, icmp_unwrapper, icmp_unwrapper1


async def client():
    loop = asyncio.get_running_loop()
    icmp_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))
    icmp_sock.bind(('2.0.0.2', 0))
    icmp_sock.connect(('2.0.0.1', 0))
    tcp_sniff_sock = AsyncSocket(loop, socket(AF_PACKET, SOCK_RAW, 0x08))
    tcp_sniff_sock.set_bpf('tcp')
    response_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_TCP))
    tasks = [
        asyncio.create_task(tunneler(tcp_sniff_sock, icmp_sock, icmp_wrapper)),
        asyncio.create_task(tunneler_to_tcp(icmp_sock, response_sock, icmp_unwrapper1))
    ]


async def main():
    await client()
    # asyncio.create_task(tunneler(tcp_sock, icmp_sock, None))]

    await asyncio.sleep(3600)

asyncio.run(main(), debug=True)
