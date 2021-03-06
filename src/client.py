import asyncio
from optparse import OptionParser
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_ICMP, AF_PACKET, IPPROTO_RAW
from typing import Optional

from scapy.layers.all import Ether, IP, ICMP, Raw

from src.common import AsyncSocket, tunneler

SELF_TUNNEL_IP = '2.0.0.2'


def icmp_wrapper(data: bytes) -> Optional[tuple[bytes, Optional[tuple[bytes, int]]]]:
    # Wrap the packet IP layer and up in an ICMP Echo Request header
    return bytes(ICMP(seq=1, id=37)) + bytes(Ether(data)[IP]), None


def icmp_unwrapper(data: bytes) -> Optional[tuple[bytes, Optional[tuple[bytes, int]]]]:
    wrapper_pkt = IP(data)
    if wrapper_pkt[ICMP].type != 8:
        # Drop all packets which are not ICMP Echo request
        return
    pkt = IP(bytes(wrapper_pkt[Raw]))
    return bytes(pkt), (pkt[IP].dst, 0)


async def client(dst_ip):
    loop = asyncio.get_running_loop()
    # ICMP Tunnel socket
    icmp_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))
    icmp_sock.bind((SELF_TUNNEL_IP, 0))
    icmp_sock.connect((dst_ip, 0))

    # TCP Raw sniffer
    tcp_sniff_sock = AsyncSocket(loop, socket(AF_PACKET, SOCK_RAW, 0x08))
    tcp_sniff_sock.set_bpf('tcp and inbound')

    # Raw TCP send socket
    response_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_RAW))

    tasks = (
        # Client => Tunnel
        asyncio.create_task(tunneler(tcp_sniff_sock, icmp_sock, icmp_wrapper)),
        # Tunnel => Client
        asyncio.create_task(tunneler(icmp_sock, response_sock, icmp_unwrapper))
    )
    await asyncio.wait(tasks)


def parse_arguments():
    parser = OptionParser()
    parser.add_option('-d', '--dst-ip', dest='dst_ip', help='Tunnel server IP address')
    options, args = parser.parse_args()
    return options, args


async def main():
    options, _ = parse_arguments()
    await client(options.dst_ip)


asyncio.run(main())
