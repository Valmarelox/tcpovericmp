import asyncio
import struct
from asyncio import DatagramProtocol

from scapy.all import *
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_ICMP, AF_PACKET, IPPROTO_TCP, IPPROTO_RAW

from src.common import AsyncSocket, tunneler, tunneler_to_tcp
from optparse import OptionParser

SELF_TUNNEL_IP = '2.0.0.2'


def icmp_wrapper(data: bytes) -> bytes:
    return bytes(ICMP(seq=1, id=37)) + bytes(Ether(data)[IP])

def icmp_unwrapper1(data: bytes) -> bytes:
    wrapper_pkt = IP(data)
    return IP(bytes(wrapper_pkt[Raw]))

async def client(dst_ip):
    loop = asyncio.get_running_loop()
    # TODO: use create_datagram_endpoint with an existing socket
    icmp_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))
    icmp_sock.bind((SELF_TUNNEL_IP, 0))
    icmp_sock.connect((dst_ip, 0))

    tcp_sniff_sock = AsyncSocket(loop, socket(AF_PACKET, SOCK_RAW, 0x08))
    tcp_sniff_sock.set_bpf('tcp and inbound')

    response_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_RAW))

    tasks = [
        asyncio.create_task(tunneler(tcp_sniff_sock, icmp_sock, icmp_wrapper)),
        asyncio.create_task(tunneler_to_tcp(icmp_sock, response_sock, icmp_unwrapper1))
    ]
    await asyncio.wait(tasks)

def parse_arguments():
    parser = OptionParser()
    parser.add_option('-d', '--dst-ip', dest='dst_ip', help='Tunnel server IP address')
    options, args = parser.parse_args()
    return options, args


async def main():
    options, _ = parse_arguments()
    await client(options.dst_ip)


asyncio.run(main(), debug=True)
