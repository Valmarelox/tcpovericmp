import asyncio
import struct
from scapy.all import *
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_ICMP, IPPROTO_RAW, IPPROTO_IP, IP_HDRINCL, AF_PACKET, SOL_SOCKET
from itertools import cycle

from src.common import AsyncSocket, tunneler, tunneler_to_tcp, get_bpf

NAT_TABLE = {}
RNAT_TABLE = {}
CURRENT_PORT = 1025

SELF_TUNNEL_IP = '2.0.0.1'
TARGET_TUNNEL_IP = '2.0.0.2'
SELF_WORLD_IP = '3.0.0.1'


def rnat(pkt):
    """
        Reverse NAT a response packet
    """
    pkt[IP].dst, _, pkt[TCP].dport, _ = RNAT_TABLE[(pkt[IP].dst, pkt[IP].src, pkt[TCP].dport, pkt[TCP].sport)]
    print(pkt[IP].dst, pkt[TCP].dport)


def nat(pkt):
    """
        Implement NATing for incoming packets
    """
    global CURRENT_PORT
    four_tuple = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
    if four_tuple in NAT_TABLE:
        # TODO: Clean the NAT
        _, masquarade_tuple = NAT_TABLE[four_tuple]
        NAT_TABLE[four_tuple] = (datetime.now(), masquarade_tuple)
        print(masquarade_tuple)
        pkt[IP].src, _, pkt[TCP].sport, _ = masquarade_tuple
    else:
        sport = CURRENT_PORT
        CURRENT_PORT = (CURRENT_PORT + 1) % (2 ** 16)
        mask_tuple = (SELF_WORLD_IP, pkt[IP].dst, sport, pkt[TCP].dport)
        NAT_TABLE[four_tuple] = (datetime.now(), mask_tuple)
        RNAT_TABLE[mask_tuple] = four_tuple
        print('Not in NAT table')
        pkt[IP].src, _, pkt[TCP].sport, _ = mask_tuple


def icmp_unwrapper(data: bytes) -> bytes:
    print('Unwrapping packet')
    pkt = IP(bytes(IP(data)[Raw]))
    nat(pkt)

    pkt[IP].chksum = None
    pkt[TCP].chksum = None

    print('Unwrapper', pkt.summary())
    return pkt


def icmp_wrapper(data: bytes) -> bytes:
    # TODO: Do proper
    pkt = Ether(data)[IP]
    rnat(pkt)
    pkt[IP].chksum = None
    pkt[TCP].chksum = None

    print('Wrapper', pkt.summary())
    return bytes(ICMP(seq=1, id=37)) + bytes(pkt)


async def server():
    loop = asyncio.get_running_loop()
    icmp_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))
    icmp_sock.bind((SELF_TUNNEL_IP, 0))
    icmp_sock.connect((TARGET_TUNNEL_IP, 0))
    tcp_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_RAW))
    tcp_sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    tcp_sniff_sock = AsyncSocket(loop, socket(AF_PACKET, SOCK_RAW, 0x08))
    tcp_sniff_sock.set_bpf('tcp and inbound')
    tasks = [
        asyncio.create_task(tunneler_to_tcp(icmp_sock, tcp_sock, icmp_unwrapper)),
        asyncio.create_task(tunneler(tcp_sniff_sock, icmp_sock, icmp_wrapper)),
    ]
    await asyncio.wait(tasks)


async def main():
    await server()


asyncio.run(main(), debug=True)
