import asyncio
import struct
from scapy.layers.all import Ether, IP, TCP, ICMP, Raw
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_ICMP, IPPROTO_RAW, IPPROTO_IP, IP_HDRINCL, AF_PACKET, SOL_SOCKET
from datetime import datetime, timedelta

from src.common import AsyncSocket, tunneler, tunneler, get_bpf

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
        pkt[IP].src, _, pkt[TCP].sport, _ = masquarade_tuple
    else:
        # add new entry to the table
        for _ in range(2 ** 16):
            sport = CURRENT_PORT
            CURRENT_PORT = (CURRENT_PORT + 1) % (2 ** 16)
            mask_tuple = (SELF_WORLD_IP, pkt[IP].dst, sport, pkt[TCP].dport)
            if mask_tuple not in RNAT_TABLE:
                break
            last_used, _ = NAT_TABLE[four_tuple]
            if datetime.now() - last_used >= 15 * 60:
                # Record is stale, override
                break
        else:
            # Too many clients try to acess the same target address, cannot NAT them all
            raise RuntimeError(f"Too many nat records for {pkt[IP].dst}:{pkt[TCP].dport}")
        NAT_TABLE[four_tuple] = (datetime.now(), mask_tuple)
        RNAT_TABLE[mask_tuple] = four_tuple
        pkt[IP].src, _, pkt[TCP].sport, _ = mask_tuple


def icmp_unwrapper(data: bytes) -> bytes:
    pkt = IP(bytes(IP(data)[Raw]))
    nat(pkt)

    pkt[IP].chksum = None
    pkt[TCP].chksum = None
    return bytes(pkt), (pkt[IP].dst, 0)


def icmp_wrapper(data: bytes) -> bytes:
    # TODO: Do proper
    pkt = Ether(data)[IP]
    try:
        rnat(pkt)
    except KeyError:
        # Drop the packet if we can't reverse NAT it
        return

    # Let scapy recalculate the checksums
    pkt[IP].chksum = None
    pkt[TCP].chksum = None

    return bytes(ICMP(seq=1, id=37)) + bytes(pkt), None


async def server():
    loop = asyncio.get_running_loop()
    icmp_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))
    icmp_sock.bind((SELF_TUNNEL_IP, 0))
    icmp_sock.connect((TARGET_TUNNEL_IP, 0))
    tcp_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_RAW))
    tcp_sniff_sock = AsyncSocket(loop, socket(AF_PACKET, SOCK_RAW, 0x08))
    tcp_sniff_sock.set_bpf('tcp and inbound')
    tasks = [
        asyncio.create_task(tunneler(icmp_sock, tcp_sock, icmp_unwrapper)),
        asyncio.create_task(tunneler(tcp_sniff_sock, icmp_sock, icmp_wrapper)),
    ]
    await asyncio.wait(tasks)


async def main():
    await server()


asyncio.run(main())
