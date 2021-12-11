import asyncio
from datetime import datetime
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_ICMP, IPPROTO_RAW, AF_PACKET
from typing import Tuple, Optional

from scapy.layers.all import Ether, IP, TCP, ICMP, Raw

from src.common import AsyncSocket, tunneler, TransformResult

NAT_TABLE = {}
RNAT_TABLE = {}
CURRENT_PORT = 1025
PORT_MAX = 2 ** 16
NAT_RECORD_TIMEOUT = 15 * 60

SELF_TUNNEL_IP = '2.0.0.1'
TARGET_TUNNEL_IP = '2.0.0.2'

SELF_WORLD_IP = '3.0.0.1'


def rnat(pkt):
    """
        Reverse NAT a response packet
    """
    pkt[IP].dst, _, pkt[TCP].dport, _ = RNAT_TABLE[(pkt[IP].dst, pkt[IP].src, pkt[TCP].dport, pkt[TCP].sport)]


def _nat_new_entry(pkt, four_tuple):
    global CURRENT_PORT
    # add new entry to the table
    # Attempt to find a free port for the new four tuple
    for _ in range(PORT_MAX):
        sport = CURRENT_PORT
        CURRENT_PORT = (CURRENT_PORT + 1) % (PORT_MAX)
        mask_tuple = (SELF_WORLD_IP, pkt[IP].dst, sport, pkt[TCP].dport)
        if mask_tuple not in RNAT_TABLE:
            # The port is not in the table
            break
        last_used, _ = NAT_TABLE[four_tuple]
        if datetime.now() - last_used >= NAT_RECORD_TIMEOUT:
            # Record is stale, override
            break
    else:
        # Too many clients try to acess the same target address, cannot NAT them all
        raise RuntimeError(f"Too many nat records for {pkt[IP].dst}:{pkt[TCP].dport}")

    # Add the entries
    NAT_TABLE[four_tuple] = (datetime.now(), mask_tuple)
    RNAT_TABLE[mask_tuple] = four_tuple
    # NAT the packet
    pkt[IP].src, _, pkt[TCP].sport, _ = mask_tuple


def nat(pkt):
    """
        Implement NATing for incoming packets
    """
    global CURRENT_PORT
    # Get the packets four tuple
    four_tuple = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
    if four_tuple not in NAT_TABLE:
        _nat_new_entry(pkt, four_tuple)
        return

    # We already saw this four tuple
    _, masquarade_tuple = NAT_TABLE[four_tuple]
    # Refresh the timeout on the entry
    NAT_TABLE[four_tuple] = (datetime.now(), masquarade_tuple)
    # NAT the packet
    pkt[IP].src, _, pkt[TCP].sport, _ = masquarade_tuple


def icmp_unwrapper(data: bytes) -> TransformResult:
    wrapped_pkt = IP(data)
    pkt = IP(bytes(wrapped_pkt[Raw]))
    if wrapped_pkt[ICMP].type != 8:
        # Drop all packets which are not ICMP Echo request
        return

    nat(pkt)

    # Let scapy recalculate the checksums
    pkt[IP].chksum = None
    pkt[TCP].chksum = None
    return bytes(pkt), (pkt[IP].dst, 0)


def icmp_wrapper(data: bytes) -> TransformResult:
    """
        Server => Tunnel transformer
    """
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

    # ICMP Tunnel Socket
    icmp_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))
    icmp_sock.bind((SELF_TUNNEL_IP, 0))
    icmp_sock.connect((TARGET_TUNNEL_IP, 0))

    # TCP Sender socket
    tcp_sock = AsyncSocket(loop, socket(AF_INET, SOCK_RAW, IPPROTO_RAW))

    # TCP Sniffer
    tcp_sniff_sock = AsyncSocket(loop, socket(AF_PACKET, SOCK_RAW, 0x08))
    tcp_sniff_sock.set_bpf('tcp and inbound')

    tasks = (
        # Tunnel => Server
        asyncio.create_task(tunneler(icmp_sock, tcp_sock, icmp_unwrapper)),
        # Server => Tunnel
        asyncio.create_task(tunneler(tcp_sniff_sock, icmp_sock, icmp_wrapper)),
    )
    await asyncio.wait(tasks)


async def main():
    await server()


if __name__ == '__main__':
    asyncio.run(main())
