#!/bin/bash
set -ex
ip netns add client
ip netns add client_tunnel
ip netns add server_tunnel
ip netns add server


ip link add c2t type veth peer name t2c
ip link add ct type veth peer name st 
ip link add t2s type veth peer name s2t

ip link set c2t netns client
ip link set t2c netns client_tunnel
ip link set ct netns client_tunnel
ip link set st netns server_tunnel 
ip link set t2s netns server_tunnel 
ip link set s2t netns server


# Emulate a LAN - with the tunneler being our default gateway
ip netns exec client ip address add 1.0.0.2/24 dev c2t
ip netns exec client_tunnel ip address add 1.0.0.1/24 dev t2c
ip netns exec client ip link set c2t up
ip netns exec client_tunnel ip link set t2c up
ip netns exec client ip route add default via 1.0.0.1
ip netns exec client_tunnel iptables --append INPUT --protocol tcp --jump DROP
ip netns exec client_tunnel iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP

# Config tunnel - emulate the internet
ip netns exec client_tunnel ip address add 2.0.0.2/24 dev ct
ip netns exec server_tunnel ip address add 2.0.0.1/24 dev st
ip netns exec client_tunnel ip link set ct up
ip netns exec server_tunnel ip link set st up
ip netns exec server_tunnel iptables --append INPUT --protocol tcp --jump DROP
ip netns exec client_tunnel iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP


# Config server & tunnel - emulate another LAN
ip netns exec server_tunnel ip address add 3.0.0.1/24 dev t2s
ip netns exec server ip address add 3.0.0.2/24 dev s2t
ip netns exec server_tunnel ip link set t2s up
ip netns exec server ip link set s2t up
ip netns exec server ip route add default via 3.0.0.1
set +ex
