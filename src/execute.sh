#!/bin/bash

ip netns exec client_tunnel python client.py
ip netns exec client_tunnel python server.py
