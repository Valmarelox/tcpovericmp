#!/bin/bash

ip netns exec client_tunnel python main.py
ip netns exec client_tunnel python server.py
