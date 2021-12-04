#!/bin/bash

setsid ip netns exec client_tunnel python -m src.client -d 2.0.0.1 &
setsid ip netns exec server_tunnel python -m src.server &
