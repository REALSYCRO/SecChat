#!/bin/bash

# Install Python and dependencies
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install cryptography --break-system-packages
echo "Installation complete."
