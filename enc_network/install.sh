#!/bin/bash

# Install Python and dependencies
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install cryptography
git clone https://your-repo.com/securechat
cd securechat
chmod +x install.sh
./install.sh
echo "Installation complete."
