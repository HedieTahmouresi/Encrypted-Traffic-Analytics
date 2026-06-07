#!/bin/bash

# Exit immediately if any command fails
set -e

echo "--- Starting Environment Setup ---"

# 1. Install Zeek (if not already present)
if [ ! -d "/opt/zeek" ]; then
    echo "Zeek not found. Installing..."
    
    # Add the Zeek repository and key (Assumes Ubuntu 24.04)
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
    
    sudo apt update
    sudo apt install -y zeek
else
    echo "Zeek is already installed in /opt/zeek."
fi

# 2. Install project requirements
echo "Installing Python dependencies..."
pip install -r requirements.txt

echo "--- Setup Complete! Run the project using ./run.sh ---"