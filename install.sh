#!/bin/bash
# WiFi Cut - Kali Linux install script

set -e

echo "======================================"
echo "  WiFi Cut Setup"
echo "======================================"

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo: sudo bash install.sh"
    exit 1
fi

echo "[1/3] Updating packages..."
apt update -qq

echo "[2/3] Installing dependencies..."
apt install -y aircrack-ng iw wireless-tools mdk4

echo "[3/3] Setting permissions..."
chmod +x wifi_cut.py

echo ""
echo "Installation complete!"
echo ""
echo "Usage:"
echo "  sudo python3 wifi_cut.py          # interactive mode"
echo "  sudo python3 wifi_cut.py -i wlan0 # specify interface"
echo ""
echo "⚠  Use only on networks you own or are authorized to test!"
