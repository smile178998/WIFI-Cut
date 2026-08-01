#!/bin/bash
# WiFi Cut - Kali Linux 安装脚本

set -e

echo "======================================"
echo "  WiFi Cut 安装"
echo "======================================"

if [ "$EUID" -ne 0 ]; then
    echo "请使用 sudo 运行: sudo bash install.sh"
    exit 1
fi

echo "[1/3] 更新软件包..."
apt update -qq

echo "[2/3] 安装依赖..."
apt install -y aircrack-ng iw wireless-tools

echo "[3/3] 设置权限..."
chmod +x wifi_cut.py

echo ""
echo "安装完成！"
echo ""
echo "使用方法："
echo "  sudo python3 wifi_cut.py          # 交互模式"
echo "  sudo python3 wifi_cut.py -i wlan0 # 指定网卡"
echo ""
echo "⚠  仅在你拥有或已获授权的网络上使用！"
