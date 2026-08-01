# WiFi Cut

[![Kali Linux](https://img.shields.io/badge/Platform-Kali%20Linux-blue)](https://www.kali.org/)
[![Python 3](https://img.shields.io/badge/Python-3.8+-green)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Educational%20Use-only)](LICENSE)

Scan nearby WiFi networks and phone hotspots on **Kali Linux**, discover connected clients, and disconnect them using deauth attacks.

> **Legal notice:** Use only on networks you **own** or are **explicitly authorized** to test. Unauthorized interference with wireless networks is illegal in most countries.

---

## Features

- Scan nearby WiFi / hotspots (including phone tethering)
- Discover connected clients (channel-locked, multi-AP SSID support)
- Disconnect all clients or a specific device
- Aggressive mode (`mdk4` + high-volume deauth)
- Built-in diagnostics (`--check`)
- Graceful exit (Ctrl+C restores your adapter)

---

## Quick start

```bash
git clone https://github.com/smile178998/WIFI-Cut.git
cd WIFI-Cut
sudo bash install.sh
sudo python3 wifi_cut.py
```

Run diagnostics if something fails:

```bash
sudo python3 wifi_cut.py --check
```

---

## Requirements

| Item | Details |
|------|---------|
| OS | Kali Linux (recommended) or Debian-based Linux with `aircrack-ng` |
| Privileges | `root` / `sudo` required |
| Python | 3.8+ (no extra pip packages) |
| Wireless adapter | Must support **monitor mode** + packet injection |

### Tested adapters

| Adapter | Chipset | Notes |
|---------|---------|-------|
| TP-Link TL-WN722N **v1** | AR9271 | Recommended, works out of the box |
| Alfa AWUS036ACH | — | Popular pentest adapter |
| Many built-in laptop WiFi | — | Often **do not** support monitor mode |

> **WN722N v2/v3** (Realtek) have poor Linux monitor support. Check with `lsusb` — v1 shows `AR9271`.

---

## Installation

### Automatic

```bash
sudo bash install.sh
```

Installs: `aircrack-ng`, `iw`, `wireless-tools`, `mdk4`

### Manual

```bash
sudo apt update
sudo apt install -y aircrack-ng iw wireless-tools mdk4
```

### Verify adapter

```bash
iw dev
lsusb
```

You should see an interface like `wlan0`.

---

## Usage

### Interactive mode (recommended)

```bash
sudo python3 wifi_cut.py
```

| Step | Action |
|------|--------|
| 1 | Select wireless interface (`wlan0`) |
| 2 | Wait ~30s for scan |
| 3 | Pick target WiFi by number |
| 4 | Wait ~40s for client discovery |
| 5 | Choose disconnect action |

**Disconnect options:**

| Key | Action |
|-----|--------|
| `1` | Disconnect all clients (standard deauth) |
| `2` | Disconnect one specific client |
| `3` | Continuous disconnect until Ctrl+C |
| `4` | **Aggressive** — mdk4 flood + channel lock + heavy deauth |
| `5` | Re-scan clients (45s) |
| `0` | Back to WiFi list |

**Tips for client discovery:**

- Keep phones/laptops **actively using** the target WiFi (video, download)
- Enterprise SSIDs may have multiple APs with the same name — the tool matches by SSID
- If clients = 0, use option `5` or option `4` (works without client list)

### Command line

```bash
# Diagnostics
sudo python3 wifi_cut.py --check
sudo python3 wifi_cut.py --check -i wlan0

# Specify interface
sudo python3 wifi_cut.py -i wlan0

# Longer scan
sudo python3 wifi_cut.py -i wlan0 --scan 45

# Disconnect all clients on an AP
sudo python3 wifi_cut.py -i wlan0 -b AA:BB:CC:DD:EE:FF --deauth-all

# Aggressive continuous attack
sudo python3 wifi_cut.py -i wlan0 -b AA:BB:CC:DD:EE:FF --channel 6 --deauth-all --aggressive --continuous

# Disconnect one client
sudo python3 wifi_cut.py -i wlan0 -b AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 --deauth-all
```

### Output legend

```
  #    Name                   BSSID              CH    Signal  Enc      Clients
  1    ?? iPhone               AA:BB:CC:DD:EE:FF  6     -45 dBm WPA2     2
```

- **??** — likely phone hotspot / tethering
- **Clients** — devices seen during passive scan (0 = none detected yet, not necessarily empty)

---

## VirtualBox users

USB WiFi adapters in VMs need extra setup:

1. Install **VirtualBox Extension Pack** (same version as VirtualBox)
2. VM Settings ? USB ? enable **USB 2.0** controller (not USB 1.1)
3. Add USB filter for your adapter (e.g. `ATHEROS USB2.0 WLAN` for WN722N)
4. After boot: **Devices ? USB** ? attach adapter to the VM
5. Run VirtualBox as **Administrator** on Windows if USB passthrough fails

```bash
lsusb   # should show AR9271 inside Kali
iw dev  # should show wlan0
```

VM passthrough may limit scanning/injection. **Native Kali (Live USB)** is more reliable.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `root privileges required` | Use `sudo` |
| `Missing dependencies` | `sudo bash install.sh` |
| `Failed to enable monitor mode` | External USB adapter; `sudo airmon-ng check kill` |
| `Monitor interface: phy0` | Update to latest version: `git pull` |
| No WiFi found | Check monitor mode; move closer to APs |
| Clients always 0 | Active traffic on target WiFi; option `5`; try `--scan 45` |
| Deauth has no effect | Target may use **WPA3 + PMF**; test on WPA2/open network |
| Ctrl+C traceback | Update: `git pull` (fixed in latest version) |

### Manual test

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
```

If this shows networks, WiFi Cut should work too.

---

## Limitations

| Limitation | Explanation |
|------------|-------------|
| WPA3 + PMF | Many routers ignore forged deauth frames |
| 4G/5G cellular | Cannot cut mobile data — only WiFi / hotspots |
| VirtualBox | USB passthrough may reduce scan/injection reliability |
| Passive client scan | Idle devices may not appear until they send traffic |

---

## How it works

| Tool | Purpose |
|------|---------|
| `airmon-ng` | Enable monitor mode |
| `airodump-ng` | Passive WiFi + client scan |
| `aireplay-ng` | Send deauth frames |
| `mdk4` | Optional deauth flood (aggressive mode) |

---

## Project structure

```
WIFI-Cut/
??? wifi_cut.py      # Main tool
??? install.sh       # Dependency installer
??? requirements.txt # System dependency notes
??? README.md
```

---

## Contributing

Issues and pull requests welcome. Please do not use this tool for unauthorized attacks.

1. Fork the repo
2. Create a feature branch
3. Submit a PR with a clear description

---

## Disclaimer

This project is for **authorized security testing, education, and auditing your own networks only**. The authors are not responsible for misuse.

---

## License

Educational / authorized testing use only. See [LICENSE](LICENSE).
