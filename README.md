# Python Packet Sniffer (Scapy)

A simple network packet sniffer and analyzer built with **Scapy**, created as part of an
internship task to learn how data flows through a network and how core protocols
(Ethernet, ARP, IP, TCP, UDP, ICMP) are structured.

## What it does

Live-captures network packets and prints, per packet:

- Timestamp
- Source/destination IP (or ARP source/destination for ARP traffic)
- L4 protocol (TCP / UDP / ICMP)
- Port numbers (for TCP/UDP)
- A printable-ASCII payload preview, with optional hex

> ⚠️ Run only on networks/devices you own or are explicitly authorized to test.
> Capturing traffic without permission may be illegal.

## Requirements

- Python 3.8+
- [Npcap](https://npcap.com/) (Windows only — required by Scapy for live capture)
- Administrator (Windows) or root/sudo (Linux/macOS) privileges

## Setup

```bash
git clone https://github.com/PRITEERAJBHAR/cyber.s_1.git
cd cyber.s_1
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

Run with elevated privileges:

```bash
# Windows (PowerShell as Administrator)
python packet_sniffer.py --iface "Wi-Fi" --count 0

# macOS/Linux
sudo python3 packet_sniffer.py --iface eth0 --count 0
```

### Capture indefinitely (Ctrl+C to stop)

```bash
python packet_sniffer.py --iface "Wi-Fi" --count 0
```

### Capture only packets to/from a host

```bash
python packet_sniffer.py --iface "Wi-Fi" --host 8.8.8.8 --proto all --count 0
```

### Capture only TCP, UDP, or ICMP

```bash
python packet_sniffer.py --iface "Wi-Fi" --proto tcp --count 0
python packet_sniffer.py --iface "Wi-Fi" --proto udp --count 0
python packet_sniffer.py --iface "Wi-Fi" --proto icmp --count 0
```

### Limit captured packets and payload preview size

```bash
python packet_sniffer.py --iface "Wi-Fi" --proto tcp --count 50 --payload-bytes 120
```

### Show payload preview as hex too

```bash
python packet_sniffer.py --iface "Wi-Fi" --proto tcp --count 50 --log-hex
```

### All options

| Flag | Description | Default |
|------|-------------|---------|
| `--iface` | Network interface to sniff on | Scapy's default |
| `--count` | Number of packets to capture (0 = forever) | `0` |
| `--host` | Only capture packets matching this IP | none |
| `--proto` | Filter by `tcp`, `udp`, `icmp`, or `all` | `all` |
| `--payload-bytes` | Max payload bytes to preview | `64` |
| `--timeout` | Stop after N seconds | none |
| `--log-hex` | Also print payload as hex | off |

## Sample output

```
Starting packet capture...
  Interface: Wi-Fi
  Filter: (none)
  Count: 0 (0=forever)
14:32:10.221 TCP  192.168.1.5:51322 -> 142.250.190.14:443 payload='...........'
14:32:10.512 ARP  192.168.1.1 -> 192.168.1.5 (is-at)
```

## Notes

- `--proto tcp/udp/icmp` applies a BPF filter, so ARP traffic will only be visible
  when `--proto all` (the default) is used.
- Live capture generally requires Administrator (Windows) or root (Linux/macOS)
  privileges, and Npcap installed on Windows.
- If a permission or capture-backend error occurs, the script prints a clear message
  instead of crashing with a raw traceback.

## Disclaimer

This project is for **educational purposes only**, built as part of an internship
learning exercise. Only capture traffic on networks you own or have explicit
authorization to monitor.
