# Python Packet Sniffer (Scapy)

## What it does
Live-captures network packets using **Scapy** and prints useful details:
- timestamp
- source/destination IPs
- L4 protocol (TCP/UDP/ICMP)
- port numbers (for TCP/UDP)
- payload preview (printable ASCII) and optional hex

> Run only on networks/devices you are authorized to test.

## Setup
### 1) Install Scapy
```bash
pip install scapy
```

## Run
### Capture indefinitely (Ctrl+C to stop)
```bash
python packet_sniffer.py --iface "Wi-Fi" --count 0
```

### Capture only packets to/from a host
```bash
python packet_sniffer.py --iface "Wi-Fi" --host 8.8.8.8 --proto all --count 0
```

### Capture only TCP or UDP
```bash
python packet_sniffer.py --iface "Wi-Fi" --proto tcp --count 0
python packet_sniffer.py --iface "Wi-Fi" --proto udp --count 0
```

### Limit captured packets + payload size
```bash
python packet_sniffer.py --iface "Wi-Fi" --proto tcp --count 50 --payload-bytes 120
```

### Show payload preview as hex too
```bash
python packet_sniffer.py --iface "Wi-Fi" --proto tcp --count 50 --log-hex
```

## Notes
- Packet capture often requires **Administrator** privileges (Windows) or **root** (Linux/Mac).
- Some traffic may not include readable payload bytes; the script previews whatever payload is available.

