#!/usr/bin/env python3
"""packet_sniffer.py

A simple Python network packet sniffer using Scapy.

WARNING:
- Capturing traffic may require elevated privileges (run as Administrator/root).
- This tool is intended for learning/authorized testing only.

Features:
- Live capture (sniff)
- Prints source/destination IPs, L4 protocol, and payload preview
- Optionally filters by host or TCP/UDP

Examples:
  python packet_sniffer.py --iface "Wi-Fi" --count 0
  python packet_sniffer.py --iface "Wi-Fi" --host 8.8.8.8 --proto tcp
  python packet_sniffer.py --iface "Wi-Fi" --proto udp --payload-bytes 80
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime


class SnifferUnavailableError(RuntimeError):
    """Raised when the environment cannot start live packet capture."""



def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Live packet sniffer using Scapy")
    p.add_argument(
        "--iface",
        default=None,
        help="Network interface to sniff on (e.g. 'Wi-Fi'). Default: Scapy chooses.",
    )
    p.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture. 0 means run until interrupted.",
    )
    p.add_argument(
        "--host",
        default=None,
        help="Only capture packets where the IP matches this value.",
    )
    p.add_argument(
        "--proto",
        choices=["tcp", "udp", "icmp", "all"],
        default="all",
        help="Filter by L4 protocol. Default: all.",
    )
    p.add_argument(
        "--payload-bytes",
        type=int,
        default=64,
        help="Maximum number of payload bytes to preview.",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Stop sniffing after this many seconds (optional).",
    )
    p.add_argument(
        "--log-hex",
        action="store_true",
        help="Also show payload preview as hex.",
    )
    return p


def printable_payload(data: bytes, max_len: int) -> str:
    if not data:
        return ""
    data = data[:max_len]

    # Keep it compact: show printable ASCII, otherwise '.'
    out = []
    for b in data:
        if 32 <= b <= 126:
            out.append(chr(b))
        else:
            out.append(".")
    return "".join(out)


def safe_bytes(x) -> bytes:
    if x is None:
        return b""
    try:
        return bytes(x)
    except Exception:
        return b""


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        # Lazy import so users get a helpful message if scapy isn't installed.
        from scapy.all import IP, TCP, UDP, ICMP, Raw, sniff
    except ImportError:
        print(
            "Scapy is not installed. Install it with:\n"
            "  pip install scapy\n",
            file=sys.stderr,
        )
        return 2

    # Respect the user's stop conditions explicitly.
    if args.count == 0 and args.timeout is None:
        print("No stop condition was provided; use --count or --timeout to stop automatically.")

    # Build a BPF filter string for efficiency.
    # Note: Scapy sniff uses libpcap filters if available.
    bpf_parts: list[str] = []
    if args.host:
        bpf_parts.append(f"host {args.host}")

    if args.proto == "tcp":
        bpf_parts.append("tcp")
    elif args.proto == "udp":
        bpf_parts.append("udp")
    elif args.proto == "icmp":
        bpf_parts.append("icmp")
    # args.proto == 'all' => no additional filter

    bpf_filter = " and ".join(bpf_parts) if bpf_parts else None

    def on_packet(pkt):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ip_proto = pkt[IP].proto
        else:
            # Non-IP packet (e.g., ARP/IPv6). For now, show minimal info.
            src_ip = "?"
            dst_ip = "?"
            ip_proto = None

        l4_proto = "N/A"
        sport = dport = None
        payload_bytes = b""

        if TCP in pkt:
            l4_proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            payload_bytes = safe_bytes(pkt[TCP].payload)
        elif UDP in pkt:
            l4_proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            payload_bytes = safe_bytes(pkt[UDP].payload)
        elif ICMP in pkt:
            l4_proto = "ICMP"
            payload_bytes = safe_bytes(pkt[ICMP].payload)
        else:
            # Try Raw payload preview if available
            if Raw in pkt:
                payload_bytes = safe_bytes(pkt[Raw])

        payload_preview = printable_payload(payload_bytes, args.payload_bytes)
        payload_hex = payload_bytes[: args.payload_bytes].hex() if args.log_hex else ""

        # Try to avoid dumping tons of junk: only show payload if it looks meaningful
        # (has printable characters or any bytes when hex requested).
        show_payload = bool(payload_bytes)

        if show_payload:
            if args.log_hex:
                print(
                    f"{ts} {l4_proto:<4} {src_ip}:{sport if sport else ''} -> {dst_ip}:{dport if dport else ''} "
                    f"payload='{payload_preview}' hex={payload_hex}",
                    flush=True,
                )
            else:
                print(
                    f"{ts} {l4_proto:<4} {src_ip}:{sport if sport else ''} -> {dst_ip}:{dport if dport else ''} "
                    f"payload='{payload_preview}'",
                    flush=True,
                )
        else:
            extra = f" ip_proto={ip_proto}" if ip_proto is not None else ""
            port_part = f"{sport if sport else ''}->{dport if dport else ''}".strip("-")
            print(
                f"{ts} {l4_proto:<4} {src_ip} -> {dst_ip} {port_part}{extra}",
                flush=True,
            )

    print("Starting packet capture...")
    print(f"  Interface: {args.iface or '(scapy default)'}")
    print(f"  Filter: {bpf_filter or '(none)'}")
    print(f"  Count: {args.count} (0=forever)")

    try:
        sniff(
            iface=args.iface,
            filter=bpf_filter,
            prn=on_packet,
            store=False,
            count=args.count if args.count > 0 else 0,
            timeout=args.timeout,
        )
    except RuntimeError as exc:
        print(f"Live sniffing could not start: {exc}", file=sys.stderr)
        print("Install Npcap/WinPcap or run with a supported capture backend.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

