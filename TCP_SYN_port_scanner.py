#!/usr/bin/env python3
from scapy.all import IP, TCP, sr1
import argparse


def scan_port(target, port):
    """Send TCP SYN and analyze response"""
    pkt = IP(dst=target) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=1, verbose=0)

    if resp is None:
        return "Filtered/No response"
    elif resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:  # SYN-ACK
            # Send RST to close half-open connection
            sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=1, verbose=0)
            return "Open"
        elif resp[TCP].flags == 0x14:  # RST-ACK
            return "Closed"
    return "Unknown"


def main(target, ports):
    print(f"Scanning {target}...")
    for port in ports:
        status = scan_port(target, port)
        print(f"Port {port:5}: {status}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simple TCP SYN Port Scanner with Scapy"
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=[22, 80, 443],
        help="Ports to scan (default: 22 80 443)",
    )
    args = parser.parse_args()

    main(args.target, args.ports)
