#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp
import argparse


def scan_network(target):
    # Build ARP request
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send & receive packets
    result = srp(packet, timeout=2, verbose=0)[0]

    # Parse responses
    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices


def print_result(devices):
    print("Available devices in the network:")
    print("IP" + " " * 18 + "MAC")
    print("-" * 40)
    for device in devices:
        print(f"{device['ip']:16}    {device['mac']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simple ARP network scanner with Scapy"
    )
    parser.add_argument("target", help="Target IP / subnet (e.g. 192.168.1.0/24)")
    args = parser.parse_args()

    devices = scan_network(args.target)
    print_result(devices)
