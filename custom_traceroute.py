#!/usr/bin/env python3
from scapy.all import IP, ICMP, sr1
import argparse


def traceroute(destination, max_hops=30):
    print(f"Traceroute to {destination}, max hops = {max_hops}")
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=destination, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=2)

        if reply is None:
            print(f"{ttl:2}   *")
        elif reply.type == 11:  # ICMP Time Exceeded
            print(f"{ttl:2}   {reply.src}")
        elif reply.type == 0:  # ICMP Echo Reply
            print(f"{ttl:2}   {reply.src}   [Destination Reached]")
            break
        else:
            print(f"{ttl:2}   {reply.src}   [Unexpected ICMP type {reply.type}]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Custom traceroute with Scapy")
    parser.add_argument("destination", help="Destination host or IP")
    parser.add_argument(
        "--max-hops", type=int, default=30, help="Maximum hops (default 30)"
    )
    args = parser.parse_args()

    traceroute(args.destination, args.max_hops)
