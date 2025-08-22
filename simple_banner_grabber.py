# This helps us learn what service/version is actually running behind an open port

#!/usr/bin/env python3

import socket
import argparse


def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))

        # For HTTP/HTTPS, send a dummy request
        if port == 80:
            s.send(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip).encode())
        elif port == 443:
            # HTTPS needs TLS handshake; skipping here for simplicity
            s.close()
            return "[HTTPS requires SSL/TLS handling]"

        banner = s.recv(1024).decode(errors="ignore")
        s.close()
        return banner.strip() if banner else "[No banner]"
    except Exception as e:
        return f"[Error: {e}]"


def main(target, ports):
    print(f"Grabbing banners from {target}...")
    for port in ports:
        banner = grab_banner(target, port)
        print(f"Port {port:5}: {banner}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Banner Grabber")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=[22, 80, 443],
        help="Ports to grab banners from (default: 22 80 443)",
    )
    args = parser.parse_args()

    main(args.target, args.ports)
