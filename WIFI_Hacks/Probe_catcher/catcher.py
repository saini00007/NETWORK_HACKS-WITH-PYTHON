from datetime import datetime
from scapy.all import *
import os

# Network interface to sniff on
iface = "wlan0"

# Command to set the device into monitor mode
iwconfig_cmd = "/usr/sbin/iwconfig"

# Function to handle packet
def handle_packet(packet):
    if packet.haslayer(Dot11ProbeResp):
        print(str(datetime.now()) + " " + packet[Dot11].addr2 + " searches for " + packet.info)

# Set device into monitor mode
os.system(iwconfig_cmd + " " + iface + " mode monitor")

# Start sniffing
print("Sniffing on interface " + iface)
sniff(iface=iface, prn=handle_packet)
