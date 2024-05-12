from scapy.all import *
import os

iface = "wlp2s0"
iwconfig_cmd = "/usr/sbin/iwconfig"

# Print SSID of probe requests, probe response
# or association request
def handle_packet(packet):
    if packet.haslayer(Dot11ProbeReq) or \
            packet.haslayer(Dot11ProbeResp) or \
            packet.haslayer(Dot11AssoReq):
        print("Found SSID: " + packet.info)

# Set device into monitor mode
os.system(iwconfig_cmd + " " + iface + " mode monitor")

# Start sniffing
print("Sniffing on interface " + iface)
sniff(iface=iface, prn=handle_packet)
