from scapy.all import sniff, Ether

def handle_packet(packet):
    if Ether in packet:
        print(packet.summary())

# Replace 'eth0' with your desired network interface
interface = 'wlan0'

# Replace 'arp' with your desired packet filter
filter_expression = 'arp'

# Start sniffing packets
sniff(iface=interface, filter=filter_expression, prn=handle_packet)
