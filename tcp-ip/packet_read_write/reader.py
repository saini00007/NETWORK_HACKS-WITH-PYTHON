import pcapy

def read_packet(hdr, data):
    try:
        print("Packet Header:", hdr)
        print("Packet Data:", data)
    except Exception as e:
        print("Error reading packet:", e)

# Set the input pcap dump file
input_file = "/home/kali/Desktop/Network_hacks_with_python/tcp-ip/packet_read_write/1.pcap "

# Open the pcap dump file for reading
pcap = pcapy.open_offline(input_file)

# Define a function to handle reading packets
def packet_handler(hdr, data):
    read_packet(hdr, data)

# Start reading packets from the pcap dump file
pcap.loop(0, packet_handler)
