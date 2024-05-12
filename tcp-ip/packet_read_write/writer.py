import pcapy

def write_packet(hdr, data):
    try:
        dumper.dump(hdr, data)
        print("Packet written to pcap dump file")
    except Exception as e:
        print("Error writing packet to pcap dump file:", e)

# Set your network interface and dump file
dev = "wlan0"
dump_file = "sniffer.pcap"

# Open live capture and dump file
pcap = pcapy.open_live(dev, 65536, 1, 0)
dumper = pcap.dump_open(dump_file)

# Start sniffing and write packets to pcap dump file
pcap.loop(0, write_packet)
