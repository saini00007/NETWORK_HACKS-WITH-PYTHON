
from scapy.all import sniff, ARP
from signal import signal, SIGINT
import sys


arp_watcher_db_file = "/var/cache/arp-watcher.db"
ip_mac = {}


def sig_int_handler(signum, frame):
    print("Got SIGINT. Saving ARP database...")
    try:
        with open(arp_watcher_db_file, "w") as f:
            for (ip, mac) in ip_mac.items():
                f.write(ip + " " + mac + "\n")
        print("Done.")
    except IOError:
        print("Cannot write file " + arp_watcher_db_file)
    sys.exit(1)


def watch_arp(pkt):
    
    if pkt[ARP].op == 2:
        print(pkt[ARP].hwsrc + " " + pkt[ARP].psrc)
        
        # Check if the device is new
        if ip_mac.get(pkt[ARP].psrc) == None:
            print("Found new device " + pkt[ARP].hwsrc + " " + pkt[ARP].psrc)
            ip_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc
            
        # Check if the device is known but has a different IP
        elif ip_mac.get(pkt[ARP].psrc) and ip_mac[pkt[ARP].psrc] != pkt[ARP].hwsrc:
            print(pkt[ARP].hwsrc + " has got new ip " + pkt[ARP].psrc + " (old " + ip_mac[pkt[ARP].psrc] + ")")
            ip_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc

# Register signal handler for SIGINT
signal(SIGINT, sig_int_handler)

# Check if the interface argument is provided
if len(sys.argv) < 2:
    print(sys.argv[0] + " <iface>")
    sys.exit(0)

# to read the ARP database file
try:
    with open(arp_watcher_db_file, "r") as fh:
        for line in fh:
            line = line.strip()
            (ip, mac) = line.split(" ")
            ip_mac[ip] = mac
except IOError:
    print("Cannot read file " + arp_watcher_db_file)
    sys.exit(1)

# Start sniffing ARP packets on the specified interface
sniff(prn=watch_arp, filter="arp", iface=sys.argv[1], store=0)
