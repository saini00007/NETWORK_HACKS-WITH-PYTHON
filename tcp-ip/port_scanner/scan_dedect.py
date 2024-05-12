import sys
from time import time
from scapy.all import sniff

ip_to_ports = dict()
nr_of_diff_ports = 10
port_scan_timespan = 10

def detect_port_scan(packet):
    ip = packet.getlayer("IP")
    tcp = packet.getlayer("TCP")
    
    # Records scanned port and time in Unix format
    ip_to_ports.setdefault(ip.src, {})[str(tcp.dport)] = int(time())
    
    # Checks if source IP has scanned too many different ports
    if len(ip_to_ports[ip.src]) >= nr_of_diff_ports:
        scanned_ports = ip_to_ports[ip.src].items()
        
        # Checks recorded time of each scan
        for (scanned_port, scan_time) in scanned_ports:
            # Deletes scanned port if not in timeout span
            if scan_time + port_scan_timespan < int(time()):
                del ip_to_ports[ip.src][scanned_port]
        
        # Deletes source IP if still too many scanned ports
        if len(ip_to_ports[ip.src]) >= nr_of_diff_ports:
            print("Port scan detected from " + ip.src)
            print("Scanned ports: " + ", ".join(ip_to_ports[ip.src].keys()) + "\n")
            del ip_to_ports[ip.src]

if len(sys.argv) < 2:
    print(sys.argv[0] + " <iface>")
    sys.exit(0)

sniff(prn=detect_port_scan, filter="tcp", iface=sys.argv[1], store=0)
