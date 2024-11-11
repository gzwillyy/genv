from scapy.all import *

pkt = IP(src="10.3.4.6", dst="51.79.213.102")/TCP(sport=8123, dport=58372, flags="S")
pkt[TCP].window = 65535
del pkt[IP].chksum
del pkt[TCP].chksum
send(pkt)
