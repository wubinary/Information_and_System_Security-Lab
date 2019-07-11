from scapy.all import *

def print_pkt(pkt):
	pkt.show()

pkt = sniff(filter='net 140.113.122.185/32',prn=print_pkt, count=1)


