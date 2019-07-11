import time
from scapy.all import *


def make_spoofy_pkt(pkt):
	a = IP()
	if str(pkt[0].getlayer(IP).src) == '10.0.2.15':
		return 
	a.dst = pkt[0].getlayer(IP).src
	a.ttl = 87
	b = pkt[0].getlayer(ICMP)
	p = a/b
		
	send(p, verbose=True)	

while True:
	time.sleep(1)	
	pkt = sniff(filter='icmp',prn=make_spoofy_pkt)


