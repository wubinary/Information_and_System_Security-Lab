import time,threading
from scapy.all import *

def print_pkt(pkt):
	global tmpIp
	#pkt.show()
	tmpIp = str(pkt[0].getlayer(IP).src)

def sniffer():
	while True:
		ptk = sniff(filter='icmp and ip dst 10.0.2.15',prn=print_pkt,count=1)

t_sniff = threading.Thread(target=sniffer,args=())
t_sniff.start()

dstIp = '157.185.144.122'
tmpIp = 'x.x.x.x'
TTL = 1
while True:
	a = IP()
	a.dst = dstIp
	a.ttl = TTL
	b = ICMP()
	p = a/b

	time.sleep(5)
	send(p, verbose=False)
	print(tmpIp)
	if tmpIp==dstIp :
		print("Trace terminated !!")
		break
	tmpIp = 'x.x.x.x'

	TTL += 1


