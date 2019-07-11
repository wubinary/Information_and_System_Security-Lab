from scapy.all import *

a = IP()
a.src = '87.87.87.87'
a.dst = '10.0.2.3'
print(a.show())
b = ICMP()
p = a/b
print(p.show())
send(p)

